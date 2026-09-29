/**
 * CAPTA · Área privada de actualizaciones
 *
 * Cloudflare Worker que sirve, bajo BASE_PATH, un sitio accesible solo con
 * usuario y contraseña:
 *   GET  BASE_PATH                    login o listado de versiones
 *   POST BASE_PATH/login              inicia sesión
 *   POST BASE_PATH/logout             cierra sesión
 *   GET  BASE_PATH/descargar/<ver>    descarga el ZIP (requiere sesión)
 *
 * Almacenamiento:
 *   KV  DB    user:<usuario>      {hash, nombre, creado}
 *             sess:<sha256>       {u}                  (TTL = SESSION_TTL)
 *             rl:ip:<ip> / rl:u:<usuario>  intentos fallidos (TTL 15 min)
 *             config:releases     [{version, fecha, key, size, sha256, notas}]
 *   R2  ZIPS  objetos ZIP (bucket privado)
 *
 * Las cuentas y las versiones se administran con scripts/admin.mjs.
 */

const COOKIE = "__Host-capta_upd";
const PBKDF2_ITER = 100000; // máximo admitido por WebCrypto en Workers
const RL_MAX_USER = 8;      // intentos fallidos por usuario antes de bloquear
const RL_MAX_IP = 30;       // por IP: más alto porque una oficina puede compartir IP
const RL_TTL = 900;         // 15 min
const USER_RE = /^[a-z0-9._-]{3,32}$/;
// Hash de relleno: se verifica contra él cuando el usuario no existe, para que
// el tiempo de respuesta no revele qué usuarios son válidos.
const DUMMY_HASH = "pbkdf2$100000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (err) {
      console.error(JSON.stringify({ evt: "error", msg: String(err && err.stack || err) }));
      return page(env, "Error", `<p>Ocurrió un error inesperado. Intente nuevamente más tarde.</p>`, 500);
    }
  },
};

async function handle(request, env) {
  const url = new URL(request.url);
  const base = (env.BASE_PATH || "/actualizacion").replace(/\/+$/, "");
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (!path.startsWith(base) || (path.length > base.length && path[base.length] !== "/")) {
    return notFound(env);
  }
  const sub = path.slice(base.length) || "/";
  const method = request.method;

  if (method === "POST") {
    // CSRF: además de SameSite=Strict, se exige que el formulario venga de este origen.
    if (request.headers.get("Origin") !== url.origin) {
      return page(env, "Solicitud rechazada", `<p>Origen no válido.</p>`, 403);
    }
    if (sub === "/login") return login(request, env, base);
    if (sub === "/logout") return logout(request, env, base);
    return notFound(env);
  }

  if (method !== "GET" && method !== "HEAD") {
    return new Response("Método no permitido", { status: 405, headers: { Allow: "GET, HEAD, POST" } });
  }

  const session = await getSession(request, env);

  if (sub === "/") {
    if (!session) return loginPage(env, base, url.searchParams.get("e"));
    return releasesPage(env, base, session);
  }

  const m = sub.match(/^\/descargar\/([0-9A-Za-z._-]{1,40})$/);
  if (m) {
    if (!session) return redirect(base);
    return download(request, env, session, m[1]);
  }

  return notFound(env);
}

/* ------------------------------------------------------------------ */
/* Autenticación                                                       */
/* ------------------------------------------------------------------ */

async function login(request, env, base) {
  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const len = Number(request.headers.get("Content-Length") || "0");
  if (len > 2048) return redirect(`${base}?e=1`);

  let form;
  try {
    form = await request.formData();
  } catch {
    return redirect(`${base}?e=1`);
  }
  const user = String(form.get("usuario") || "").trim().toLowerCase();
  const pass = String(form.get("clave") || "");

  const ipKey = `rl:ip:${ip}`;
  const userKey = USER_RE.test(user) ? `rl:u:${user}` : null;
  const [ipFails, userFails] = await Promise.all([
    counter(env, ipKey),
    userKey ? counter(env, userKey) : 0,
  ]);
  if (ipFails >= RL_MAX_IP || userFails >= RL_MAX_USER) {
    log("login_blocked", { u: user, ip });
    return redirect(`${base}?e=2`);
  }

  let record = null;
  if (userKey && pass.length > 0 && pass.length <= 256) {
    record = await env.DB.get(`user:${user}`, "json");
  }
  const ok = await verifyPassword(pass, record ? record.hash : DUMMY_HASH);

  if (!record || !ok || record.disabled) {
    await Promise.all([
      bump(env, ipKey, ipFails),
      userKey ? bump(env, userKey, userFails) : null,
    ]);
    log("login_fail", { u: user, ip });
    return redirect(`${base}?e=1`);
  }

  if (userFails) await env.DB.delete(userKey);

  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const ttl = Math.max(300, Number(env.SESSION_TTL) || 28800);
  await env.DB.put(`sess:${await sha256hex(token)}`, JSON.stringify({ u: user }), { expirationTtl: ttl });
  log("login_ok", { u: user, ip });

  return new Response(null, {
    status: 303,
    headers: {
      Location: base,
      "Set-Cookie": `${COOKIE}=${token}; Path=/; Max-Age=${ttl}; HttpOnly; Secure; SameSite=Strict`,
      ...securityHeaders(),
    },
  });
}

async function logout(request, env, base) {
  const token = readCookie(request);
  if (token) await env.DB.delete(`sess:${await sha256hex(token)}`);
  return new Response(null, {
    status: 303,
    headers: {
      Location: base,
      "Set-Cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`,
      ...securityHeaders(),
    },
  });
}

async function getSession(request, env) {
  const token = readCookie(request);
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const sess = await env.DB.get(`sess:${await sha256hex(token)}`, "json");
  if (!sess) return null;
  // Si la cuenta se borró o deshabilitó, la sesión deja de valer al instante.
  const record = await env.DB.get(`user:${sess.u}`, "json");
  if (!record || record.disabled) return null;
  return { user: sess.u, nombre: record.nombre || sess.u };
}

function readCookie(request) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === COOKIE) return part.slice(i + 1).trim();
  }
  return null;
}

async function counter(env, key) {
  return Number(await env.DB.get(key)) || 0;
}

async function bump(env, key, current) {
  await env.DB.put(key, String(current + 1), { expirationTtl: RL_TTL });
}

/** Formato: pbkdf2$<iteraciones>$<sal base64>$<hash base64> (igual que admin.mjs). */
async function verifyPassword(password, stored) {
  const parts = String(stored).split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = Number(parts[1]);
  if (!(iterations > 0 && iterations <= PBKDF2_ITER)) return false;
  const salt = b64decode(parts[2]);
  const expected = b64decode(parts[3]);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, expected.length * 8,
  ));
  let diff = bits.length ^ expected.length;
  for (let i = 0; i < bits.length; i++) diff |= bits[i] ^ expected[i];
  return diff === 0;
}

/* ------------------------------------------------------------------ */
/* Descargas                                                           */
/* ------------------------------------------------------------------ */

async function getReleases(env) {
  const list = (await env.DB.get("config:releases", "json")) || [];
  return Array.isArray(list) ? list.slice(0, 2) : [];
}

async function download(request, env, session, version) {
  const rel = (await getReleases(env)).find((r) => r.version === version);
  if (!rel) return notFound(env);
  const obj = request.method === "HEAD" ? await env.ZIPS.head(rel.key) : await env.ZIPS.get(rel.key);
  if (!obj) return notFound(env);

  log("download", { u: session.user, v: version, ip: request.headers.get("CF-Connecting-IP") });
  const filename = `CAPTA-${version}.zip`;
  return new Response(request.method === "HEAD" ? null : obj.body, {
    headers: {
      "Content-Type": "application/zip",
      "Content-Length": String(obj.size),
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "private, no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

/* ------------------------------------------------------------------ */
/* Páginas                                                             */
/* ------------------------------------------------------------------ */

function loginPage(env, base, error) {
  const msg = error === "2"
    ? "Demasiados intentos fallidos. Espere 15 minutos e intente nuevamente."
    : error ? "Usuario o contraseña incorrectos." : "";
  const body = `
  <section class="card narrow">
    <h1>Acceso a actualizaciones</h1>
    <p class="muted">Área restringida para usuarios autorizados de CAPTA.</p>
    ${msg ? `<p class="alert" role="alert">${esc(msg)}</p>` : ""}
    <form method="post" action="${esc(base)}/login" autocomplete="on">
      <label for="usuario">Usuario</label>
      <input id="usuario" name="usuario" type="text" required maxlength="32"
             autocomplete="username" autocapitalize="none" spellcheck="false" autofocus>
      <label for="clave">Contraseña</label>
      <input id="clave" name="clave" type="password" required maxlength="256" autocomplete="current-password">
      <button class="btn btn-primary" type="submit">Ingresar</button>
    </form>
  </section>`;
  return page(env, "Acceso", body);
}

async function releasesPage(env, base, session) {
  const releases = await getReleases(env);
  const labels = ["Versión nueva", "Versión anterior"];
  const cards = releases.length
    ? releases.map((r, i) => releaseCard(base, r, labels[i], i === 0)).join("")
    : `<section class="card"><p>Todavía no hay versiones publicadas.</p></section>`;

  const body = `
  <div class="topbar">
    <p class="muted">Sesión iniciada como <strong>${esc(session.nombre)}</strong></p>
    <form method="post" action="${esc(base)}/logout"><button class="btn btn-ghost" type="submit">Cerrar sesión</button></form>
  </div>
  <h1>Actualizaciones de CAPTA</h1>
  ${cards}
  <section class="card" id="guia">
    <h2>Cómo actualizar</h2>
    <!-- PENDIENTE: redactar la guía de actualización paso a paso. -->
    <p class="pending">Guía en preparación.</p>
  </section>`;
  return page(env, "Actualizaciones", body);
}

function releaseCard(base, r, label, isNew) {
  return `
  <section class="card release${isNew ? " new" : ""}">
    <div class="release-head">
      <div>
        <span class="tag${isNew ? " tag-new" : ""}">${esc(label)}</span>
        <h2>CAPTA ${esc(r.version)}</h2>
        <p class="muted">Publicada el ${esc(r.fecha || "")} · ${esc(formatSize(r.size))}</p>
      </div>
      <a class="btn ${isNew ? "btn-primary" : "btn-ghost"}" href="${esc(base)}/descargar/${encodeURIComponent(r.version)}" download>
        Descargar ZIP
      </a>
    </div>
    <div class="notes">${renderNotes(r.notas)}</div>
    ${r.sha256 ? `<p class="hash"><span>SHA-256</span> <code>${esc(r.sha256)}</code></p>` : ""}
  </section>`;
}

/** Texto plano → HTML: líneas en blanco separan párrafos; "- " arma listas. */
function renderNotes(text) {
  if (!text) return `<p class="muted">Sin descripción.</p>`;
  return String(text).trim().split(/\n\s*\n/).map((block) => {
    const lines = block.split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.every((l) => /^[-*] /.test(l))) {
      return `<ul>${lines.map((l) => `<li>${esc(l.slice(2))}</li>`).join("")}</ul>`;
    }
    return `<p>${lines.map(esc).join("<br>")}</p>`;
  }).join("");
}

function notFound(env) {
  return page(env, "No encontrado", `<section class="card narrow"><h1>No encontrado</h1><p>La página solicitada no existe.</p></section>`, 404);
}

function redirect(location) {
  return new Response(null, { status: 303, headers: { Location: location, ...securityHeaders() } });
}

function securityHeaders() {
  return {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000",
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  };
}

function page(env, title, body, status = 200) {
  const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>${esc(title)} · CAPTA</title>
<style>${CSS}</style>
</head>
<body>
<header class="brand"><div class="wrap"><span class="logo">CAPTA</span><span class="sub">Actualizaciones</span></div></header>
<main class="wrap">${body}</main>
<footer class="wrap muted small">CAPTA · Ministerio Público Fiscal de Córdoba · Acceso restringido</footer>
</body>
</html>`;
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", ...securityHeaders() },
  });
}

const CSS = `
:root{--primary:#12294a;--primary-600:#1a3c66;--primary-700:#0f2340;--accent:#00677f;--accent-soft:#e2f1f5;
--on-primary:#fff;--bg:#f6f8fb;--surface:#fff;--surface-2:#eef1f6;--line:#e1e6ee;--hover:#f4f6fa;
--ink:#1b2129;--ink-soft:#4b535d;--ink-muted:#646c76;--note-bg:#fbfbf9;--note-accent:#8a7433;--danger:#a4262c;
--danger-bg:#fdf0f0;--brand-bg:#0f2340;--radius:10px;--radius-sm:6px;
--shadow:0 1px 2px rgba(16,26,45,.04),0 6px 24px rgba(16,26,45,.06);
--mono:ui-monospace,"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
--sans:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--primary:#c7d6f2;--primary-600:#a9c1e8;--primary-700:#8aa7d6;--accent:#5cc9e6;
--accent-soft:#0f2d38;--on-primary:#0f2340;--bg:#12161c;--surface:#1a1f27;--surface-2:#232a33;--line:#2b333d;--hover:#20262f;
--ink:#e6e9ee;--ink-soft:#aab3be;--ink-muted:#7f8893;--note-bg:#20262f;--note-accent:#c8ad5f;--danger:#f1a7a9;--danger-bg:#3a1f22;
--brand-bg:#0b1626;--shadow:0 1px 2px rgba(0,0,0,.3),0 8px 28px rgba(0,0,0,.35)}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
.wrap{max-width:820px;margin:0 auto;padding:0 16px}
.brand{background:var(--brand-bg);color:#fff;margin-bottom:32px}
.brand .wrap{display:flex;align-items:baseline;gap:12px;height:64px;align-items:center}
.logo{font-weight:800;letter-spacing:.08em;font-size:20px}
.sub{color:#aab8cc;font-size:14px}
h1{color:var(--primary);font-size:clamp(24px,4vw,32px);line-height:1.2;margin:0 0 16px}
h2{color:var(--primary);font-size:22px;margin:4px 0 2px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:24px;box-shadow:var(--shadow);margin-bottom:24px}
.card.narrow{max-width:420px;margin:48px auto}
.narrow h1{font-size:26px}
.release.new{border-left:4px solid var(--accent)}
.release-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
.tag{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:2px 10px;border-radius:999px;background:var(--surface-2);color:var(--ink-soft)}
.tag-new{background:var(--accent-soft);color:var(--accent)}
.notes{margin-top:16px;color:var(--ink-soft)}
.notes ul{padding-left:20px}
.hash{margin:16px 0 0;font-size:13px;color:var(--ink-muted);overflow-wrap:anywhere}
.hash span{font-weight:700;margin-right:6px}
.hash code{font-family:var(--mono);background:var(--surface-2);padding:2px 6px;border-radius:4px}
.muted{color:var(--ink-muted)}
.small{font-size:13px;padding-top:16px;padding-bottom:32px}
.pending{background:var(--note-bg);border-left:3px solid var(--note-accent);padding:12px 16px;border-radius:var(--radius-sm);color:var(--ink-soft)}
.alert{background:var(--danger-bg);color:var(--danger);padding:10px 14px;border-radius:var(--radius-sm);font-size:14px}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.topbar p{margin:0;font-size:14px}
label{display:block;font-size:14px;font-weight:600;margin:16px 0 6px}
input{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:var(--radius-sm);background:var(--surface);color:var(--ink)}
input:focus-visible,.btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
form .btn{margin-top:24px;width:100%;justify-content:center}
.btn{display:inline-flex;align-items:center;gap:8px;font:600 14px var(--sans);padding:12px 22px;border-radius:var(--radius-sm);border:1px solid transparent;cursor:pointer;text-decoration:none;white-space:nowrap}
.btn-primary{background:var(--primary-600);color:var(--on-primary)}
.btn-primary:hover{background:var(--primary-700)}
.btn-ghost{background:var(--surface);color:var(--ink);border-color:var(--line)}
.btn-ghost:hover{background:var(--hover)}
.topbar .btn{padding:8px 14px;margin:0;width:auto}
`;

/* ------------------------------------------------------------------ */
/* Utilidades                                                          */
/* ------------------------------------------------------------------ */

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function formatSize(bytes) {
  const n = Number(bytes) || 0;
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(2)} GB`;
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`;
  return `${Math.ceil(n / 1024)} KB`;
}

function log(evt, data) {
  console.log(JSON.stringify({ evt, ...data }));
}

async function sha256hex(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64decode(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
