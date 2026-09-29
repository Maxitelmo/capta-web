#!/usr/bin/env node
/**
 * Administración del área de actualizaciones de CAPTA.
 * Usa wrangler (ya autenticado con `npx wrangler login`) para escribir en KV y R2.
 *
 *   node scripts/admin.mjs user:add <usuario> ["Nombre visible"]
 *   node scripts/admin.mjs user:reset <usuario>
 *   node scripts/admin.mjs user:disable <usuario>
 *   node scripts/admin.mjs user:enable <usuario>
 *   node scripts/admin.mjs user:del <usuario>
 *   node scripts/admin.mjs user:list
 *   node scripts/admin.mjs release:publish <archivo.zip> <version> <notas.txt>
 *   node scripts/admin.mjs release:list
 *
 * Agregar --local para operar contra el entorno de `wrangler dev`.
 */
import { spawnSync } from "node:child_process";
import { createHash, pbkdf2Sync, randomBytes, randomInt } from "node:crypto";
import { createReadStream, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

const PBKDF2_ITER = 100000; // igual que el Worker (máximo de WebCrypto en Workers)
const USER_RE = /^[a-z0-9._-]{3,32}$/;
const VERSION_RE = /^[0-9A-Za-z._-]{1,40}$/;
const BUCKET = "capta-actualizaciones";

const args = process.argv.slice(2);
const local = args.includes("--local");
const [cmd, ...rest] = args.filter((a) => a !== "--local");
const target = local ? "--local" : "--remote";

function wrangler(params, { input } = {}) {
  const r = spawnSync("npx", ["wrangler", ...params, target], {
    encoding: "utf8",
    input,
    stdio: ["pipe", "pipe", "pipe"],
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) {
    throw new Error(`wrangler ${params.join(" ")} falló:\n${r.stderr || r.stdout}`);
  }
  return r.stdout;
}

function kvGet(key) {
  const r = spawnSync("npx", ["wrangler", "kv", "key", "get", key, "--binding", "DB", "--text", target], {
    encoding: "utf8",
  });
  if (r.status !== 0) return null;
  const out = r.stdout.trim();
  if (!out || out === "Value not found") return null;
  return out;
}

function kvPut(key, value) {
  const dir = mkdtempSync(join(tmpdir(), "capta-"));
  const file = join(dir, "v");
  try {
    writeFileSync(file, value, { mode: 0o600 });
    wrangler(["kv", "key", "put", key, "--binding", "DB", "--path", file]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function kvDel(key) {
  wrangler(["kv", "key", "delete", key, "--binding", "DB"]);
}

function kvList(prefix) {
  const out = wrangler(["kv", "key", "list", "--binding", "DB", "--prefix", prefix]);
  const start = out.indexOf("[");
  return JSON.parse(out.slice(start)).map((k) => k.name);
}

function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = pbkdf2Sync(password, salt, PBKDF2_ITER, 32, "sha256");
  return `pbkdf2$${PBKDF2_ITER}$${salt.toString("base64")}$${hash.toString("base64")}`;
}

/** 20 caracteres sin ambigüedades (sin 0/O, 1/l/I): ~115 bits. */
function generatePassword() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  let out = "";
  for (let i = 0; i < 20; i++) out += alphabet[randomInt(alphabet.length)];
  return out.replace(/(.{5})(?=.)/g, "$1-");
}

function requireUser(name) {
  const user = String(name || "").toLowerCase();
  if (!USER_RE.test(user)) die("Usuario inválido: 3 a 32 caracteres a-z, 0-9, punto, guion o guion bajo.");
  return user;
}

function getUser(user) {
  const raw = kvGet(`user:${user}`);
  return raw ? JSON.parse(raw) : null;
}

function maxUsers() {
  const m = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8").match(/MAX_USERS\s*=\s*"(\d+)"/);
  return m ? Number(m[1]) : 100;
}

function sha256File(path) {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    createReadStream(path).on("data", (d) => h.update(d)).on("error", reject).on("end", () => resolve(h.digest("hex")));
  });
}

function die(msg) {
  console.error(msg);
  process.exit(1);
}

function today() {
  return new Date().toLocaleDateString("es-AR", { timeZone: "America/Argentina/Cordoba" });
}

const commands = {
  "user:add"([name, nombre]) {
    const user = requireUser(name);
    if (getUser(user)) die(`El usuario "${user}" ya existe. Use user:reset para cambiar la contraseña.`);
    const count = kvList("user:").length;
    if (count >= maxUsers()) die(`Se alcanzó el máximo de ${maxUsers()} usuarios.`);
    const password = generatePassword();
    kvPut(`user:${user}`, JSON.stringify({ hash: hashPassword(password), nombre: nombre || user, creado: new Date().toISOString() }));
    console.log(`Usuario creado (${count + 1}/${maxUsers()}).\n  usuario:    ${user}\n  contraseña: ${password}\nEntréguela por un canal seguro; no se vuelve a mostrar.`);
  },

  "user:reset"([name]) {
    const user = requireUser(name);
    const record = getUser(user) || die(`No existe el usuario "${user}".`);
    const password = generatePassword();
    kvPut(`user:${user}`, JSON.stringify({ ...record, hash: hashPassword(password), actualizado: new Date().toISOString() }));
    console.log(`Contraseña restablecida.\n  usuario:    ${user}\n  contraseña: ${password}`);
  },

  "user:disable"([name]) {
    const user = requireUser(name);
    const record = getUser(user) || die(`No existe el usuario "${user}".`);
    kvPut(`user:${user}`, JSON.stringify({ ...record, disabled: true }));
    console.log(`Usuario "${user}" deshabilitado (sus sesiones dejan de valer).`);
  },

  "user:enable"([name]) {
    const user = requireUser(name);
    const record = getUser(user) || die(`No existe el usuario "${user}".`);
    delete record.disabled;
    kvPut(`user:${user}`, JSON.stringify(record));
    console.log(`Usuario "${user}" habilitado.`);
  },

  "user:del"([name]) {
    const user = requireUser(name);
    if (!getUser(user)) die(`No existe el usuario "${user}".`);
    kvDel(`user:${user}`);
    console.log(`Usuario "${user}" eliminado (sus sesiones dejan de valer).`);
  },

  "user:list"() {
    const names = kvList("user:").map((k) => k.slice(5));
    for (const u of names) {
      const r = getUser(u) || {};
      console.log(`${u.padEnd(34)}${(r.nombre || "").padEnd(34)}${r.disabled ? "DESHABILITADO" : ""}`);
    }
    console.log(`\n${names.length}/${maxUsers()} usuarios`);
  },

  async "release:publish"([zip, version, notesFile]) {
    if (!zip || !version || !notesFile) die("Uso: release:publish <archivo.zip> <version> <notas.txt>");
    if (!VERSION_RE.test(version)) die("Versión inválida (use por ej. 3.2.0).");
    if (!zip.toLowerCase().endsWith(".zip")) die("El archivo debe ser .zip");
    const size = statSync(zip).size;
    if (size > 300 * 1024 * 1024) {
      die("El ZIP supera 300 MB, el límite de subida de wrangler. Súbalo con rclone/aws-cli (API S3 de R2) y avise para adaptar el script.");
    }
    const notas = readFileSync(notesFile, "utf8").trim();
    const sha256 = await sha256File(zip);
    const key = `capta-${version}.zip`;

    console.log(`Subiendo ${basename(zip)} (${(size / 1048576).toFixed(1)} MB) a R2 como ${key}...`);
    wrangler(["r2", "object", "put", `${BUCKET}/${key}`, "--file", zip, "--content-type", "application/zip"]);

    const current = JSON.parse(kvGet("config:releases") || "[]").filter((r) => r.version !== version);
    const next = [{ version, fecha: today(), key, size, sha256, notas }, ...current];
    const keep = next.slice(0, 2);
    kvPut("config:releases", JSON.stringify(keep));

    for (const old of next.slice(2)) {
      if (keep.some((r) => r.key === old.key)) continue;
      console.log(`Eliminando versión antigua ${old.version} (${old.key}) de R2...`);
      wrangler(["r2", "object", "delete", `${BUCKET}/${old.key}`]);
    }
    console.log(`Publicada CAPTA ${version}\n  SHA-256: ${sha256}\nVisibles: ${keep.map((r) => r.version).join(", ")}`);
  },

  "release:list"() {
    const list = JSON.parse(kvGet("config:releases") || "[]");
    if (!list.length) return console.log("Sin versiones publicadas.");
    list.forEach((r, i) => console.log(`${i === 0 ? "nueva   " : "anterior"}  ${r.version}  ${r.fecha}  ${r.key}  ${r.sha256}`));
  },
};

const fn = commands[cmd];
if (!fn) {
  console.log(readFileSync(new URL(import.meta.url), "utf8").split("*/")[0].replace(/^#!.*\n\/\*\*?/, "").replace(/^ \* ?/gm, ""));
  process.exit(cmd ? 1 : 0);
}
try {
  await fn(rest);
} catch (err) {
  die(err.message);
}
