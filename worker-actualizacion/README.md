# CAPTA · Área privada de actualizaciones

Sitio con usuario y contraseña para descargar las actualizaciones de CAPTA en ZIP.
No está enlazado desde el sitio público: la dirección se entrega solo a los
usuarios habilitados.

Muestra las **dos últimas versiones** (la nueva y la anterior), con descripción,
tamaño, hash SHA-256, botón de descarga y la guía de actualización (pendiente de
redactar en `src/index.js`, sección `#guia`).

## Por qué un Worker y no GitHub Pages

GitHub Pages es estático y todo lo que está en el repositorio es público: ahí no se
puede hacer un login real ni ocultar los ZIP. Este Worker de Cloudflare atiende solo
`/actualizacion` y `/actualizacion/*`. El resto del dominio sigue en GitHub Pages.

| Pieza | Uso |
|---|---|
| Worker | Login, sesiones, páginas y descargas |
| KV `DB` | Usuarios (hash de contraseña), sesiones, límite de intentos, lista de versiones |
| R2 `capta-actualizaciones` | ZIP en bucket **privado**: solo se descargan a través del Worker con sesión válida |

Todo entra en el plan gratuito de Cloudflare para este volumen (hasta 100 usuarios).

## Seguridad

- Contraseñas con PBKDF2-SHA256 (100.000 iteraciones, sal aleatoria). Nunca se guardan en claro.
- Las contraseñas las genera el script (20 caracteres aleatorios); no hay registro público ni "olvidé mi contraseña".
- Sesión con token aleatorio de 256 bits en cookie `__Host-`, `HttpOnly`, `Secure`, `SameSite=Strict`; vence a las 8 h. En KV solo se guarda el hash del token.
- Bloqueo por intentos fallidos: 8 por usuario o 30 por IP en 15 minutos.
- Mismo tiempo de respuesta exista o no el usuario (no se puede averiguar qué usuarios son válidos).
- Los POST se aceptan solo desde el propio origen (protección CSRF).
- Borrar o deshabilitar un usuario corta sus sesiones al instante.
- Cabeceras: CSP sin scripts, `frame-ancestors 'none'`, HSTS, `no-store`, `noindex`.
- Registro de ingresos, fallos y descargas (usuario, versión, IP) en los logs del Worker (Cloudflare → Workers → capta-actualizacion → Logs).

La ruta `/actualizacion` figura en este repositorio público. No es un secreto: la
protección es el login. Para usar otra ruta, cambiar `BASE_PATH` y `routes` en
`wrangler.toml`.

## Puesta en marcha (una sola vez)

Requisitos: Node 18+, una cuenta de Cloudflare y un **dominio propio** gestionado
por Cloudflare (`maxitelmo.github.io` no sirve: es de GitHub).

1. **Dominio en Cloudflare → GitHub Pages**
   - Agregar el dominio a Cloudflare y cambiar los DNS en el registrador.
   - Crear un registro `CNAME` (por ej. `capta` → `maxitelmo.github.io`) con proxy activado (nube naranja).
   - En GitHub → Settings → Pages → *Custom domain*, poner ese dominio. SSL/TLS en Cloudflare: **Full**.
   - Actualizar `canonical`, `og:url`, `sitemap.xml` y `robots.txt` del sitio al dominio nuevo.

2. **Recursos de Cloudflare**
   ```sh
   cd worker-actualizacion
   npm install
   npx wrangler login
   npx wrangler kv namespace create DB          # copiar el id a wrangler.toml
   npx wrangler r2 bucket create capta-actualizaciones
   ```
   El bucket R2 queda privado por defecto: **no** activar acceso público ni `r2.dev`.

3. **Configurar `wrangler.toml`**: `id` del KV y las dos rutas con el dominio real
   (`capta.ejemplo.gob.ar/actualizacion` y `.../actualizacion/*`, y `zone_name`).

4. **Publicar**
   ```sh
   npx wrangler deploy
   ```

## Uso diario

```sh
cd worker-actualizacion

# Usuarios (máximo 100)
node scripts/admin.mjs user:add jperez "Juan Pérez"   # imprime la contraseña generada
node scripts/admin.mjs user:reset jperez               # nueva contraseña
node scripts/admin.mjs user:disable jperez             # bloquea sin borrar
node scripts/admin.mjs user:enable jperez
node scripts/admin.mjs user:del jperez
node scripts/admin.mjs user:list

# Versiones
node scripts/admin.mjs release:publish CAPTA-3.2.0.zip 3.2.0 notas.txt
node scripts/admin.mjs release:list
```

- La contraseña se muestra una sola vez: entregarla por un canal seguro, separado de la dirección del sitio.
- `release:publish` sube el ZIP, calcula su SHA-256 y deja visibles la nueva y la anterior; la más vieja se borra de R2.
- `notas.txt` es texto plano: una línea en blanco separa párrafos; las líneas que empiezan con `- ` forman una lista.
- Límite de subida con wrangler: 300 MB por ZIP.

## Prueba local

```sh
node scripts/admin.mjs user:add prueba --local
node scripts/admin.mjs release:publish prueba.zip 0.0.1 notas.txt --local
npx wrangler dev
# abrir http://localhost:8787/actualizacion
```

## Pendiente

- Redactar la guía "Cómo actualizar" (`src/index.js`, función `releasesPage`).
