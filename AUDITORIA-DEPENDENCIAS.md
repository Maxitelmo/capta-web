# Auditoría de dependencias y código de terceros

**Proyecto:** CAPTA · Sitio institucional y guías (`capta-web`)
**Fecha:** 2026-09-06
**Alcance:** dependencias de librerías, programas y todo código de terceros, con foco en la **distribución del software**.
**Método:** análisis estático de los 12 archivos versionados (3 HTML, 4 PNG, favicon, robots, sitemap, verificación Google, `.nojekyll`), tras descartar los `data:` URIs base64 para evitar falsos positivos.

---

## Veredicto

**El sitio no tiene dependencias de terceros en tiempo de ejecución.** Cero CDN, cero librerías JS/CSS externas, cero fuentes descargadas, cero tracking, cero cadena de suministro de paquetes. Para distribución, es prácticamente el escenario ideal: superficie de ataque por dependencias = 0 y funcionamiento offline real. La afirmación del README ("autocontenidas… no dependen de servicios externos") es **correcta**, con matices menores documentados abajo.

---

## Aciertos

1. **Cero dependencias en runtime.** No hay `<script src>` ni `<link rel=stylesheet>` a dominios externos, ni CDN (jsdelivr/unpkg/cloudflare/googleapis), ni `@import`, ni `fetch`/`XHR`/`WebSocket`/`Worker`.
2. **JavaScript 100% propio y vanilla.** Solo tres funciones: toggle de tema, menú móvil y selector de plataforma. Sin `eval`, `new Function`, `document.write` ni `innerHTML` dinámico → sin vectores de inyección por código de terceros.
3. **Tipografías del sistema.** Solo *font stacks* (`-apple-system, Segoe UI, Roboto…` y `ui-monospace`). No se embeben ni descargan fuentes → **sin exposición de licencias tipográficas**.
4. **Sin telemetría.** No hay Google Analytics/gtag, Tag Manager, Meta Pixel, Hotjar, Clarity, Sentry ni similares. Ningún dato del usuario sale hacia terceros — relevante en un contexto forense/institucional.
5. **Assets autocontenidos.** Imágenes embebidas en base64 o locales (`assets/*.png`, `favicon.png`). El sitio se abre y funciona sin conexión.
6. **Sin cadena de suministro de build.** No hay `package.json`, lockfiles, `node_modules`, ni CI. No hay dependencias transitivas que auditar ni actualizar.
7. **Enlaces externos con `rel="noopener"`** y `target="_blank"` (buena práctica de seguridad).
8. **Peso total ~624 KB**, íntegramente versionado y auditable a mano.

---

## Observaciones y puntos a corregir (para distribución)

1. **Sin Content-Security-Policy ni cabeceras de seguridad.** No hay `<meta http-equiv="Content-Security-Policy">` ni equivalentes. No es una vulnerabilidad activa (no se carga nada externo), pero como defensa en profundidad conviene declarar una CSP restrictiva. Como CSS y JS son *inline*, requeriría `'unsafe-inline'` o migrar a hashes/archivos. Ejemplo mínimo coherente con el sitio actual:
   ```html
   <meta http-equiv="Content-Security-Policy"
         content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
   ```

2. **Dependencias de red residuales (rompen el "100% offline").** No son código de terceros embebido, pero sí requieren Internet:
   - 2 enlaces salientes a PDFs de referencia en `55jaiio.sadio.org.ar` (`index.html`). Son **citas académicas**, no recursos cargados; en una copia offline quedan como enlaces muertos.
   - `google-site-verification` y `sitemap`/`robots` apuntando a Google Search Console.
   - `schema.org` aparece solo como **vocabulario** en el JSON-LD (no se descarga): no cuenta como dependencia.

3. **Acoplamiento al dominio `maxitelmo.github.io`.** `canonical`, `og:url`, `sitemap.xml` y `robots.txt` tienen la URL hardcodeada. Si el sitio se distribuye en otro dominio, como paquete offline o dentro de la propia herramienta CAPTA, estos metadatos quedan inconsistentes. Conviene parametrizarlos o documentar que deben ajustarse por instancia.

4. **Archivos específicos de la instancia GitHub Pages** (`google283ba198f6c0728e.html`, `.nojekyll`, `robots.txt`, `sitemap.xml`): son ruido en una copia distribuida fuera de GitHub Pages. Recomendable excluirlos del paquete de distribución offline.

5. **Sin verificación de integridad del propio paquete.** No hay checksums ni firma de los HTML distribuidos. Dado que CAPTA es una herramienta forense que basa su valor en hashes SHA-256 y cadena de custodia, sería coherente **publicar los SHA-256 de los archivos distribuidos** para que un tercero pueda verificar que la copia que recibió no fue alterada.

---

## Inventario de terceros

| Tipo | Detectado | Detalle |
|---|---|---|
| Librerías JS (jQuery, React, Vue, Bootstrap, etc.) | **No** | Todo JS es propio y vanilla |
| CSS/frameworks externos (Tailwind, Bootstrap CSS) | **No** | CSS propio, inline |
| Fuentes web (Google Fonts, `@font-face`) | **No** | Solo *font stacks* del sistema |
| CDN / scripts remotos | **No** | — |
| Analytics / tracking / telemetría | **No** | — |
| Gestores de paquetes / build (npm, etc.) | **No** | Sin `package.json` ni `node_modules` |
| Imágenes/recursos externos | **No** | base64 o `assets/` locales |
| Enlaces salientes | **Sí (2)** | PDFs de referencia en `55jaiio.sadio.org.ar` (`rel="noopener"`) |
| Vocabulario JSON-LD | schema.org | Solo referencia semántica, no se descarga |

---

## Conclusión

Desde la óptica de la distribución del software, el proyecto está **limpio**: no arrastra código de terceros que auditar, versionar o parchear, y no filtra datos. Las mejoras propuestas son de robustez y consistencia (CSP, desacople del dominio, checksums de distribución), no correcciones de dependencias inseguras.
