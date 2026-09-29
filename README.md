# CAPTA · Sitio institucional y guías de estudio

Sitio de **CAPTA (Colecta Ágil de PEP Técnico Auditable)**, la herramienta de
adquisición forense digital móvil (Android / iOS) del **Ministerio Público Fiscal
de Córdoba**, desarrollada en la Dirección de Investigación Operativa y aprobada por
Resolución FG N° 7/26.

Está pensado como material de capacitación para operadores y como difusión de uso
del sistema.

## Contenido del sitio

| Archivo | Descripción |
|---|---|
| [`index.html`](index.html) | Portada institucional: qué es CAPTA, qué releva, integridad y cadena de custodia, respaldo institucional y accesos a las guías. |
| [`guia.html`](guia.html) | Guía interactiva, con selector Android / iOS / comparación, capacidades de extracción, modo de operación, cadena de custodia, referencias y glosario. |
| [`guia_adb.html`](guia_adb.html) | Guía ilustrada complementaria: cómo activar la depuración USB (ADB) en Android, paso a paso. |
| `favicon.png` | Ícono de la marca CAPTA. |
| `sitemap.xml` | Mapa del sitio para buscadores (Google Search Console). |
| `robots.txt` | Permite el rastreo e indica la ubicación del sitemap. |
| [`worker-actualizacion/`](worker-actualizacion/README.md) | Área privada de descargas de actualizaciones (Cloudflare Worker con login). No se enlaza desde el sitio; el código es público pero no contiene usuarios, contraseñas ni ZIP. |

Las tres páginas son **autocontenidas** (CSS e imágenes embebidas): funcionan sin
conexión y no dependen de servicios externos. Comparten una capa común de tokens de
diseño (color, tipografía y espaciado) mantenida idéntica en los tres archivos.

### Política de seguridad de contenido (CSP)

Cada página declara una CSP en `<meta http-equiv="Content-Security-Policy">` que solo
permite los `<script>` internos cuyo hash SHA-256 figura en `script-src`. **Si se
modifica o agrega un script interno, hay que recalcular su hash** o el navegador lo
bloqueará. No usar atributos `onclick=` ni similares: asignar eventos desde un script.

```sh
python3 -c "import re,sys,hashlib,base64;s=open(sys.argv[1],encoding='utf-8').read();[print(\"'sha256-%s'\"%base64.b64encode(hashlib.sha256(m.encode()).digest()).decode()) for m in re.findall(r'<script>(.*?)</script>',s,re.S)]" index.html
```


## Créditos

CAPTA — Ministerio Público Fiscal de Córdoba. Aprobada por Resolución FG N° 7/26.
Material de capacitación y difusión de uso abierto.
