# HDRI Studio

Página web para crear HDRIs 360° (`.hdr`) a partir de fotos en bracketing. Todo se procesa en el navegador.

La página está **cifrada con contraseña** (PBKDF2-SHA256 + AES-256-GCM). Este repositorio solo contiene la versión cifrada (`index.html`). Sin la contraseña el contenido es ilegible.

## Actualizar la página
1. Pon la nueva versión sin cifrar en `src/hdri-studio.html`. Esa carpeta no se sube al repositorio.
2. Ejecuta `node tools/encrypt.mjs` y escribe la contraseña.
3. Haz commit y push de `index.html`.
