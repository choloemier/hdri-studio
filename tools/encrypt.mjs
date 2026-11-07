// Cifra src/hdri-studio.html con una contraseña y genera index.html.
// Uso:  node tools/encrypt.mjs
// La contraseña se pide oculta en la terminal y nunca se guarda en ningún archivo.
// Cifrado: PBKDF2-SHA256 (600 000 iteraciones) -> AES-256-GCM. Sin la contraseña el contenido es ilegible.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ITER = 600000;

function askHidden(prompt) {
  return new Promise(resolve => {
    process.stdout.write(prompt);
    const stdin = process.stdin;
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding("utf8");
    let pw = "";
    const onData = chunk => {
      for (const c of chunk) {
        if (c === "\r" || c === "\n") {
          stdin.setRawMode(false); stdin.pause(); stdin.removeListener("data", onData);
          process.stdout.write("\n"); resolve(pw); return;
        } else if (c === "\u0003") { process.stdout.write("\nCancelado.\n"); process.exit(1); }
        else if (c === "\u0008" || c === "\u007f") { if (pw.length) { pw = pw.slice(0, -1); process.stdout.write("\b \b"); } }
        else { pw += c; process.stdout.write("*"); }
      }
    };
    stdin.on("data", onData);
  });
}

const pw1 = await askHidden("Contraseña para la página: ");
if (pw1.length < 6) { console.log("Usa al menos 6 caracteres."); process.exit(1); }
const pw2 = await askHidden("Repite la contraseña:       ");
if (pw1 !== pw2) { console.log("Las contraseñas no coinciden."); process.exit(1); }

let html = readFileSync(join(root, "src", "hdri-studio.html"), "utf8");
if (!/^\s*<!doctype/i.test(html)) {
  html = '<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"></head><body>' + html + "</body></html>";
}
const enc = new TextEncoder();
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey("raw", enc.encode(pw1), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(html)));
const payload = Buffer.concat([salt, iv, ct]).toString("base64");

const page = readFileSync(join(root, "tools", "gate.html"), "utf8")
  .replace("__ITER__", String(ITER))
  .replace("__PAYLOAD__", payload);
writeFileSync(join(root, "index.html"), page);
console.log(`Listo: index.html cifrado (${(page.length / 1024).toFixed(0)} KB).`);
