// Cifra src/hdri-studio.html y genera index.html (página protegida con contraseña).
//
//   node tools/encrypt.mjs --setup   -> pide la contraseña UNA vez, crea una llave de contenido aleatoria
//                                        y la guarda envuelta con la contraseña en .secrets/ (no se sube a GitHub).
//   node tools/encrypt.mjs           -> vuelve a cifrar la página con esa llave, SIN pedir contraseña.
//
// Esquema: llave de contenido K (AES-256-GCM, aleatoria). K se guarda en index.html cifrada con
// PBKDF2-SHA256(contraseña, 600 000 iteraciones). Quien entra escribe la contraseña -> descifra K -> descifra la página.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const secretsDir = join(root, ".secrets"), secretsFile = join(secretsDir, "content-key.json");
const ITER = 600000;
const b64 = u8 => Buffer.from(u8).toString("base64");
const unb64 = s => new Uint8Array(Buffer.from(s, "base64"));
const enc = new TextEncoder();

function askHidden(prompt) {
  return new Promise(resolve => {
    process.stdout.write(prompt);
    const stdin = process.stdin;
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding("utf8");
    let pw = "";
    const onData = chunk => {
      for (const c of chunk) {
        if (c === "\r" || c === "\n") { stdin.setRawMode(false); stdin.pause(); stdin.removeListener("data", onData); process.stdout.write("\n"); resolve(pw); return; }
        else if (c === "\u0003") { process.stdout.write("\nCancelado.\n"); process.exit(1); }
        else if (c === "\u0008" || c === "\u007f") { if (pw.length) { pw = pw.slice(0, -1); process.stdout.write("\b \b"); } }
        else { pw += c; process.stdout.write("*"); }
      }
    };
    stdin.on("data", onData);
  });
}

async function setup() {
  const pw1 = await askHidden("Contraseña para entrar a la página: ");
  if (pw1.length < 6) { console.log("Usa al menos 6 caracteres."); process.exit(1); }
  const pw2 = await askHidden("Repite la contraseña:               ");
  if (pw1 !== pw2) { console.log("Las contraseñas no coinciden."); process.exit(1); }
  const K = crypto.getRandomValues(new Uint8Array(32));
  const salt = crypto.getRandomValues(new Uint8Array(16)), wiv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey("raw", enc.encode(pw1), "PBKDF2", false, ["deriveKey"]);
  const kek = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: wiv }, kek, K));
  mkdirSync(secretsDir, { recursive: true });
  writeFileSync(secretsFile, JSON.stringify({ k: b64(K), salt: b64(salt), wiv: b64(wiv), wrapped: b64(wrapped), iter: ITER }, null, 2));
  console.log("Llave creada. Desde ahora la página se puede volver a publicar sin pedir la contraseña.");
}

if (process.argv.includes("--setup") || !existsSync(secretsFile)) await setup();

const sec = JSON.parse(readFileSync(secretsFile, "utf8"));
const key = await crypto.subtle.importKey("raw", unb64(sec.k), { name: "AES-GCM" }, false, ["encrypt"]);
let html = readFileSync(join(root, "src", "hdri-studio.html"), "utf8");
if (!/^\s*<!doctype/i.test(html)) html = '<!doctype html><html lang="es"><head><meta charset="utf-8"></head><body>' + html + "</body></html>";
const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(html)));
const payload = JSON.stringify({ iter: sec.iter, salt: sec.salt, wiv: sec.wiv, wrapped: sec.wrapped, iv: b64(iv), ct: b64(ct) });
const page = readFileSync(join(root, "tools", "gate.html"), "utf8").replace("__PAYLOAD__", () => payload);
writeFileSync(join(root, "index.html"), page);
console.log(`Listo: index.html cifrado (${(page.length / 1024).toFixed(0)} KB).`);
