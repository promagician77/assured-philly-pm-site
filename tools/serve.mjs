// Minimal static server for local preview and QA (Vercel serves the same files in production).
import { createServer } from "node:http";
import { readFileSync, existsSync, statSync } from "node:fs";
import { extname, join, normalize, resolve } from "node:path";
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css",
  ".json": "application/json", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".svg": "image/svg+xml",
  ".woff2": "font/woff2", ".wasm": "application/wasm", ".pck": "application/octet-stream", ".zip": "application/zip" };
export function serve(root, port = 4180) {
  root = resolve(root);
  return createServer((req, res) => {
    let p = normalize(join(root, decodeURIComponent(req.url.split("?")[0])));
    if (existsSync(p) && statSync(p).isDirectory()) p = join(p, "index.html");
    if (!p.startsWith(normalize(root)) || !existsSync(p)) { res.writeHead(404); return res.end("not found"); }
    res.writeHead(200, { "content-type": TYPES[extname(p)] || "application/octet-stream" });
    res.end(readFileSync(p));
  }).listen(port);
}
if (process.argv[1] && process.argv[1].endsWith("serve.mjs")) {
  const root = process.argv[2] || "."; serve(root, 4180); console.log("http://localhost:4180");
}
