import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, extname, sep } from "node:path";
import { existsSync } from "node:fs";

const PORT = parseInt(process.argv[2] || "4175", 10);
const STATIC_DIR = resolve(
  import.meta.dirname,
  "../../src/codex_plugin_scanner/guard/daemon/static",
);

const MIME = {
  ".html": "text/html",
  ".js": "application/javascript",
  ".css": "text/css",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost`);
  const candidatePath = resolve(STATIC_DIR, "." + url.pathname);
  const staticDirPrefix = `${STATIC_DIR}${sep}`;
  const isPathInsideStaticDir =
    candidatePath === STATIC_DIR || candidatePath.startsWith(staticDirPrefix);
  let filePath = isPathInsideStaticDir ? candidatePath : resolve(STATIC_DIR, "index.html");

  if (!existsSync(filePath) || filePath === STATIC_DIR) {
    filePath = resolve(STATIC_DIR, "index.html");
  }

  const ext = extname(filePath);
  const mime = MIME[ext] || "application/octet-stream";

  try {
    const data = await readFile(filePath);
    res.writeHead(200, { "Content-Type": mime });
    res.end(data);
  } catch {
    const html = await readFile(resolve(STATIC_DIR, "index.html"));
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`HOL Guard static server ready on http://127.0.0.1:${PORT}`);
});
