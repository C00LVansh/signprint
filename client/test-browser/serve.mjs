// Tiny static server for the browser tests: serves the built client and the
// shared test vectors from localhost, which counts as a secure context so
// crypto.subtle is available.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const roots = {
  "/dist/": join(here, "..", "dist"),
  "/testvectors/": join(here, "..", "..", "testvectors"),
};
const types = { ".js": "text/javascript", ".json": "application/json", ".map": "application/json" };
const port = Number(process.env.PORT ?? 4173);

createServer(async (req, res) => {
  const path = new URL(req.url ?? "/", "http://x").pathname;
  if (path === "/" || path === "/blank.html") {
    res.writeHead(200, { "content-type": "text/html" }).end("<!doctype html><title>signprint test</title>");
    return;
  }
  for (const [prefix, dir] of Object.entries(roots)) {
    if (!path.startsWith(prefix)) continue;
    const file = normalize(join(dir, path.slice(prefix.length)));
    if (!file.startsWith(dir + sep)) break;
    try {
      const body = await readFile(file);
      res.writeHead(200, { "content-type": types[extname(file)] ?? "application/octet-stream" }).end(body);
    } catch {
      res.writeHead(404).end();
    }
    return;
  }
  res.writeHead(404).end();
}).listen(port, "127.0.0.1", () => console.log(`serving on http://127.0.0.1:${port}`));
