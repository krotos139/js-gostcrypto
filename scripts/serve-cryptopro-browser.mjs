import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const port = Number(process.env.GOSTCRYPTO_BROWSER_PORT ?? 4173);
const routes = new Map([
  ["/", "examples/cryptopro-browser/index.html"],
  ["/examples/cryptopro-browser/", "examples/cryptopro-browser/index.html"],
  ["/examples/cryptopro-browser/index.html", "examples/cryptopro-browser/index.html"],
  ["/examples/cryptopro-browser/app.js", "examples/cryptopro-browser/app.js"],
  ["/packages/gostcrypto/dist/gostcrypto.min.js", "packages/gostcrypto/dist/gostcrypto.min.js"],
]);
const contentTypes = new Map([[".html", "text/html; charset=utf-8"], [".js", "text/javascript; charset=utf-8"]]);

const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    const relativePath = routes.get(pathname);
    if (relativePath === undefined) {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("Not found");
      return;
    }
    const file = resolve(root, relativePath);
    const metadata = await stat(file);
    response.writeHead(200, {
      "content-length": metadata.size,
      "content-type": contentTypes.get(extname(file)) ?? "application/octet-stream",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    });
    createReadStream(file).pipe(response);
  } catch (error) {
    response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    response.end(error instanceof Error ? error.message : String(error));
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`CryptoPro browser smoke test: http://127.0.0.1:${port}/examples/cryptopro-browser/`);
});
