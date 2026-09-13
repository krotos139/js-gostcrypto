import { readFile, readdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build, transform } from "esbuild";

const examples = fileURLToPath(new URL("../examples/", import.meta.url));
const root = fileURLToPath(new URL("../", import.meta.url));

async function files(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules" && entry.name !== "dist") result.push(...await files(path));
    } else result.push(path);
  }
  return result;
}

const paths = await files(examples);
let sourceCount = 0;
for (const path of paths) {
  const extension = extname(path);
  if (extension === ".js" || extension === ".mjs" || extension === ".jsx") {
    await transform(await readFile(path, "utf8"), {
      loader: extension === ".jsx" ? "jsx" : "js",
      format: "esm",
      target: "es2022",
      sourcefile: path,
    });
    sourceCount += 1;
  } else if (entryName(path) === "package.json") {
    JSON.parse(await readFile(path, "utf8"));
  }
}

const hashExample = fileURLToPath(new URL("../examples/node/hash-file.mjs", import.meta.url));
const fixture = fileURLToPath(new URL("../package.json", import.meta.url));
for (const bits of ["256", "512"]) {
  const run = spawnSync(process.execPath, [hashExample, fixture, bits], { encoding: "utf8" });
  if (run.status !== 0) throw new Error(`Node hash example failed: ${run.stderr}`);
  const expectedLength = Number(bits) / 4;
  if (!new RegExp(`^[0-9a-f]{${expectedLength}}$`).test(run.stdout.trim())) {
    throw new Error(`Node hash example returned an invalid Streebog-${bits} digest`);
  }
}

const localPackages = {
  name: "local-gostcrypto-packages",
  setup(buildContext) {
    buildContext.onResolve({ filter: /^@gostcrypto\// }, (arguments_) => ({
      path: join(root, "packages", arguments_.path.slice("@gostcrypto/".length), "src", "index.ts"),
    }));
  },
};

for (const entry of [
  "react/src/main.jsx",
  "angularjs/app.js",
  "jquery/app.js",
]) {
  await build({
    entryPoints: [join(examples, entry)],
    bundle: true,
    write: false,
    outdir: join(root, ".example-validation"),
    platform: "browser",
    format: "esm",
    target: "es2022",
    jsx: "automatic",
    external: ["angular", "jquery", "react", "react-dom/client", "react/jsx-runtime"],
    plugins: [localPackages],
  });
}

await build({
  entryPoints: [join(examples, "node", "sign-pfx.mjs")],
  bundle: true,
  write: false,
  platform: "node",
  format: "esm",
  target: "node18",
  plugins: [localPackages],
});

console.log(`Validated ${sourceCount} source files, bundled four applications, and ran both Node.js hash modes.`);

function entryName(path) {
  return path.slice(Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\")) + 1);
}
