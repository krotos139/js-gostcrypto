import { build } from "esbuild";
import { copyFile, readdir } from "node:fs/promises";

const packageDirectories=(await readdir("packages",{withFileTypes:true})).filter((entry)=>entry.isDirectory()).map((entry)=>`packages/${entry.name}`);
await Promise.all(packageDirectories.flatMap((directory)=>[copyFile("LICENSE",`${directory}/LICENSE`),copyFile("README.md",`${directory}/README.md`)]));

const entry="packages/gostcrypto/src/index.ts";
await Promise.all([
  build({entryPoints:[entry],outfile:"packages/gostcrypto/dist/index.cjs",bundle:true,format:"cjs",platform:"node",target:"node18",legalComments:"none"}),
  build({entryPoints:[entry],outfile:"packages/gostcrypto/dist/browser.js",bundle:true,format:"esm",platform:"browser",target:"es2022",legalComments:"none"}),
  build({entryPoints:[entry],outfile:"packages/gostcrypto/dist/gostcrypto.min.js",bundle:true,format:"iife",globalName:"GostCrypto",platform:"browser",target:"es2020",minify:true,legalComments:"none"}),
]);
