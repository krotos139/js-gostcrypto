import { readFile } from "node:fs/promises";
import { streebog256, streebog512 } from "@gostcrypto/hash";

const [, , inputPath, bits = "256"] = process.argv;

if (inputPath === undefined || (bits !== "256" && bits !== "512")) {
  console.error("Usage: node hash-file.mjs <file> [256|512]");
  process.exitCode = 2;
} else {
  const data = new Uint8Array(await readFile(inputPath));
  const digest = bits === "256" ? streebog256(data) : streebog512(data);
  console.log(Buffer.from(digest).toString("hex"));
}
