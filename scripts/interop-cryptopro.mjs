import { execFile } from "node:child_process";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { readDer, readDerChildren } from "../packages/asn1/dist/index.js";
import { streebog256, streebog512 } from "../packages/hash/dist/index.js";
import { gost341194 } from "../packages/legacy-gost341194/dist/index.js";

const execute = promisify(execFile);
const candidates = [
  process.env.CRYPTOPRO_CSPTEST,
  "C:\\Program Files\\Crypto Pro\\CSP\\csptest.exe",
  "C:\\Program Files (x86)\\Crypto Pro\\CSP\\csptest.exe",
].filter((value) => value !== undefined);

let executable;
for (const candidate of candidates) {
  try { await access(candidate); executable = candidate; break; }
  catch { /* Try the next well-known path. */ }
}
if (executable === undefined) {
  console.log("SKIP: CryptoPro CSP csptest.exe is not installed");
  process.exit(0);
}

function digestedData(cms) {
  const outer = readDer(cms), contentInfo = readDerChildren(outer.content);
  if (outer.tag !== 0x30 || outer.end !== cms.length || contentInfo.length !== 2 || contentInfo[1].tag !== 0xa0) throw new Error("CryptoPro returned malformed CMS ContentInfo");
  const explicit = readDer(contentInfo[1].content), fields = readDerChildren(explicit.content);
  if (explicit.tag !== 0x30 || explicit.end !== contentInfo[1].content.length || fields.length !== 4 || fields[2].tag !== 0x30 || fields[3].tag !== 0x04) throw new Error("CryptoPro returned malformed CMS DigestedData");
  const encapsulated = readDerChildren(fields[2].content);
  if (encapsulated.length !== 2 || encapsulated[1].tag !== 0xa0) throw new Error("CryptoPro CMS has no encapsulated content");
  const content = readDer(encapsulated[1].content);
  if (content.tag !== 0x04 || content.end !== encapsulated[1].content.length) throw new Error("CryptoPro CMS content is malformed");
  return { content: content.content, digest: fields[3].content };
}

function equal(left, right) { return left.length === right.length && left.every((byte, index) => byte === right[index]); }
const data = Uint8Array.from({ length: 4097 }, (_, index) => (index * 73 + 19) & 0xff);
const directory = await mkdtemp(join(tmpdir(), "gostcrypto-interop-"));
try {
  const input = join(directory, "input.bin");
  await writeFile(input, data);
  for (const [algorithm, implementation] of [["GOST12_256", streebog256], ["GOST12_512", streebog512], ["GOST94_256", gost341194]]) {
    const output = join(directory, `${algorithm}.p7m`);
    await execute(executable, ["-hash", "-silent", "-alg", algorithm, "-in", input, "-out", output], { windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
    const parsed = digestedData(await readFile(output)), expected = implementation(data);
    if (!equal(parsed.content, data)) throw new Error(`${algorithm}: CryptoPro changed the encapsulated input`);
    if (!equal(parsed.digest, expected)) throw new Error(`${algorithm}: CryptoPro and JavaScript digests differ`);
    console.log(`${algorithm}: ${Buffer.from(expected).toString("hex")} OK`);
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}
