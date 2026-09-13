import { readFile, writeFile } from "node:fs/promises";
import { parseSignedData } from "@gostcrypto/cms";
import { openPfxFile } from "@gostcrypto/node";

const [, , pfxPath, inputPath, outputPath, bits = "256"] = process.argv;
const password = process.env.PFX_PASSWORD;

if (pfxPath === undefined || inputPath === undefined || outputPath === undefined ||
    (bits !== "256" && bits !== "512")) {
  console.error("Usage: node sign-pfx.mjs <key.pfx> <document> <signature.p7s> [256|512]");
  process.exitCode = 2;
} else if (password === undefined) {
  console.error("Set PFX_PASSWORD in the process environment.");
  process.exitCode = 2;
} else {
  const provider = await openPfxFile(pfxPath, password);
  const certificate = (await provider.listCertificates()).find((item) => item.hasPrivateKey);
  if (certificate === undefined) throw new Error("The PFX contains no certificate with a private key.");

  const document = new Uint8Array(await readFile(inputPath));
  const signature = await provider.sign(certificate.id, document, {
    algorithm: `gost3410-2012-${bits}`,
    detached: true,
  });

  parseSignedData(signature).verify(document);
  await writeFile(outputPath, signature);
  console.log(`Created and verified ${outputPath} (${signature.length} bytes) with ${certificate.subject}`);
}
