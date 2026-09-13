import assert from "node:assert/strict";
import os from "node:os";
import { performance } from "node:perf_hooks";
import { gost256B, gost512A } from "@li0ard/gost/gost3410.js";
import { Kuznyechik as LiKuznyechik } from "@li0ard/gost/kuznyechik.js";
import { Magma as LiMagma } from "@li0ard/gost/magma.js";
import { streebog256 as liStreebog256, streebog512 as liStreebog512 } from "@li0ard/gost/streebog.js";
import nodeGostCrypto from "node-gost-crypto";
import { KuznyechikCipher, MagmaCipher } from "../packages/ciphers/dist/index.js";
import { streebog256, streebog512 } from "../packages/hash/dist/index.js";
import {
  TC26_PARAM_SET_256_B,
  TC26_PARAM_SET_512_A,
  createPrivateKey,
  encodePublicKey,
  encodeSignature,
  signDigestWithK,
  verifyDigest,
} from "../packages/signature/dist/index.js";

const samples = Number.parseInt(process.env.BENCHMARK_SAMPLES ?? "5", 10);
if (!Number.isSafeInteger(samples) || samples < 1) throw new RangeError("BENCHMARK_SAMPLES must be a positive integer");

const fromHex = (value) => Uint8Array.from(value.match(/../g), (part) => Number.parseInt(part, 16));
const toHex = (value) => Buffer.from(value).toString("hex");
const median = (values) => [...values].sort((left, right) => left - right)[Math.floor(values.length / 2)];

function integerBytes(value, size, littleEndian = false) {
  const output = new Uint8Array(size);
  let current = value;
  for (let index = 0; index < size; index += 1) {
    output[littleEndian ? index : size - index - 1] = Number(current & 0xffn);
    current >>= 8n;
  }
  return output;
}

function normalizeNodeSignature(signature) {
  const bytes = new Uint8Array(signature), size = bytes.length / 2;
  return Uint8Array.from([
    ...Uint8Array.from(bytes.subarray(0, size)).reverse(),
    ...Uint8Array.from(bytes.subarray(size)).reverse(),
  ]);
}

function measure(action, iterations) {
  action();
  const values = [];
  for (let sample = 0; sample < samples; sample += 1) {
    const started = performance.now();
    for (let index = 0; index < iterations; index += 1) action();
    values.push((performance.now() - started) / iterations);
  }
  return median(values);
}

function formatDuration(milliseconds) {
  if (milliseconds < 0.001) return `${(milliseconds * 1_000_000).toFixed(0)} ns`;
  if (milliseconds < 1) return `${(milliseconds * 1_000).toFixed(1)} us`;
  return `${milliseconds.toFixed(2)} ms`;
}

const formatThroughput = (bytes, milliseconds) => `${(bytes / 1_000_000 / (milliseconds / 1_000)).toFixed(2)} MB/s`;
const kuzKey = fromHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
const kuzPlaintext = fromHex("1122334455667700ffeeddccbbaa9988");
const magmaKey = fromHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
const magmaPlaintext = fromHex("fedcba9876543210");
const hashInput = new Uint8Array(8 * 1024), message = new Uint8Array(32);
const privateScalar = 123456789n, nonce = 987654321n;

const nodeKuznyechik = () => nodeGostCrypto.gostEngine.getGostCipher({ name: "GOST R 34.12", version: 2015, length: 128, block: "ECB", padding: "NO" });
const nodeMagma = () => nodeGostCrypto.gostEngine.getGostCipher({ name: "GOST R 34.12", version: 2015, length: 64, block: "ECB", padding: "NO" });
const nodeDigest = (length) => nodeGostCrypto.gostEngine.getGostDigest({ name: "GOST R 34.11", version: 2012, length });
const createNodeSigner = (length, namedCurve, scalar) => nodeGostCrypto.gostEngine.getGostSign({
  name: "GOST R 34.10",
  version: 2012,
  length,
  namedCurve,
  hash: { name: "GOST R 34.11" },
  ukm: integerBytes(scalar, length / 8, true),
});

function createSignatureAdapters(size) {
  const curve = size === 32 ? TC26_PARAM_SET_256_B : TC26_PARAM_SET_512_A;
  const li = size === 32 ? gost256B : gost512A;
  const hash = size === 32 ? streebog256 : streebog512;
  const privateKey = createPrivateKey(curve, privateScalar), digest = hash(message);
  const oursSignatureValue = signDigestWithK(privateKey, digest, nonce);
  const oursSignature = encodeSignature(curve, oursSignatureValue);
  const liPrivateKey = integerBytes(privateScalar, size), liPublicKey = li.getPublicKey(liPrivateKey, false);
  const liDigest = Uint8Array.from(digest).reverse(), liNonce = integerBytes(nonce, size);
  const liSignature = li.sign(liPrivateKey, liDigest, { rand: liNonce });
  const bits = size * 8, nodeCurve = size === 32 ? "T-256-A" : "T-512-A";
  const generatedNodeKeyPair = createNodeSigner(bits, nodeCurve, privateScalar).generateKey();
  const nodeKeyPair = {
    privateKey: Uint8Array.from(new Uint8Array(generatedNodeKeyPair.privateKey)),
    publicKey: Uint8Array.from(new Uint8Array(generatedNodeKeyPair.publicKey)),
  };
  const nodeSigner = createNodeSigner(bits, nodeCurve, nonce);
  const nodeSignature = Uint8Array.from(new Uint8Array(nodeSigner.sign(nodeKeyPair.privateKey, message)));

  const oursPublicKey = encodePublicKey(privateKey.publicKey);
  const liPublicKeyBody = liPublicKey.subarray(1);
  const normalizedLiPublicKey = Uint8Array.from([
    ...Uint8Array.from(liPublicKeyBody.subarray(0, size)).reverse(),
    ...Uint8Array.from(liPublicKeyBody.subarray(size)).reverse(),
  ]);
  assert.equal(toHex(normalizedLiPublicKey), toHex(oursPublicKey), `${bits}-bit li public key`);
  assert.equal(toHex(nodeKeyPair.publicKey), toHex(oursPublicKey), `${bits}-bit node public key`);
  assert.equal(toHex(liSignature), toHex(oursSignature), `${bits}-bit li signature`);
  assert.equal(toHex(normalizeNodeSignature(nodeSignature)), toHex(oursSignature), `${bits}-bit node signature`);
  return {
    ours: {
      sign: () => signDigestWithK(privateKey, digest, nonce),
      verify: () => verifyDigest(privateKey.publicKey, digest, oursSignatureValue),
    },
    li: {
      sign: () => li.sign(liPrivateKey, liDigest, { rand: liNonce }),
      verify: () => li.verify(liPublicKey, liDigest, liSignature),
    },
    node: {
      sign: () => nodeSigner.sign(nodeKeyPair.privateKey, message),
      verify: () => nodeSigner.verify(nodeKeyPair.publicKey, nodeSignature, message),
    },
  };
}

const nodeHash256 = nodeDigest(256), nodeHash512 = nodeDigest(512);
const nodeKuz = nodeKuznyechik(), nodeMag = nodeMagma();
const ourKuz = new KuznyechikCipher(kuzKey), ourMag = new MagmaCipher(magmaKey);
const liKuz = new LiKuznyechik(kuzKey), liMag = new LiMagma(magmaKey);
const signatures256 = createSignatureAdapters(32), signatures512 = createSignatureAdapters(64);
const implementations = [
  {
    name: "js-gostcrypto",
    hash256: () => streebog256(hashInput), hash512: () => streebog512(hashInput),
    kuzBlock: () => ourKuz.encryptBlock(kuzPlaintext),
    magmaBlock: () => ourMag.encryptBlock(magmaPlaintext),
    kuzSetup: () => new KuznyechikCipher(kuzKey),
    sign256: signatures256.ours.sign, verify256: signatures256.ours.verify,
    sign512: signatures512.ours.sign, verify512: signatures512.ours.verify,
  },
  {
    name: "@li0ard/gost 0.2.4",
    hash256: () => liStreebog256(hashInput), hash512: () => liStreebog512(hashInput),
    kuzBlock: () => liKuz.encrypt(kuzPlaintext),
    magmaBlock: () => liMag.encrypt(magmaPlaintext),
    kuzSetup: () => new LiKuznyechik(kuzKey),
    sign256: signatures256.li.sign, verify256: signatures256.li.verify,
    sign512: signatures512.li.sign, verify512: signatures512.li.verify,
  },
  {
    name: "node-gost-crypto 1.0.2",
    hash256: () => new Uint8Array(nodeHash256.digest(hashInput)), hash512: () => new Uint8Array(nodeHash512.digest(hashInput)),
    kuzBlock: () => new Uint8Array(nodeKuz.encrypt(kuzKey, kuzPlaintext)),
    magmaBlock: () => new Uint8Array(nodeMag.encrypt(magmaKey, magmaPlaintext)),
    kuzSetup: () => nodeKuznyechik().encrypt(kuzKey, kuzPlaintext),
    sign256: signatures256.node.sign, verify256: signatures256.node.verify,
    sign512: signatures512.node.sign, verify512: signatures512.node.verify,
  },
];

for (const implementation of implementations) {
  assert.equal(toHex(implementation.hash256()), toHex(streebog256(hashInput)));
  assert.equal(toHex(implementation.hash512()), toHex(streebog512(hashInput)));
  assert.equal(toHex(implementation.kuzBlock()), "7f679d90bebc24305a468d42b9d4edcd");
  assert.equal(toHex(implementation.magmaBlock()), "4ee901e5c2d8ca3d");
  assert.equal(implementation.verify256(), true, `${implementation.name}: verify 256`);
  assert.equal(implementation.verify512(), true, `${implementation.name}: verify 512`);
}

const operations = [
  { name: "Streebog-256, 8 KiB", method: "hash256", iterations: 4, bytes: hashInput.length },
  { name: "Streebog-512, 8 KiB", method: "hash512", iterations: 4, bytes: hashInput.length },
  { name: "Kuznyechik, one block", method: "kuzBlock", iterations: 2_000 },
  { name: "Magma, one block", method: "magmaBlock", iterations: 10_000 },
  { name: "Kuznyechik key setup", method: "kuzSetup", iterations: 2_000 },
  { name: "Sign, 256 bit", method: "sign256", iterations: 20 },
  { name: "Verify, 256 bit", method: "verify256", iterations: 10 },
  { name: "Sign, 512 bit", method: "sign512", iterations: 5 },
  { name: "Verify, 512 bit", method: "verify512", iterations: 3 },
];

const rows = [];
for (const operation of operations) {
  const row = { operation: operation.name };
  for (const implementation of implementations) {
    const milliseconds = measure(implementation[operation.method], operation.iterations);
    row[implementation.name] = operation.bytes === undefined ? formatDuration(milliseconds) : formatThroughput(operation.bytes, milliseconds);
  }
  rows.push(row);
}

console.log(`Node.js ${process.version}; ${process.platform} ${process.arch}; ${os.cpus()[0]?.model ?? "unknown CPU"}; median of ${samples} samples`);
console.log("Hashes, cipher blocks, public keys, and deterministic signatures were cross-checked before measurement.");
console.log("node-gost-crypto signature timings include hashing a 32-byte message; its key-setup timing includes the first block.");
console.table(rows);
