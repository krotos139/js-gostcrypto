import { streebog256, streebog512 } from "@gostcrypto/hash";

type Hash = (input: Uint8Array) => Uint8Array;

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

function hmac(hash: Hash, key: Uint8Array, input: Uint8Array): Uint8Array {
  const blockSize = 64;
  let normalized = key.length > blockSize ? hash(key) : Uint8Array.from(key);
  normalized = concat(normalized, new Uint8Array(Math.max(0, blockSize - normalized.length)));
  const inner = new Uint8Array(blockSize);
  const outer = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i += 1) { inner[i] = normalized[i]! ^ 0x36; outer[i] = normalized[i]! ^ 0x5c; }
  return hash(concat(outer, hash(concat(inner, input))));
}

export const hmacStreebog256 = (key: Uint8Array, input: Uint8Array): Uint8Array => hmac(streebog256, key, input);
export const hmacStreebog512 = (key: Uint8Array, input: Uint8Array): Uint8Array => hmac(streebog512, key, input);

function uintBE(value: number, bytes: number): Uint8Array {
  const out = new Uint8Array(bytes);
  for (let i = bytes - 1; i >= 0; i -= 1) { out[i] = value & 0xff; value = Math.floor(value / 256); }
  return out;
}
function lengthBytes(bits: number): Uint8Array {
  const full = uintBE(bits, 8); let offset = 0;
  while (offset < 7 && full[offset] === 0) offset += 1;
  return full.slice(offset);
}

/** KDF_TREE_GOSTR3411_2012_256 (RFC 7836 section 4.5). */
export function deriveTree(key: Uint8Array, label: Uint8Array, seed: Uint8Array, counterBytes: number, lengthBits: number): Uint8Array {
  if (!Number.isInteger(counterBytes) || counterBytes < 1 || counterBytes > 4) throw new RangeError("KDF counter size must be 1..4 bytes");
  if (!Number.isInteger(lengthBits) || lengthBits <= 0 || lengthBits % 8 !== 0) throw new RangeError("KDF output length must be a positive multiple of 8 bits");
  const maxBits = 256 * (2 ** (8 * counterBytes) - 1);
  if (lengthBits > maxBits) throw new RangeError("KDF output length exceeds counter capacity");
  const output = new Uint8Array(lengthBits / 8); const suffix = concat(label, Uint8Array.of(0), seed, lengthBytes(lengthBits));
  for (let index = 1, offset = 0; offset < output.length; index += 1, offset += 32) output.set(hmacStreebog256(key, concat(uintBE(index, counterBytes), suffix)).subarray(0, Math.min(32, output.length - offset)), offset);
  return output;
}

/** KDF_GOSTR3411_2012_256, the fixed 256-bit special case. */
export const derive = (key: Uint8Array, label: Uint8Array, seed: Uint8Array): Uint8Array => deriveTree(key, label, seed, 1, 256);

function pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number, length: number, prf: (key: Uint8Array, input: Uint8Array) => Uint8Array): Uint8Array {
  if (!Number.isInteger(iterations) || iterations <= 0) throw new RangeError("PBKDF2 iterations must be positive");
  if (!Number.isInteger(length) || length < 0) throw new RangeError("PBKDF2 length must be non-negative");
  const hLen = prf(password, new Uint8Array()).length;
  const output = new Uint8Array(length);
  for (let block = 1, offset = 0; offset < length; block += 1, offset += hLen) {
    let u = prf(password, concat(salt, uintBE(block, 4)));
    const t = Uint8Array.from(u);
    for (let round = 1; round < iterations; round += 1) {
      u = prf(password, u);
      for (let index = 0; index < hLen; index += 1) t[index] = t[index]! ^ u[index]!;
    }
    output.set(t.subarray(0, Math.min(hLen, length - offset)), offset);
  }
  return output;
}

/** PBKDF2 using HMAC_GOSTR3411_2012_512, required by R 50.1.111-2016. */
export const pbkdf2Streebog512 = (password: Uint8Array, salt: Uint8Array, iterations: number, length: number): Uint8Array => pbkdf2(password, salt, iterations, length, hmacStreebog512);

/** Compatibility variant of PBKDF2 using HMAC_GOSTR3411_2012_256. */
export const pbkdf2Streebog256 = (password: Uint8Array, salt: Uint8Array, iterations: number, length: number): Uint8Array => pbkdf2(password, salt, iterations, length, hmacStreebog256);
