import type { BlockCipher, Bytes } from "@gostcrypto/core";

/** ГОСТ Р 34.12-2015, section 5 (also RFC 8891). */
export const MAGMA_BLOCK_SIZE = 8;
export const MAGMA_KEY_SIZE = 32;

const S_BOX = [
  [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
  [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
  [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
  [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
  [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
  [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
  [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
  [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
] as const;

function readUint32BE(input: Bytes, offset: number): number {
  return (
    (input[offset]! << 24) |
    (input[offset + 1]! << 16) |
    (input[offset + 2]! << 8) |
    input[offset + 3]!
  ) >>> 0;
}

function writeUint32BE(output: Bytes, offset: number, value: number): void {
  output[offset] = value >>> 24;
  output[offset + 1] = value >>> 16;
  output[offset + 2] = value >>> 8;
  output[offset + 3] = value;
}

function rotateLeft32(value: number, count: number): number {
  return ((value << count) | (value >>> (32 - count))) >>> 0;
}

const G_TABLE = (() => {
  const table = new Uint32Array(4 * 256);
  for (let byte = 0; byte < 4; byte += 1) {
    for (let value = 0; value < 256; value += 1) {
      const substituted = S_BOX[byte * 2]![value & 0x0f]! | S_BOX[byte * 2 + 1]![value >>> 4]! << 4;
      table[byte * 256 + value] = rotateLeft32(substituted << (byte * 8), 11);
    }
  }
  return table;
})();

/** t(a), the fixed substitution used by Magma. Exported for conformance tests. */
export function magmaSubstitute(value: number): number {
  let output = 0;
  for (let index = 0; index < 8; index += 1) {
    const nibble = (value >>> (index * 4)) & 0x0f;
    output |= S_BOX[index]![nibble]! << (index * 4);
  }
  return output >>> 0;
}

/** g[k](a) = t(a + k mod 2^32) <<< 11. */
export function magmaRound(value: number, key: number): number {
  const sum = (value + key) >>> 0;
  return (G_TABLE[sum & 0xff]! ^ G_TABLE[256 + (sum >>> 8 & 0xff)]! ^ G_TABLE[512 + (sum >>> 16 & 0xff)]! ^ G_TABLE[768 + (sum >>> 24)]!) >>> 0;
}

/**
 * A 64-bit Magma block cipher. Inputs are copied, so `encryptBlock` and
 * `decryptBlock` support the equivalent of in-place use without aliasing.
 */
export class MagmaCipher implements BlockCipher {
  public readonly blockSize = MAGMA_BLOCK_SIZE;
  readonly #roundKeys: Uint32Array;

  public constructor(key: Bytes) {
    if (key.length !== MAGMA_KEY_SIZE) {
      throw new RangeError(`magma key must contain ${MAGMA_KEY_SIZE} bytes; received ${key.length}`);
    }
    const baseKeys = new Uint32Array(8);
    for (let index = 0; index < baseKeys.length; index += 1) {
      baseKeys[index] = readUint32BE(key, index * 4);
    }
    this.#roundKeys = new Uint32Array(32);
    for (let index = 0; index < 24; index += 1) this.#roundKeys[index] = baseKeys[index % 8]!;
    for (let index = 0; index < 8; index += 1) this.#roundKeys[24 + index] = baseKeys[7 - index]!;
  }

  public encryptBlock(block: Bytes): Bytes {
    return this.#crypt(block, 0, 1);
  }

  public decryptBlock(block: Bytes): Bytes {
    return this.#crypt(block, 31, -1);
  }

  #crypt(block: Bytes, firstKey: number, keyStep: 1 | -1): Bytes {
    if (block.length !== MAGMA_BLOCK_SIZE) {
      throw new RangeError(`magma block must contain ${MAGMA_BLOCK_SIZE} bytes; received ${block.length}`);
    }
    let left = readUint32BE(block, 0);
    let right = readUint32BE(block, 4);
    for (let round = 0; round < 31; round += 1) {
      const keyIndex = firstKey + round * keyStep;
      const previousRight = right;
      right = (left ^ magmaRound(right, this.#roundKeys[keyIndex]!)) >>> 0;
      left = previousRight;
    }
    const finalKeyIndex = firstKey + 31 * keyStep;
    left = (left ^ magmaRound(right, this.#roundKeys[finalKeyIndex]!)) >>> 0;
    const output = new Uint8Array(MAGMA_BLOCK_SIZE);
    writeUint32BE(output, 0, left);
    writeUint32BE(output, 4, right);
    return output;
  }
}
