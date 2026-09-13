import type { BlockCipher, Bytes } from "@gostcrypto/core";

/** ГОСТ Р 34.12-2015, section 4 (also RFC 7801). */
export const KUZNYECHIK_BLOCK_SIZE = 16;
export const KUZNYECHIK_KEY_SIZE = 32;

const PI = Uint8Array.from([
  252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
  233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
  249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
  5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
  235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
  181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
  21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
  50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
  223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
  224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
  167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
  173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
  7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
  225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
  32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
  89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
]);

const PI_INV = (() => {
  const inverse = new Uint8Array(256);
  for (let index = 0; index < PI.length; index += 1) inverse[PI[index]!] = index;
  return inverse;
})();

// Formula (1) from GOST R 34.12-2015. This deliberately uses the corrected
// coefficient for a_14, rather than the typo in RFC 7801 section 4.2.
const KAPPA = Uint8Array.from([148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]);

function xor(left: Bytes, right: Bytes): Bytes {
  const output = new Uint8Array(KUZNYECHIK_BLOCK_SIZE);
  for (let index = 0; index < output.length; index += 1) output[index] = left[index]! ^ right[index]!;
  return output;
}

function multiply(a: number, b: number): number {
  let product = 0;
  let left = a;
  let right = b;
  for (let index = 0; index < 8; index += 1) {
    if ((right & 1) !== 0) product ^= left;
    const highBit = left & 0x80;
    left = (left << 1) & 0xff;
    if (highBit !== 0) left ^= 0xc3;
    right >>>= 1;
  }
  return product;
}

// As in go-gostcrypto, field multiplication is performed only while this
// lookup table is initialized. R and R^-1 use one indexed byte load per
// coefficient instead of running the eight-step GF loop.
const MULTIPLICATION_TABLE = (() => {
  const table = new Uint8Array(KUZNYECHIK_BLOCK_SIZE * 256);
  for (let position = 0; position < KUZNYECHIK_BLOCK_SIZE; position += 1) {
    const offset = position * 256;
    for (let value = 0; value < 256; value += 1) table[offset + value] = multiply(KAPPA[position]!, value);
  }
  return table;
})();

function linearValue(block: Bytes): number {
  let value = 0;
  for (let index = 0; index < KUZNYECHIK_BLOCK_SIZE; index += 1) {
    value ^= MULTIPLICATION_TABLE[index * 256 + block[index]!]!;
  }
  return value;
}

function rTransform(block: Bytes): void {
  const first = linearValue(block);
  block.copyWithin(1, 0, KUZNYECHIK_BLOCK_SIZE - 1);
  block[0] = first;
}

function rInverse(block: Bytes): void {
  let last = MULTIPLICATION_TABLE[(KUZNYECHIK_BLOCK_SIZE - 1) * 256 + block[0]!]!;
  for (let index = 0; index < KUZNYECHIK_BLOCK_SIZE - 1; index += 1) {
    last ^= MULTIPLICATION_TABLE[index * 256 + block[index + 1]!]!;
  }
  block.copyWithin(0, 1);
  block[KUZNYECHIK_BLOCK_SIZE - 1] = last;
}

function lTransform(block: Bytes): Bytes {
  const output: Bytes = Uint8Array.from(block);
  for (let index = 0; index < KUZNYECHIK_BLOCK_SIZE; index += 1) rTransform(output);
  return output;
}

function lInverse(block: Bytes): Bytes {
  const output: Bytes = Uint8Array.from(block);
  for (let index = 0; index < KUZNYECHIK_BLOCK_SIZE; index += 1) rInverse(output);
  return output;
}

function tableWords(transform: (block: Bytes) => Bytes, substitution?: Bytes): Uint32Array {
  const table = new Uint32Array(KUZNYECHIK_BLOCK_SIZE * 256 * 4);
  for (let position = 0; position < KUZNYECHIK_BLOCK_SIZE; position += 1) {
    const basis: Bytes[] = [];
    for (let bit = 0; bit < 8; bit += 1) {
      const input = new Uint8Array(KUZNYECHIK_BLOCK_SIZE);
      input[position] = 1 << bit;
      basis.push(transform(input));
    }
    for (let value = 0; value < 256; value += 1) {
      const output = new Uint8Array(KUZNYECHIK_BLOCK_SIZE), substituted = substitution?.[value] ?? value;
      for (let bit = 0; bit < 8; bit += 1) if ((substituted & (1 << bit)) !== 0) {
        const contribution = basis[bit]!;
        for (let byte = 0; byte < output.length; byte += 1) output[byte] = output[byte]! ^ contribution[byte]!;
      }
      const offset = (position * 256 + value) * 4;
      for (let word = 0; word < 4; word += 1) {
        const byte = word * 4;
        table[offset + word] = (output[byte]! << 24 | output[byte + 1]! << 16 | output[byte + 2]! << 8 | output[byte + 3]!) >>> 0;
      }
    }
  }
  return table;
}

// The Go/gamma multiplication loops are used only once to construct these
// fused tables. Hot encryption and decryption rounds then operate on 32-bit
// words, following the same table-fusion strategy as the Go implementation.
const LSX_TABLE = tableWords(lTransform, PI);
const DECRYPT_TABLE = tableWords(lInverse, PI_INV);

// C_i = L(Vec_128(i)) is independent of the user key. Computing these values
// once avoids repeating 512 R transformations for every cipher instance.
const ITERATION_CONSTANTS: readonly Bytes[] = Array.from({ length: 32 }, (_, index) => {
  const vector = new Uint8Array(KUZNYECHIK_BLOCK_SIZE);
  vector[KUZNYECHIK_BLOCK_SIZE - 1] = index + 1;
  return lTransform(vector);
});

function applyTableInto(output: Bytes, input: Bytes, table: Uint32Array, key?: Bytes): void {
  let first = 0, second = 0, third = 0, fourth = 0;
  for (let position = 0; position < KUZNYECHIK_BLOCK_SIZE; position += 1) {
    const value = input[position]! ^ (key?.[position] ?? 0), offset = (position * 256 + value) * 4;
    first ^= table[offset]!; second ^= table[offset + 1]!; third ^= table[offset + 2]!; fourth ^= table[offset + 3]!;
  }
  output[0] = first >>> 24; output[1] = first >>> 16; output[2] = first >>> 8; output[3] = first;
  output[4] = second >>> 24; output[5] = second >>> 16; output[6] = second >>> 8; output[7] = second;
  output[8] = third >>> 24; output[9] = third >>> 16; output[10] = third >>> 8; output[11] = third;
  output[12] = fourth >>> 24; output[13] = fourth >>> 16; output[14] = fourth >>> 8; output[15] = fourth;
}

function applyInverseLinear(input: Bytes): Bytes {
  const output = new Uint8Array(KUZNYECHIK_BLOCK_SIZE);
  let first = 0, second = 0, third = 0, fourth = 0;
  // DECRYPT_TABLE contains L^-1(S^-1(x)). Indexing it with S(input)
  // cancels the substitution and leaves a pure L^-1 transform.
  for (let position = 0; position < KUZNYECHIK_BLOCK_SIZE; position += 1) {
    const offset = (position * 256 + PI[input[position]!]!) * 4;
    first ^= DECRYPT_TABLE[offset]!; second ^= DECRYPT_TABLE[offset + 1]!;
    third ^= DECRYPT_TABLE[offset + 2]!; fourth ^= DECRYPT_TABLE[offset + 3]!;
  }
  output[0] = first >>> 24; output[1] = first >>> 16; output[2] = first >>> 8; output[3] = first;
  output[4] = second >>> 24; output[5] = second >>> 16; output[6] = second >>> 8; output[7] = second;
  output[8] = third >>> 24; output[9] = third >>> 16; output[10] = third >>> 8; output[11] = third;
  output[12] = fourth >>> 24; output[13] = fourth >>> 16; output[14] = fourth >>> 8; output[15] = fourth;
  return output;
}

function substitute(block: Bytes, table: Bytes): Bytes {
  const output = new Uint8Array(KUZNYECHIK_BLOCK_SIZE);
  for (let index = 0; index < output.length; index += 1) output[index] = table[block[index]!]!;
  return output;
}

/**
 * A 128-bit Kuznyechik block cipher with fused LSX tables for hot rounds.
 */
export class KuznyechikCipher implements BlockCipher {
  public readonly blockSize = KUZNYECHIK_BLOCK_SIZE;
  readonly #roundKeys: readonly Bytes[];
  readonly #decryptKeys: readonly Bytes[];

  public constructor(key: Bytes) {
    if (key.length !== KUZNYECHIK_KEY_SIZE) {
      throw new RangeError(`kuznyechik key must contain ${KUZNYECHIK_KEY_SIZE} bytes; received ${key.length}`);
    }
    this.#roundKeys = this.#expandKey(key);
    this.#decryptKeys = Array.from({ length: 8 }, (_, index) => applyInverseLinear(this.#roundKeys[8 - index]!));
  }

  public encryptBlock(block: Bytes): Bytes {
    this.#assertBlock(block);
    let state: Bytes = Uint8Array.from(block), next: Bytes = new Uint8Array(KUZNYECHIK_BLOCK_SIZE);
    for (let round = 0; round < 9; round += 1) { applyTableInto(next,state,LSX_TABLE,this.#roundKeys[round]!);[state,next]=[next,state]; }
    return xor(state, this.#roundKeys[9]!);
  }

  public decryptBlock(block: Bytes): Bytes {
    this.#assertBlock(block);
    let state = xor(block, this.#roundKeys[9]!);
    // Rewrite the inverse rounds in terms of u=L^-1(t), exactly as the Go
    // implementation does. The middle rounds then use one fused L^-1 S^-1
    // lookup and keys pre-transformed by L^-1.
    state = applyInverseLinear(state);
    let next: Bytes = new Uint8Array(KUZNYECHIK_BLOCK_SIZE);
    for (let round = 0; round < 8; round += 1) {applyTableInto(next,state,DECRYPT_TABLE);for(let byte=0;byte<next.length;byte+=1)next[byte]=next[byte]!^this.#decryptKeys[round]![byte]!;[state,next]=[next,state];}
    return xor(substitute(state, PI_INV), this.#roundKeys[0]!);
  }

  #assertBlock(block: Bytes): void {
    if (block.length !== KUZNYECHIK_BLOCK_SIZE) {
      throw new RangeError(`kuznyechik block must contain ${KUZNYECHIK_BLOCK_SIZE} bytes; received ${block.length}`);
    }
  }

  #expandKey(key: Bytes): readonly Bytes[] {
    const keys: Bytes[] = [Uint8Array.from(key.subarray(0, 16)), Uint8Array.from(key.subarray(16, 32))];
    let left: Bytes = Uint8Array.from(keys[0]!);
    let right: Bytes = Uint8Array.from(keys[1]!);
    let next: Bytes = new Uint8Array(KUZNYECHIK_BLOCK_SIZE);
    for (let group = 0; group < 4; group += 1) {
      for (let round = 1; round <= 8; round += 1) {
        applyTableInto(next, left, LSX_TABLE, ITERATION_CONSTANTS[group * 8 + round - 1]!);
        for (let byte = 0; byte < KUZNYECHIK_BLOCK_SIZE; byte += 1) next[byte] = next[byte]! ^ right[byte]!;
        const scratch = right;
        right = left;
        left = next;
        next = scratch;
      }
      keys.push(Uint8Array.from(left), Uint8Array.from(right));
    }
    return keys;
  }
}
