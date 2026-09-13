import type { Bytes } from "@gostcrypto/core";

function assertBlockSize(blockSize: number): void {
  if (!Number.isInteger(blockSize) || blockSize <= 0) {
    throw new RangeError(`block size must be a positive integer; received ${blockSize}`);
  }
}

/** GOST R 34.13-2015 procedure 1: zero padding. Its original length is ambiguous. */
export function pad1(input: Bytes, blockSize: number): Bytes {
  assertBlockSize(blockSize);
  const remainder = input.length % blockSize;
  if (remainder === 0) return Uint8Array.from(input);
  const output = new Uint8Array(input.length + blockSize - remainder);
  output.set(input);
  return output;
}

/** GOST R 34.13-2015 procedure 2: 0x80 followed by zero bytes. */
export function pad2(input: Bytes, blockSize: number): Bytes {
  assertBlockSize(blockSize);
  const output = new Uint8Array(input.length + blockSize - (input.length % blockSize));
  output.set(input);
  output[input.length] = 0x80;
  return output;
}

/** GOST R 34.13-2015 procedure 3: procedure 2 only for an incomplete final block. */
export function pad3(input: Bytes, blockSize: number): Bytes {
  assertBlockSize(blockSize);
  return input.length > 0 && input.length % blockSize === 0 ? Uint8Array.from(input) : pad2(input, blockSize);
}

/** Removes procedure-2 padding and rejects malformed encodings. */
export function unpad2(input: Bytes): Bytes {
  let index = input.length - 1;
  while (index >= 0 && input[index] === 0) index -= 1;
  if (index < 0 || input[index] !== 0x80) throw new Error("invalid GOST procedure-2 padding");
  return Uint8Array.from(input.subarray(0, index));
}
