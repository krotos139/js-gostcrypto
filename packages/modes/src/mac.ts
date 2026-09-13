import type { BlockCipher, Bytes } from "@gostcrypto/core";

function xor(left: Bytes, right: Bytes): Bytes {
  const output = new Uint8Array(left.length);
  for (let index = 0; index < output.length; index += 1) output[index] = left[index]! ^ right[index]!;
  return output;
}

function shiftLeftOne(input: Bytes): { value: Bytes; carry: number } {
  const output = new Uint8Array(input.length);
  for (let index = 0; index < input.length - 1; index += 1) {
    output[index] = (input[index]! << 1) | (input[index + 1]! >>> 7);
  }
  output[input.length - 1] = input[input.length - 1]! << 1;
  return { value: output, carry: input[0]! >>> 7 };
}

function deriveSubkeys(cipher: BlockCipher): { k1: Bytes; k2: Bytes } {
  const constant = cipher.blockSize === 8 ? 0x1b : cipher.blockSize === 16 ? 0x87 : undefined;
  if (constant === undefined) throw new RangeError(`OMAC1 supports 8- and 16-byte blocks; received ${cipher.blockSize}`);
  const encryptedZero = cipher.encryptBlock(new Uint8Array(cipher.blockSize));
  const first = shiftLeftOne(encryptedZero);
  if (first.carry !== 0) {
    const index = first.value.length - 1;
    first.value[index] = first.value[index]! ^ constant;
  }
  const second = shiftLeftOne(first.value);
  if (second.carry !== 0) {
    const index = second.value.length - 1;
    second.value[index] = second.value[index]! ^ constant;
  }
  return { k1: first.value, k2: second.value };
}

/** Streaming OMAC1/CMAC from GOST R 34.13-2015, section 5.6. */
export class GostMac {
  readonly #cipher: BlockCipher;
  readonly #tagSize: number;
  readonly #k1: Bytes;
  readonly #k2: Bytes;
  #chain: Bytes;
  #buffer: Bytes;
  #buffered = 0;
  #total = 0;

  public constructor(cipher: BlockCipher, tagSize = cipher.blockSize) {
    if (!Number.isInteger(tagSize) || tagSize <= 0 || tagSize > cipher.blockSize) {
      throw new RangeError(`MAC tag size must be between 1 and ${cipher.blockSize}; received ${tagSize}`);
    }
    this.#cipher = cipher;
    this.#tagSize = tagSize;
    const subkeys = deriveSubkeys(cipher);
    this.#k1 = subkeys.k1;
    this.#k2 = subkeys.k2;
    this.#chain = new Uint8Array(cipher.blockSize);
    this.#buffer = new Uint8Array(cipher.blockSize);
  }

  public reset(): this {
    this.#chain.fill(0);
    this.#buffer.fill(0);
    this.#buffered = 0;
    this.#total = 0;
    return this;
  }

  public update(input: Bytes): this {
    this.#total += input.length;
    let offset = 0;
    while (offset < input.length) {
      if (this.#buffered === this.#buffer.length) this.#processBuffered();
      const count = Math.min(this.#buffer.length - this.#buffered, input.length - offset);
      this.#buffer.set(input.subarray(offset, offset + count), this.#buffered);
      this.#buffered += count;
      offset += count;
    }
    return this;
  }

  /** Returns a tag without mutating the ongoing state. */
  public digest(): Bytes {
    const last = new Uint8Array(this.#buffer.length);
    last.set(this.#buffer.subarray(0, this.#buffered));
    const subkey = this.#total > 0 && this.#buffered === this.#buffer.length ? this.#k1 : this.#k2;
    if (subkey === this.#k2) last[this.#buffered] = 0x80;
    return this.#cipher.encryptBlock(xor(xor(this.#chain, last), subkey)).slice(0, this.#tagSize);
  }

  #processBuffered(): void {
    this.#chain = this.#cipher.encryptBlock(xor(this.#chain, this.#buffer));
    this.#buffered = 0;
  }
}
