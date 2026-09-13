import type { BlockCipher, Bytes } from "@gostcrypto/core";

/** Stateful output-feedback mode from GOST R 34.13-2015, section 5.3. */
export class GostOfb {
  readonly #cipher: BlockCipher;
  readonly #segmentSize: number;
  #register: Bytes;
  #keyStream: Bytes;
  #position: number;

  public constructor(cipher: BlockCipher, iv: Bytes, s = cipher.blockSize) {
    if (iv.length === 0 || iv.length % cipher.blockSize !== 0) {
      throw new RangeError(`OFB IV must contain a positive multiple of ${cipher.blockSize} bytes; received ${iv.length}`);
    }
    if (!Number.isInteger(s) || s <= 0 || s > cipher.blockSize) {
      throw new RangeError(`OFB segment size must be between 1 and ${cipher.blockSize}; received ${s}`);
    }
    this.#cipher = cipher;
    this.#segmentSize = s;
    this.#register = Uint8Array.from(iv);
    this.#keyStream = new Uint8Array(s);
    this.#position = s;
  }

  /** Encrypts or decrypts input while retaining state across update calls. */
  public update(input: Bytes): Bytes {
    const output = new Uint8Array(input.length);
    let offset = 0;
    while (offset < input.length) {
      if (this.#position === this.#segmentSize) this.#next();
      const count = Math.min(this.#segmentSize - this.#position, input.length - offset);
      for (let index = 0; index < count; index += 1) {
        output[offset + index] = input[offset + index]! ^ this.#keyStream[this.#position + index]!;
      }
      offset += count;
      this.#position += count;
    }
    return output;
  }

  #next(): void {
    const encrypted = this.#cipher.encryptBlock(this.#register.subarray(0, this.#cipher.blockSize));
    this.#keyStream = encrypted.slice(0, this.#segmentSize);
    this.#position = 0;
    this.#register.copyWithin(0, this.#cipher.blockSize);
    this.#register.set(encrypted, this.#register.length - this.#cipher.blockSize);
  }
}
