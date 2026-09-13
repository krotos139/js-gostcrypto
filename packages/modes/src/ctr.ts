import type { BlockCipher, Bytes } from "@gostcrypto/core";

/** Streaming CTR mode from GOST R 34.13-2015, section 5.2. */
export class GostCtr {
  readonly #cipher: BlockCipher;
  readonly #segmentSize: number;
  readonly #counter: Bytes;
  #keyStream: Bytes;
  #position: number;

  /**
   * `iv` is exactly half a cipher block, as required by GOST R 34.13. `s`
   * controls the truncated keystream segment and defaults to a whole block.
   */
  public constructor(cipher: BlockCipher, iv: Bytes, s = cipher.blockSize) {
    if (cipher.blockSize % 2 !== 0) throw new RangeError("CTR requires an even block size");
    if (iv.length !== cipher.blockSize / 2) {
      throw new RangeError(`CTR IV must contain ${cipher.blockSize / 2} bytes; received ${iv.length}`);
    }
    if (!Number.isInteger(s) || s <= 0 || s > cipher.blockSize) {
      throw new RangeError(`CTR segment size must be between 1 and ${cipher.blockSize}; received ${s}`);
    }
    this.#cipher = cipher;
    this.#segmentSize = s;
    this.#counter = new Uint8Array(cipher.blockSize);
    this.#counter.set(iv);
    this.#keyStream = new Uint8Array(s);
    this.#position = s;
  }

  /** Encrypts or decrypts input. The mode is symmetric and preserves stream state. */
  public update(input: Bytes): Bytes {
    const output = new Uint8Array(input.length);
    let offset = 0;
    while (offset < input.length) {
      if (this.#position === this.#segmentSize) this.#nextKeyStream();
      const count = Math.min(this.#segmentSize - this.#position, input.length - offset);
      for (let index = 0; index < count; index += 1) {
        output[offset + index] = input[offset + index]! ^ this.#keyStream[this.#position + index]!;
      }
      offset += count;
      this.#position += count;
    }
    return output;
  }

  #nextKeyStream(): void {
    this.#keyStream = this.#cipher.encryptBlock(this.#counter).slice(0, this.#segmentSize);
    this.#position = 0;
    for (let index = this.#counter.length - 1; index >= 0; index -= 1) {
      this.#counter[index] = (this.#counter[index]! + 1) & 0xff;
      if (this.#counter[index] !== 0) break;
    }
  }
}
