import type { BlockCipher, Bytes } from "@gostcrypto/core";

/** Stateful ciphertext-feedback mode from GOST R 34.13-2015, section 5.5. */
export class GostCfb {
  readonly #cipher: BlockCipher;
  readonly #decrypt: boolean;
  readonly #segmentSize: number;
  #register: Bytes;
  #keyStream: Bytes;
  #feedback: Bytes;
  #position = 0;

  public constructor(cipher: BlockCipher, iv: Bytes, decrypt = false, s = cipher.blockSize) {
    if (iv.length < cipher.blockSize) {
      throw new RangeError(`CFB IV must contain at least ${cipher.blockSize} bytes; received ${iv.length}`);
    }
    if (!Number.isInteger(s) || s <= 0 || s > cipher.blockSize || s > iv.length) {
      throw new RangeError(`CFB segment size is invalid: ${s}`);
    }
    this.#cipher = cipher;
    this.#decrypt = decrypt;
    this.#segmentSize = s;
    this.#register = Uint8Array.from(iv);
    this.#keyStream = new Uint8Array(s);
    this.#feedback = new Uint8Array(s);
  }

  public update(input: Bytes): Bytes {
    const output = new Uint8Array(input.length);
    let offset = 0;
    while (offset < input.length) {
      if (this.#position === 0) this.#keyStream = this.#cipher.encryptBlock(this.#register.subarray(0, this.#cipher.blockSize)).slice(0, this.#segmentSize);
      const count = Math.min(this.#segmentSize - this.#position, input.length - offset);
      for (let index = 0; index < count; index += 1) {
        const position = this.#position + index;
        const value = input[offset + index]! ^ this.#keyStream[position]!;
        output[offset + index] = value;
        this.#feedback[position] = this.#decrypt ? input[offset + index]! : value;
      }
      offset += count;
      this.#position += count;
      if (this.#position === this.#segmentSize) {
        this.#register.copyWithin(0, this.#segmentSize);
        this.#register.set(this.#feedback, this.#register.length - this.#segmentSize);
        this.#position = 0;
      }
    }
    return output;
  }
}

export function createCfbEncryptor(cipher: BlockCipher, iv: Bytes, s = cipher.blockSize): GostCfb {
  return new GostCfb(cipher, iv, false, s);
}

export function createCfbDecryptor(cipher: BlockCipher, iv: Bytes, s = cipher.blockSize): GostCfb {
  return new GostCfb(cipher, iv, true, s);
}
