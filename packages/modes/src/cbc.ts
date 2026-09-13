import type { BlockCipher, Bytes } from "@gostcrypto/core";

function xorBlock(left: Bytes, right: Bytes): Bytes {
  const output = new Uint8Array(left.length);
  for (let index = 0; index < output.length; index += 1) output[index] = left[index]! ^ right[index]!;
  return output;
}

/** Stateful GOST R 34.13-2015 CBC transform with a register of one or more blocks. */
export class GostCbc {
  readonly #cipher: BlockCipher;
  readonly #decrypt: boolean;
  #register: Bytes;

  public constructor(cipher: BlockCipher, iv: Bytes, decrypt = false) {
    if (iv.length === 0 || iv.length % cipher.blockSize !== 0) {
      throw new RangeError(`CBC IV must contain a positive multiple of ${cipher.blockSize} bytes; received ${iv.length}`);
    }
    this.#cipher = cipher;
    this.#decrypt = decrypt;
    this.#register = Uint8Array.from(iv);
  }

  public update(input: Bytes): Bytes {
    const blockSize = this.#cipher.blockSize;
    if (input.length % blockSize !== 0) {
      throw new RangeError(`CBC input length must be a multiple of ${blockSize}; received ${input.length}`);
    }
    const output = new Uint8Array(input.length);
    for (let offset = 0; offset < input.length; offset += blockSize) {
      const source = input.subarray(offset, offset + blockSize);
      const result = this.#decrypt
        ? xorBlock(this.#cipher.decryptBlock(source), this.#register.subarray(0, blockSize))
        : this.#cipher.encryptBlock(xorBlock(source, this.#register.subarray(0, blockSize)));
      output.set(result, offset);
      this.#shift(this.#decrypt ? source : result);
    }
    return output;
  }

  #shift(ciphertext: Bytes): void {
    const blockSize = this.#cipher.blockSize;
    this.#register.copyWithin(0, blockSize);
    this.#register.set(ciphertext, this.#register.length - blockSize);
  }
}

export function createCbcEncryptor(cipher: BlockCipher, iv: Bytes): GostCbc {
  return new GostCbc(cipher, iv, false);
}

export function createCbcDecryptor(cipher: BlockCipher, iv: Bytes): GostCbc {
  return new GostCbc(cipher, iv, true);
}
