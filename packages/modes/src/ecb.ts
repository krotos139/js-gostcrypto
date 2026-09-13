import type { BlockCipher, Bytes } from "@gostcrypto/core";

function transform(cipher: BlockCipher, input: Bytes, operation: (block: Bytes) => Bytes): Bytes {
  if (input.length % cipher.blockSize !== 0) {
    throw new RangeError(`ECB input length must be a multiple of ${cipher.blockSize}; received ${input.length}`);
  }
  const output = new Uint8Array(input.length);
  for (let offset = 0; offset < input.length; offset += cipher.blockSize) {
    output.set(operation(input.subarray(offset, offset + cipher.blockSize)), offset);
  }
  return output;
}

/** GOST R 34.13-2015 ECB encryption. Apply an explicit padding procedure first when needed. */
export function ecbEncrypt(cipher: BlockCipher, input: Bytes): Bytes {
  return transform(cipher, input, (block) => cipher.encryptBlock(block));
}

/** GOST R 34.13-2015 ECB decryption. */
export function ecbDecrypt(cipher: BlockCipher, input: Bytes): Bytes {
  return transform(cipher, input, (block) => cipher.decryptBlock(block));
}
