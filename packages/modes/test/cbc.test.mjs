import assert from "node:assert/strict";
import test from "node:test";
import { KuznyechikCipher, MagmaCipher } from "@gostcrypto/ciphers";
import { createCbcDecryptor, createCbcEncryptor } from "@gostcrypto/modes";

function hex(value) {
  return Uint8Array.from(value.match(/../g).map((pair) => Number.parseInt(pair, 16)));
}

const vectors = [
  {
    name: "Kuznyechik",
    cipher: new KuznyechikCipher(hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
    iv: "1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819",
    plaintext: "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
    ciphertext: "689972d4a085fa4d90e52e3d6d7dcc272826e661b478eca6af1e8e448d5ea5acfe7babf1e91999e85640e8b0f49d90d0167688065a895c631a2d9a1560b63970",
  },
  {
    name: "Magma",
    cipher: new MagmaCipher(hex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")),
    iv: "1234567890abcdef234567890abcdef134567890abcdef12",
    plaintext: "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41",
    ciphertext: "96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667",
  },
];

for (const vector of vectors) {
  test(`GOST R 34.13 CBC vector: ${vector.name}`, () => {
    const plaintext = hex(vector.plaintext);
    const ciphertext = hex(vector.ciphertext);
    assert.deepEqual(createCbcEncryptor(vector.cipher, hex(vector.iv)).update(plaintext), ciphertext);
    assert.deepEqual(createCbcDecryptor(vector.cipher, hex(vector.iv)).update(ciphertext), plaintext);
  });
}

test("CBC preserves state between caller chunks", () => {
  const vector = vectors[0];
  const plaintext = hex(vector.plaintext);
  const cbc = createCbcEncryptor(vector.cipher, hex(vector.iv));
  const output = Uint8Array.from([...cbc.update(plaintext.subarray(0, 16)), ...cbc.update(plaintext.subarray(16))]);
  assert.deepEqual(output, hex(vector.ciphertext));
});
