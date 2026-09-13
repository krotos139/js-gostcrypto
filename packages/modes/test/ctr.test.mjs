import assert from "node:assert/strict";
import test from "node:test";
import { KuznyechikCipher, MagmaCipher } from "@gostcrypto/ciphers";
import { GostCtr } from "@gostcrypto/modes";

function hex(hexString) {
  return Uint8Array.from(hexString.match(/../g).map((part) => Number.parseInt(part, 16)));
}

const vectors = [
  {
    name: "Kuznyechik",
    cipher: new KuznyechikCipher(hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
    iv: "1234567890abcef0",
    plain: "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
    encrypted: "f195d8bec10ed1dbd57b5fa240bda1b885eee733f6a13e5df33ce4b33c45dee4a5eae88be6356ed3d5e877f13564a3a5cb91fab1f20cbab6d1c6d15820bdba73",
  },
  {
    name: "Magma",
    cipher: new MagmaCipher(hex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")),
    iv: "12345678",
    plain: "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41",
    encrypted: "4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d",
  },
];

for (const vector of vectors) {
  test(`GOST R 34.13 CTR vector: ${vector.name}`, () => {
    const plaintext = hex(vector.plain);
    const ciphertext = hex(vector.encrypted);
    assert.deepEqual(new GostCtr(vector.cipher, hex(vector.iv)).update(plaintext), ciphertext);
    assert.deepEqual(new GostCtr(vector.cipher, hex(vector.iv)).update(ciphertext), plaintext);
  });
}

test("CTR state is independent of caller chunking", () => {
  const vector = vectors[0];
  const input = hex(vector.plain);
  const stream = new GostCtr(vector.cipher, hex(vector.iv));
  const pieces = [stream.update(input.subarray(0, 1)), stream.update(input.subarray(1, 29)), stream.update(input.subarray(29))];
  const output = Uint8Array.from(pieces.flatMap((piece) => [...piece]));
  assert.deepEqual(output, hex(vector.encrypted));
});
