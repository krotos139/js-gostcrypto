import assert from "node:assert/strict";
import test from "node:test";
import { KuznyechikCipher, MagmaCipher } from "@gostcrypto/ciphers";
import { GostMac } from "@gostcrypto/modes";

function hex(value) {
  return Uint8Array.from(value.match(/../g).map((pair) => Number.parseInt(pair, 16)));
}

const vectors = [
  { name: "Kuznyechik", cipher: new KuznyechikCipher(hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")), tagSize: 8, plain: "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011", tag: "336f4d296059fbe3" },
  { name: "Magma", cipher: new MagmaCipher(hex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")), tagSize: 4, plain: "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", tag: "154e7210" },
];

for (const vector of vectors) {
  test(`GOST R 34.13 OMAC1 vector: ${vector.name}`, () => {
    assert.deepEqual(new GostMac(vector.cipher, vector.tagSize).update(hex(vector.plain)).digest(), hex(vector.tag));
  });
  test(`GOST R 34.13 OMAC1 chunking: ${vector.name}`, () => {
    const input = hex(vector.plain);
    const mac = new GostMac(vector.cipher, vector.tagSize);
    for (const byte of input) mac.update(Uint8Array.of(byte));
    assert.deepEqual(mac.digest(), hex(vector.tag));
    assert.deepEqual(mac.digest(), hex(vector.tag));
  });
}

test("OMAC1 supports the empty message and rejects invalid tag sizes", () => {
  const cipher = new KuznyechikCipher(new Uint8Array(32));
  const mac = new GostMac(cipher);
  assert.equal(mac.digest().length, 16);
  assert.throws(() => new GostMac(cipher, 0), RangeError);
});
