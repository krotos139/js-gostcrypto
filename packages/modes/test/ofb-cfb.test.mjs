import assert from "node:assert/strict";
import test from "node:test";
import { KuznyechikCipher, MagmaCipher } from "@gostcrypto/ciphers";
import { createCfbDecryptor, createCfbEncryptor, GostOfb } from "@gostcrypto/modes";

function hex(value) {
  return Uint8Array.from(value.match(/../g).map((pair) => Number.parseInt(pair, 16)));
}

const kuznyechik = new KuznyechikCipher(hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"));
const magma = new MagmaCipher(hex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));

const vectors = [
  { name: "Kuznyechik", cipher: kuznyechik, iv: "1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819", plain: "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011", ofb: "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf66a257ac3ca0b8b1c80fe7fc10288a13203ebbc066138660a0292243f6903150", cfb: "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1" },
  { name: "Magma", cipher: magma, iv: "1234567890abcdef234567890abcdef1", plain: "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", ofb: "db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bd4fdb05", cfb: "db37e0e266903c830d46644c1f9a089c24bdd2035315d38bbcc0321421075505" },
];

for (const vector of vectors) {
  test(`GOST R 34.13 OFB vector: ${vector.name}`, () => {
    assert.deepEqual(new GostOfb(vector.cipher, hex(vector.iv)).update(hex(vector.plain)), hex(vector.ofb));
    assert.deepEqual(new GostOfb(vector.cipher, hex(vector.iv)).update(hex(vector.ofb)), hex(vector.plain));
  });
  test(`GOST R 34.13 CFB vector: ${vector.name}`, () => {
    assert.deepEqual(createCfbEncryptor(vector.cipher, hex(vector.iv)).update(hex(vector.plain)), hex(vector.cfb));
    assert.deepEqual(createCfbDecryptor(vector.cipher, hex(vector.iv)).update(hex(vector.cfb)), hex(vector.plain));
  });
}

test("OFB and CFB preserve caller chunking", () => {
  const vector = vectors[0];
  const input = hex(vector.plain);
  const ofb = new GostOfb(vector.cipher, hex(vector.iv));
  assert.deepEqual(Uint8Array.from([...ofb.update(input.subarray(0, 3)), ...ofb.update(input.subarray(3))]), hex(vector.ofb));
  const cfb = createCfbEncryptor(vector.cipher, hex(vector.iv));
  assert.deepEqual(Uint8Array.from([...cfb.update(input.subarray(0, 17)), ...cfb.update(input.subarray(17))]), hex(vector.cfb));
});
