import assert from "node:assert/strict";
import test from "node:test";
import { KuznyechikCipher, MagmaCipher } from "@gostcrypto/ciphers";
import { ecbDecrypt, ecbEncrypt, pad1, pad2, pad3, unpad2 } from "@gostcrypto/modes";

function hex(value) {
  return Uint8Array.from(value.match(/../g).map((pair) => Number.parseInt(pair, 16)));
}

test("GOST padding procedures", () => {
  assert.deepEqual(pad1(hex("11"), 8), hex("1100000000000000"));
  assert.deepEqual(pad2(hex("11"), 8), hex("1180000000000000"));
  assert.deepEqual(pad2(new Uint8Array(), 8), hex("8000000000000000"));
  assert.deepEqual(pad3(hex("1122334455667788"), 8), hex("1122334455667788"));
  assert.deepEqual(unpad2(pad2(hex("112233"), 8)), hex("112233"));
  assert.throws(() => unpad2(hex("0000000000000000")));
});

test("ECB applies Magma to each independent block", () => {
  const cipher = new MagmaCipher(hex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  const plaintext = hex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");
  const ciphertext = hex("2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb");
  assert.deepEqual(ecbEncrypt(cipher, plaintext), ciphertext);
  assert.deepEqual(ecbDecrypt(cipher, ciphertext), plaintext);
});

test("ECB applies Kuznyechik to each independent block", () => {
  const cipher = new KuznyechikCipher(hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"));
  const plaintext = hex("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a");
  const ciphertext = hex("7f679d90bebc24305a468d42b9d4edcdb429912c6e0032f9285452d76718d08b");
  assert.deepEqual(ecbEncrypt(cipher, plaintext), ciphertext);
  assert.deepEqual(ecbDecrypt(cipher, ciphertext), plaintext);
  assert.throws(() => ecbEncrypt(cipher, new Uint8Array(3)), RangeError);
});
