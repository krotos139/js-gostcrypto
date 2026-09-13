import assert from "node:assert/strict";
import test from "node:test";
import { KuznyechikCipher } from "@gostcrypto/ciphers";

function hex(hexString) {
  return Uint8Array.from(hexString.match(/../g).map((part) => Number.parseInt(part, 16)));
}

const key = hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");

test("RFC 7801 Kuznyechik encryption and decryption vector", () => {
  const cipher = new KuznyechikCipher(key);
  const plaintext = hex("1122334455667700ffeeddccbbaa9988");
  const ciphertext = hex("7f679d90bebc24305a468d42b9d4edcd");
  assert.deepEqual(cipher.encryptBlock(plaintext), ciphertext);
  assert.deepEqual(cipher.decryptBlock(ciphertext), plaintext);
});

test("GOST R 34.13 ECB base-cipher vectors", () => {
  const cipher = new KuznyechikCipher(key);
  const vectors = [
    ["1122334455667700ffeeddccbbaa9988", "7f679d90bebc24305a468d42b9d4edcd"],
    ["00112233445566778899aabbcceeff0a", "b429912c6e0032f9285452d76718d08b"],
    ["112233445566778899aabbcceeff0a00", "f0ca33549d247ceef3f5a5313bd4b157"],
    ["2233445566778899aabbcceeff0a0011", "d0b09ccde830b9eb3a02c4c5aa8ada98"],
  ];
  for (const [plaintext, ciphertext] of vectors) {
    assert.deepEqual(cipher.encryptBlock(hex(plaintext)), hex(ciphertext));
    assert.deepEqual(cipher.decryptBlock(hex(ciphertext)), hex(plaintext));
  }
});

test("Kuznyechik rejects invalid key and block lengths", () => {
  assert.throws(() => new KuznyechikCipher(new Uint8Array(31)), RangeError);
  const cipher = new KuznyechikCipher(key);
  assert.throws(() => cipher.encryptBlock(new Uint8Array(15)), RangeError);
});

test("Kuznyechik key expansion is stable across independent instances", () => {
  const originalKey = Uint8Array.from(key);
  for (let seed = 0; seed < 64; seed += 1) {
    const candidateKey = Uint8Array.from({ length: 32 }, (_, index) => seed * 17 + index * 29);
    const plaintext = Uint8Array.from({ length: 16 }, (_, index) => seed * 31 + index * 13);
    const cipher = new KuznyechikCipher(candidateKey);
    assert.deepEqual(cipher.decryptBlock(cipher.encryptBlock(plaintext)), plaintext);
  }
  assert.deepEqual(key, originalKey, "constructor must not mutate its input key");
  assert.deepEqual(
    new KuznyechikCipher(key).encryptBlock(hex("1122334455667700ffeeddccbbaa9988")),
    hex("7f679d90bebc24305a468d42b9d4edcd"),
  );
});
