import assert from "node:assert/strict";
import test from "node:test";
import { MagmaCipher, magmaRound, magmaSubstitute } from "@gostcrypto/ciphers";

function hex(hexString) {
  return Uint8Array.from(hexString.match(/../g).map((part) => Number.parseInt(part, 16)));
}

test("GOST R 34.12-2015 substitution and round vectors", () => {
  assert.equal(magmaSubstitute(0xfdb97531), 0x2a196f34);
  assert.equal(magmaRound(0xfedcba98, 0x87654321), 0xfdcbc20c);
});

test("RFC 8891 Magma encryption and decryption vector", () => {
  const cipher = new MagmaCipher(hex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  const plaintext = hex("fedcba9876543210");
  const ciphertext = hex("4ee901e5c2d8ca3d");
  assert.deepEqual(cipher.encryptBlock(plaintext), ciphertext);
  assert.deepEqual(cipher.decryptBlock(ciphertext), plaintext);
});

test("GOST R 34.13 ECB base-cipher vectors", () => {
  const cipher = new MagmaCipher(hex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  const vectors = [
    ["92def06b3c130a59", "2b073f0494f372a0"],
    ["db54c704f8189d20", "de70e715d3556e48"],
    ["4a98fb2e67a8024c", "11d8d9e9eacfbc1e"],
    ["8912409b17b57e41", "7c68260996c67efb"],
  ];
  for (const [plaintext, ciphertext] of vectors) {
    assert.deepEqual(cipher.encryptBlock(hex(plaintext)), hex(ciphertext));
    assert.deepEqual(cipher.decryptBlock(hex(ciphertext)), hex(plaintext));
  }
});

test("Magma rejects invalid key and block lengths", () => {
  assert.throws(() => new MagmaCipher(new Uint8Array(31)), RangeError);
  const cipher = new MagmaCipher(new Uint8Array(32));
  assert.throws(() => cipher.encryptBlock(new Uint8Array(7)), RangeError);
});
