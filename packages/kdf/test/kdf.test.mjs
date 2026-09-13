import assert from "node:assert/strict";
import test from "node:test";
import { derive, deriveTree, pbkdf2Streebog256, pbkdf2Streebog512 } from "@gostcrypto/kdf";
function hex(value) { return Uint8Array.from(value.match(/../g).map((pair) => Number.parseInt(pair, 16))); }
const key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const label = hex("26bdb878"); const seed = hex("af21434145656378");
test("RFC 7836 KDF vector", () => assert.deepEqual(derive(key, label, seed), hex("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")));
test("RFC 7836 KDF_TREE vector", () => assert.deepEqual(deriveTree(key, label, seed, 1, 512), hex("22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9")));
test("KDF rejects invalid parameters", () => { assert.throws(() => deriveTree(key,label,seed,0,256),RangeError); assert.throws(() => deriveTree(key,label,seed,1,7),RangeError); });
test("R 50.1.111 PBKDF2 vectors", () => {
  const password = new TextEncoder().encode("password"); const salt = new TextEncoder().encode("salt");
  assert.deepEqual(pbkdf2Streebog512(password, salt, 1, 64), hex("64770af7f748c3b1c9ac831dbcfd85c26111b30a8a657ddc3056b80ca73e040d2854fd36811f6d825cc4ab66ec0a68a490a9e5cf5156b3a2b7eecddbf9a16b47"));
  assert.deepEqual(pbkdf2Streebog512(password, salt, 2, 64), hex("5a585bafdfbb6e8830d6d68aa3b43ac00d2e4aebce01c9b31c2caed56f0236d4d34b2b8fbd2c4e89d54d46f50e47d45bbac301571743119e8d3c42ba66d348de"));
});
test("PBKDF2 output is prefix-stable and variants differ", () => {
  const password = new TextEncoder().encode("password"); const salt = new TextEncoder().encode("salt");
  const full = pbkdf2Streebog512(password, salt, 2, 80);
  assert.deepEqual(pbkdf2Streebog512(password, salt, 2, 32), full.subarray(0, 32));
  assert.notDeepEqual(pbkdf2Streebog256(password, salt, 2, 32), full.subarray(0, 32));
  assert.throws(() => pbkdf2Streebog512(password, salt, 0, 32), RangeError);
});
