import assert from "node:assert/strict";
import test from "node:test";
import { KuznyechikCipher, MagmaCipher } from "@gostcrypto/ciphers";
import { Mgm, MgmAuthenticationError } from "@gostcrypto/mgm";
function hex(value) { return value === "" ? new Uint8Array() : Uint8Array.from(value.match(/../g).map((pair) => Number.parseInt(pair,16))); }
const vectors = [
  { name:"Kuznyechik", cipher:new KuznyechikCipher(hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")), nonce:"1122334455667700ffeeddccbbaa9988", ad:"0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505", plain:"1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011aabbcc", cipherText:"a9757b8147956e9055b8a33de89f42fc8075d2212bf9fd5bd3f7069aadc16b39497ab15915a6ba85936b5d0ea9f6851cc60c14d4d3f883d0ab94420695c76deb2c7552", tag:"cf5d656f40c34f5c46e8bb0e29fcdb4c" },
  { name:"Magma", cipher:new MagmaCipher(hex("99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88")), nonce:"0077665544332211", ad:"", plain:"22334455667700ff", cipherText:"6a95e1426b259d4e", tag:"334ee270450bec9e" },
];
for (const vector of vectors) test(`RFC 9058 MGM vector: ${vector.name}`,()=>{ const mgm=new Mgm(vector.cipher,hex(vector.tag).length); const expected=Uint8Array.from([...hex(vector.cipherText),...hex(vector.tag)]); assert.deepEqual(mgm.seal(hex(vector.nonce),hex(vector.plain),hex(vector.ad)),expected); assert.deepEqual(mgm.open(hex(vector.nonce),expected,hex(vector.ad)),hex(vector.plain)); });
test("MGM rejects tampering",()=>{ const vector=vectors[0]; const mgm=new Mgm(vector.cipher,16); const sealed=mgm.seal(hex(vector.nonce),hex(vector.plain),hex(vector.ad)); sealed[0]^=1; assert.throws(()=>mgm.open(hex(vector.nonce),sealed,hex(vector.ad)),MgmAuthenticationError); });
