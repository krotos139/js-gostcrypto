import assert from "node:assert/strict";
import test from "node:test";
import { ALL_GOST_CURVES, TC26_PARAM_SET_512_A, createPrivateKey } from "@gostcrypto/signature";
import { deriveVkoKek256, deriveVkoKek512, sharedPoint, ukmFromBytes } from "@gostcrypto/vko";

const fromHex = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const toHex = (value) => Buffer.from(value).toString("hex");
const leInt = (value) => ukmFromBytes(fromHex(value));

const ukm = leInt("1d80603c8544c727");
const dA = leInt("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667");
const dB = leInt("48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db");

test("RFC 7836 VKO 256 and 512 vectors", () => {
  const a = createPrivateKey(TC26_PARAM_SET_512_A, dA);
  const b = createPrivateKey(TC26_PARAM_SET_512_A, dB);
  const expected256 = "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221";
  const expected512 = "79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf";
  assert.equal(toHex(deriveVkoKek256(a, b.publicKey, ukm)), expected256);
  assert.equal(toHex(deriveVkoKek256(b, a.publicKey, ukm)), expected256);
  assert.equal(toHex(deriveVkoKek512(a, b.publicKey, ukm)), expected512);
  assert.equal(toHex(deriveVkoKek512(b, a.publicKey, ukm)), expected512);
});

test("VKO agreement works on every named curve", () => {
  for (const curve of ALL_GOST_CURVES) {
    const a = createPrivateKey(curve, 2n);
    const b = createPrivateKey(curve, 3n);
    assert.deepEqual(deriveVkoKek256(a, b.publicKey, 12345n), deriveVkoKek256(b, a.publicKey, 12345n), curve.name);
  }
});

test("VKO applies the 2012 cofactor", () => {
  const cofactorFour = ALL_GOST_CURVES.find((curve) => curve.m / curve.q === 4n);
  assert.ok(cofactorFour);
  const a = createPrivateKey(cofactorFour, 2n);
  const b = createPrivateKey(cofactorFour, 3n);
  const actual = sharedPoint(a, b.publicKey, 5n);
  const withoutCofactor = sharedPoint(a, b.publicKey, 5n * ((cofactorFour.q + 1n) / 4n));
  assert.notDeepEqual(actual, withoutCofactor);
});

test("VKO validates UKM and curve compatibility", () => {
  assert.equal(ukmFromBytes(Uint8Array.of(1, 2, 3)), 0x030201n);
  const a = createPrivateKey(ALL_GOST_CURVES[0], 2n);
  const b = createPrivateKey(ALL_GOST_CURVES[1], 3n);
  assert.throws(() => deriveVkoKek256(a, a.publicKey, 0n), /positive/);
  assert.throws(() => deriveVkoKek256(a, b.publicKey, 1n), /different curves/);
});
