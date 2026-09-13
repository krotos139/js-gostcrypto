import assert from "node:assert/strict";
import test from "node:test";
import { StreebogHash, streebog256, streebog512 } from "@gostcrypto/hash";

function fromHex(hex) {
  return Uint8Array.from(hex.match(/../g).map((part) => Number.parseInt(part, 16)));
}

function reverseHex(hex) {
  return fromHex(hex).reverse();
}

const m1 = "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130";
const h512 = "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b";
const h256 = "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d";
const m2 = "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1";
const m2h512 = "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e";
const m2h256 = "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d";

test("RFC 6986 vector M1", () => {
  const message = reverseHex(m1);
  assert.deepEqual(streebog512(message), reverseHex(h512));
  assert.deepEqual(streebog256(message), reverseHex(h256));
});

test("RFC 6986 vector M2", () => {
  const message = reverseHex(m2);
  assert.deepEqual(streebog512(message), reverseHex(m2h512));
  assert.deepEqual(streebog256(message), reverseHex(m2h256));
});

test("CryptoPro CSP 5.0 interoperability fixture", () => {
  const data = Uint8Array.from({ length: 4097 }, (_, index) => (index * 73 + 19) & 0xff);
  assert.deepEqual(streebog256(data), fromHex("002d1f018a568ed07b590928e02b5fbe4ba5e6952d349c36f08692fb0a3b89c4"));
  assert.deepEqual(streebog512(data), fromHex("6003ce949db09dd78cd234b493ee543095817cd30dee4724e8dabaefec39b0d8c6f667a969d4e6980dad95a6358e1ec670b78fbd205f70648623f076cce27114"));
});

test("streaming chunks and digest do not mutate state", () => {
  const message = reverseHex(m1);
  const hash = new StreebogHash(64);
  for (const byte of message) hash.update(Uint8Array.of(byte));
  const once = hash.digest();
  assert.deepEqual(hash.digest(), once);
  assert.deepEqual(once, streebog512(message));
});

test("block boundaries are independent of update chunking", () => {
  const data = Uint8Array.from({ length: 129 }, (_, index) => index);
  const expected = streebog512(data);
  for (const chunkSize of [1, 2, 31, 63, 64, 65]) {
    const hash = new StreebogHash(64);
    for (let offset = 0; offset < data.length; offset += chunkSize) {
      hash.update(data.subarray(offset, offset + chunkSize));
    }
    assert.deepEqual(hash.digest(), expected, `chunk size ${chunkSize}`);
  }
});
