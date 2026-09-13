import assert from "node:assert/strict";
import test from "node:test";
import { KuznyechikCipher, MagmaCipher } from "@gostcrypto/ciphers";
import { KeyIntegrityError, kexp15, kimp15 } from "@gostcrypto/keywrap";
function hex(v){return Uint8Array.from(v.match(/../g).map(x=>Number.parseInt(x,16)));}
const secret=hex("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF");
const km=hex("08090A0B0C0D0E0F0001020304050607101112131415161718191A1B1C1D1E1F"); const ke=hex("202122232425262728292A2B2C2D2E2F38393A3B3C3D3E3F3031323334353637");
const vectors=[
 {name:"Magma",make:(k)=>new MagmaCipher(k),iv:"67BED654",out:"CFD5A12D5B81B6E1E99C916D07900C6AC12703FB3ABDED55567BF3742C899C755DAFE7B42E3A8BD9"},
 {name:"Kuznyechik",make:(k)=>new KuznyechikCipher(k),iv:"0909472DD9F26BE8",out:"E36184E84E8D736FF36CC2E5AE065DC656B23C20F549B02FDFF88E1F3F30D8C29A53F3CA554DBAD80DE152B9A4625B32"}
];
for(const v of vectors)test(`KExp15 vector: ${v.name}`,()=>{const mc=v.make(km),ec=v.make(ke),iv=hex(v.iv),expected=hex(v.out);assert.deepEqual(kexp15(mc,ec,iv,secret),expected);assert.deepEqual(kimp15(mc,ec,iv,expected),secret);});
test("KImp15 rejects tampering",()=>{const mc=new KuznyechikCipher(km),ec=new KuznyechikCipher(ke),iv=hex("0909472DD9F26BE8"),bad=kexp15(mc,ec,iv,secret);bad[10]^=1;assert.throws(()=>kimp15(mc,ec,iv,bad),KeyIntegrityError);});
