import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv } from "node:crypto";
import test from "node:test";
import { KuznyechikCipher, MagmaCipher } from "@gostcrypto/ciphers";
import { CbcAcpkmMaster, CfbAcpkmMaster, CtrAcpkm, CtrAcpkmMaster, OmacAcpkmMaster, deriveAcpkm, deriveAcpkmMasterKeys, omacAcpkmMaster } from "@gostcrypto/acpkm";
const bytes = (length) => Uint8Array.from({ length }, (_, index) => index);
const factories = [{ name: "Kuznyechik", make: (key) => new KuznyechikCipher(key), icn: 8, section: 32 }, { name: "Magma", make: (key) => new MagmaCipher(key), icn: 4, section: 16 }];
for (const item of factories) {
  test(`ACPKM derive and CTR round-trip: ${item.name}`, () => {
    const key = bytes(32); const plain = Uint8Array.from({ length: 200 }, (_, index) => index * 3);
    const derived = deriveAcpkm(item.make(key), key.length); assert.equal(derived.length, 32); assert.notDeepEqual(derived, key);
    const ciphertext = new CtrAcpkm(item.make, key, new Uint8Array(item.icn), item.section).update(plain);
    assert.deepEqual(new CtrAcpkm(item.make, key, new Uint8Array(item.icn), item.section).update(ciphertext), plain);
    const singleSection = new CtrAcpkm(item.make, key, new Uint8Array(item.icn), 4096).update(plain);
    assert.notDeepEqual(ciphertext, singleSection);
  });
}
test("ACPKM validates parameters", () => { const key = bytes(32); assert.throws(() => new CtrAcpkm((x) => new KuznyechikCipher(x), key, new Uint8Array(8), 15), RangeError); });

const unhex=(value)=>Uint8Array.from(Buffer.from(value.replace(/\s/g,""),"hex"));
const aes256=(key)=>({blockSize:16,encryptBlock(block){const cipher=createCipheriv("aes-256-ecb",key,null);cipher.setAutoPadding(false);return Uint8Array.from(cipher.update(block));},decryptBlock(block){const cipher=createDecipheriv("aes-256-ecb",key,null);cipher.setAutoPadding(false);return Uint8Array.from(cipher.update(block));}});
const masterKey=unhex(`88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF`);
const masterPlain=unhex(`11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88 00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33 44`);

test("RFC 8645 ACPKM-Master key material and CTR vectors",()=>{
  const material=unhex(`9F 10 BB F1 3A 79 FB BD 4A 4C A8 64 C4 90 74 64 39 FE 50 6D 4B 86 9B 21 03 A3 B6 A4 79 28 3C 60 77 91 17 50 E0 D1 77 E5 9A 13 78 2B F1 89 08 D0 AB 6B 59 EE 92 49 05 B3 AB C7 A4 E3 69 65 76 C3 E8 76 2B 30 8B 08 EB CE 3E 93 9A C2 C0 3E 76 D4 60 9A AB D9 15 33 13 D3 CF D3 94 E7 75 DF 3A 94 F2 EE 91 45 6B DC 3D E4 91 2C 87 C3 29 CF 31 A9 2F 20 2E 5A C4 9A 2A 65 31 33 D6 74 8C 4F F9 12`);
  assert.deepEqual(deriveAcpkmMasterKeys(aes256,masterKey,64,32,4),material);
  const gamma=unhex(`8C A2 B6 82 A7 50 65 3F 8E BF 08 E7 9F 99 4D 5C F6 A6 A5 BA 58 14 1E ED 23 DC 31 68 D2 35 89 A1 4A 07 5F 86 05 87 72 94 1D 8E 7D F8 32 F4 23 71 23 35 66 AF 61 DD FE A7 B1 68 3F BA B0 52 4A D7 A8 09 6D BC E8 BB 52 FC DE 6E 03 70 C1 66 95 E8`);
  const encrypted=new CtrAcpkmMaster(aes256,masterKey,unhex(`12 34 56 78 90 AB CE F0`),32,64).update(masterPlain);
  assert.deepEqual(encrypted.slice(0,gamma.length),Uint8Array.from(gamma,(value,index)=>value^masterPlain[index]));
});

test("RFC 8645 CBC, CFB and OMAC ACPKM-Master vectors",()=>{
  const iv=unhex(`12 34 56 78 90 AB CE F0 A1 B2 C3 D4 E5 F0 01 12`);
  const cbcExpected=unhex(`59 CB 5B CA C2 69 2C 60 0D 46 03 A0 C7 40 C9 7C 80 B6 02 74 54 8B F7 C9 78 1F A1 05 8B F6 8B 42 8C 24 FB CF 68 15 B1 AF 65 FE 47 75 95 B4 97 59 19 65 A5 00 58 0D 50 23 72 1B E9 90 E1 83 30 E9 56 D8 34 F4 6F 0F 4D E6 20 53 A9 5C B5 F6 3C 14 66 68 2B 8B DD 6E B2 7E DE C7 51 D6 2F 45 A5 45 7F 4D 87 F9 CA E9 56 09 79 C4 FA FE 34 0B 45 34`);
  const cbc=new CbcAcpkmMaster(aes256,masterKey,iv,32,64).update(masterPlain);
  assert.deepEqual(cbc,cbcExpected);
  assert.deepEqual(new CbcAcpkmMaster(aes256,masterKey,iv,32,64,true).update(cbc),masterPlain);
  const cfbPlain=masterPlain.slice(0,104),cfbExpected=unhex(`0D 1B AE 1D AD 3B E6 91 56 3C CF 53 D8 BF 09 8B 6B B3 E7 71 16 3C A0 7C 9D 8D AC 3C 5C A8 09 24 84 67 6C 9F 96 F8 7D 9B 06 61 AB 39 53 86 A9 88 C2 99 76 08 E6 D3 CF 0C 10 F9 73 8D 07 40 C8 A3 CD 06 D9 16 B5 D9 57 B9 8D 0D 51 BB F2 49 77 AB 45 71 E6 F0 0E 81 0F F8 DD E4 33 BF 0A F4 20 90 C2 3A E1 BF CC B4 37 B3`);
  const cfb=new CfbAcpkmMaster(aes256,masterKey,iv,32,64).update(cfbPlain);
  assert.deepEqual(cfb,cfbExpected);
  assert.deepEqual(new CfbAcpkmMaster(aes256,masterKey,iv,32,64,true).update(cfb),cfbPlain);
  const omacPlain=masterPlain.slice(0,80),omacExpected=unhex(`B3 AD B8 92 18 32 05 4C 09 21 E7 B8 08 CF A0 B8`);
  assert.deepEqual(omacAcpkmMaster(aes256,masterKey,omacPlain,32,96,16),omacExpected);
});

test("ACPKM-Master modes stream across chunks with GOST ciphers",()=>{
  for(const item of factories){const key=bytes(32),iv=new Uint8Array(item.make(key).blockSize),plain=Uint8Array.from({length:200},(_,index)=>index*7);
    const ctr=new CtrAcpkmMaster(item.make,key,new Uint8Array(item.icn),item.section,item.section*2),cfb=new CfbAcpkmMaster(item.make,key,iv,item.section,item.section*2),mac=new OmacAcpkmMaster(item.make,key,item.section,item.section*3);
    const ctrParts=[],cfbParts=[];for(let offset=0;offset<plain.length;offset+=13){const part=plain.slice(offset,offset+13);ctrParts.push(ctr.update(part));cfbParts.push(cfb.update(part));mac.update(part);}
    const join=(parts)=>Uint8Array.from(parts.flatMap((part)=>[...part])),ctrCipher=join(ctrParts),cfbCipher=join(cfbParts);
    assert.deepEqual(new CtrAcpkmMaster(item.make,key,new Uint8Array(item.icn),item.section,item.section*2).update(ctrCipher),plain);
    const cfbDecrypt=new CfbAcpkmMaster(item.make,key,iv,item.section,item.section*2,true),back=[];for(let offset=0;offset<cfbCipher.length;offset+=11)back.push(cfbDecrypt.update(cfbCipher.slice(offset,offset+11)));assert.deepEqual(join(back),plain);
    assert.deepEqual(mac.digest(),omacAcpkmMaster(item.make,key,plain,item.section,item.section*3));assert.deepEqual(mac.digest(),mac.digest());
  }
});

test("ACPKM-Master validates parameters",()=>{const key=bytes(32),factory=(value)=>new KuznyechikCipher(value);assert.throws(()=>deriveAcpkmMasterKeys(factory,key,15,32,1),RangeError);assert.throws(()=>new CtrAcpkmMaster(factory,key,new Uint8Array(8),31,64),RangeError);assert.throws(()=>new CbcAcpkmMaster(factory,key,new Uint8Array(15),32,64),RangeError);assert.throws(()=>new OmacAcpkmMaster(factory,key,32,64,17),RangeError);});
