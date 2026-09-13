import type { BlockCipher, Bytes } from "@gostcrypto/core";
import { GostCtr, GostMac } from "@gostcrypto/modes";
import { Gost28147Cfb, Gost28147Cipher, Gost28147Mac, type Gost28147SBox } from "@gostcrypto/legacy-gost28147";

export class KeyIntegrityError extends Error { public constructor() { super("KExp15 integrity check failed"); this.name = "KeyIntegrityError"; } }
function concat(...parts: readonly Bytes[]): Bytes { const output=new Uint8Array(parts.reduce((n,p)=>n+p.length,0)); let offset=0; for(const part of parts){output.set(part,offset);offset+=part.length;} return output; }
function check(macCipher: BlockCipher, encCipher: BlockCipher, iv: Bytes): number { if(macCipher.blockSize!==encCipher.blockSize) throw new RangeError("KExp15 ciphers must have equal block sizes"); if(iv.length!==macCipher.blockSize/2) throw new RangeError("invalid KExp15 IV length"); return macCipher.blockSize; }
function equal(left: Bytes,right: Bytes):boolean { if(left.length!==right.length)return false; let diff=0; for(let i=0;i<left.length;i+=1)diff|=left[i]!^right[i]!; return diff===0; }

/** Modern key export KExp15 from R 1323565.1.017-2018 / RFC 9189. */
export function kexp15(macCipher: BlockCipher, encCipher: BlockCipher, iv: Bytes, secret: Bytes): Bytes {
  const blockSize=check(macCipher,encCipher,iv); if(secret.length===0)throw new RangeError("KExp15 secret must not be empty");
  const tag=new GostMac(macCipher,blockSize).update(concat(iv,secret)).digest(); return new GostCtr(encCipher,iv).update(concat(secret,tag));
}
/** Authenticated inverse of KExp15. */
export function kimp15(macCipher: BlockCipher, encCipher: BlockCipher, iv: Bytes, exported: Bytes): Bytes {
  const blockSize=check(macCipher,encCipher,iv); if(exported.length<=blockSize)throw new RangeError("KExp15 representation is too short");
  const decoded=new GostCtr(encCipher,iv).update(exported); const secret=decoded.slice(0,-blockSize); const tag=decoded.slice(-blockSize);
  const expected=new GostMac(macCipher,blockSize).update(concat(iv,secret)).digest(); if(!equal(tag,expected))throw new KeyIntegrityError(); return secret;
}

export const CRYPTOPRO_UKM_SIZE=8,CRYPTOPRO_WRAPPED_SIZE=44;
export class CryptoProKeyIntegrityError extends Error {constructor(){super("CryptoPro key wrap integrity check failed");this.name="CryptoProKeyIntegrityError";}}
const read32le=(input:Uint8Array,offset:number)=>(input[offset]!|input[offset+1]!<<8|input[offset+2]!<<16|input[offset+3]!<<24)>>>0;
function write32le(output:Uint8Array,offset:number,value:number):void {output[offset]=value&255;output[offset+1]=value>>>8&255;output[offset+2]=value>>>16&255;output[offset+3]=value>>>24&255;}

/** RFC 4357 section 6.5 CryptoPro KEK diversification. */
export function diversifyCryptoProKek(kek:Uint8Array,ukm:Uint8Array,sbox:Gost28147SBox):Uint8Array {
  if(kek.length!==32)throw new RangeError("CryptoPro KEK must be 32 bytes");if(ukm.length!==8)throw new RangeError("CryptoPro UKM must be 8 bytes");let key:Uint8Array=Uint8Array.from(kek);
  for(let round=0;round<8;round+=1){let ones=0,zeros=0;for(let word=0;word<8;word+=1){const value=read32le(key,word*4);if(((ukm[round]!>>>word)&1)===1)ones=(ones+value)>>>0;else zeros=(zeros+value)>>>0;}const iv=new Uint8Array(8);write32le(iv,0,ones);write32le(iv,4,zeros);key=new Gost28147Cfb(new Gost28147Cipher(key,sbox),iv).update(key);}
  return key;
}
function cryptKey(key:Uint8Array,input:Uint8Array,sbox:Gost28147SBox,decrypt:boolean):Uint8Array {if(input.length!==32)throw new RangeError("wrapped key must be 32 bytes");const cipher=new Gost28147Cipher(key,sbox),output=new Uint8Array(32);for(let offset=0;offset<32;offset+=8)output.set(decrypt?cipher.decryptBlock(input.subarray(offset,offset+8)):cipher.encryptBlock(input.subarray(offset,offset+8)),offset);return output;}
function wrapWith(key:Uint8Array,ukm:Uint8Array,cek:Uint8Array,sbox:Gost28147SBox):Uint8Array {if(key.length!==32||cek.length!==32)throw new RangeError("GOST 28147 keys must be 32 bytes");if(ukm.length!==8)throw new RangeError("CryptoPro UKM must be 8 bytes");const encrypted=cryptKey(key,cek,sbox,false),mac=new Gost28147Mac(key,sbox,ukm,4).update(cek).digest();return concat(ukm,encrypted,mac);}
function unwrapWith(key:Uint8Array,wrapped:Uint8Array,sbox:Gost28147SBox):Uint8Array {if(wrapped.length!==44)throw new RangeError("CryptoPro wrapped key must be 44 bytes");const ukm=wrapped.subarray(0,8),cek=cryptKey(key,wrapped.subarray(8,40),sbox,true),expected=new Gost28147Mac(key,sbox,ukm,4).update(cek).digest();if(!equal(expected,wrapped.subarray(40)))throw new CryptoProKeyIntegrityError();return cek;}
/** RFC 4357 section 6.3 wrapping with CryptoPro diversification. */
export function wrapCryptoPro(kek:Uint8Array,ukm:Uint8Array,cek:Uint8Array,sbox:Gost28147SBox):Uint8Array{return wrapWith(diversifyCryptoProKek(kek,ukm,sbox),ukm,cek,sbox);}
/** RFC 4357 section 6.4 authenticated unwrapping. */
export function unwrapCryptoPro(kek:Uint8Array,wrapped:Uint8Array,sbox:Gost28147SBox):Uint8Array {if(wrapped.length!==44)throw new RangeError("CryptoPro wrapped key must be 44 bytes");return unwrapWith(diversifyCryptoProKek(kek,wrapped.subarray(0,8),sbox),wrapped,sbox);}
export function wrapGost28147(kek:Uint8Array,ukm:Uint8Array,cek:Uint8Array,sbox:Gost28147SBox):Uint8Array{return wrapWith(kek,ukm,cek,sbox);}
export function unwrapGost28147(kek:Uint8Array,wrapped:Uint8Array,sbox:Gost28147SBox):Uint8Array{return unwrapWith(kek,wrapped,sbox);}
