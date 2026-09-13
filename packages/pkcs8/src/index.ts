import { OID, curveByOid, decodeOid, encodeDer, encodeOid, encodeSequence, oidByCurve, readDer, readDerChildren } from "@gostcrypto/asn1";
import { createPrivateKey, randomScalar, type GostCurve, type GostPrivateKey, type RandomFill } from "@gostcrypto/signature";
import { pbkdf2Streebog512 } from "@gostcrypto/kdf";
import { Gost28147MeshedCfb,paramCryptoProA,paramCryptoProB,paramCryptoProC,paramCryptoProD,paramTest,paramZ,type Gost28147SBox } from "@gostcrypto/legacy-gost28147";

function encodeLittleEndian(value: bigint, size: number): Uint8Array {
  const output=new Uint8Array(size);let current=value;
  for(let index=0;index<size;index+=1){output[index]=Number(current&0xffn);current>>=8n;}
  if(current!==0n)throw new RangeError("private key component too large");return output;
}
function decodeLittleEndian(bytes: Uint8Array): bigint {let result=0n;for(let index=bytes.length-1;index>=0;index-=1)result=(result<<8n)|BigInt(bytes[index]!);return result;}
function mod(value: bigint, modulus: bigint): bigint {const result=value%modulus;return result<0n?result+modulus:result;}
function inverse(value: bigint, modulus: bigint): bigint {let a=mod(value,modulus),b=modulus,x=1n,y=0n;while(b!==0n){const q=a/b;[a,b]=[b,a%b];[x,y]=[y,x-q*y];}if(a!==1n)throw new RangeError("mask is not invertible");return mod(x,modulus);}

export interface EncodePrivateKeyOptions { readonly masks?: number; readonly fillRandom?: RandomFill; }

export function maskPrivateKey(privateKey: GostPrivateKey, masks=0, fillRandom?: RandomFill): Uint8Array {
  if(!Number.isSafeInteger(masks)||masks<0)throw new RangeError("invalid mask count");
  const {curve,d}=privateKey,parts:Uint8Array[]=[];let masked=d;
  for(let index=0;index<masks;index+=1){const mask=randomScalar(curve,fillRandom);masked=mod(masked*inverse(mask,curve.q),curve.q);parts.push(encodeLittleEndian(mask,curve.size));}
  return Uint8Array.from([...encodeLittleEndian(masked,curve.size),...parts.flatMap((part)=>[...part])]);
}

export function unmaskPrivateKey(curve: GostCurve, blob: Uint8Array): GostPrivateKey {
  if(blob.length===0||blob.length%curve.size!==0)throw new RangeError("malformed masked private key");
  let value=decodeLittleEndian(blob.subarray(0,curve.size));
  for(let offset=curve.size;offset<blob.length;offset+=curve.size)value=mod(value*decodeLittleEndian(blob.subarray(offset,offset+curve.size)),curve.q);
  return createPrivateKey(curve,value);
}

function algorithmIdentifier(curve: GostCurve): Uint8Array {
  const parameterOid=oidByCurve(curve);if(parameterOid===undefined)throw new RangeError("curve has no registered OID");
  const params=encodeSequence(encodeOid(parameterOid),...(parameterOid.startsWith("1.2.643.2.2.")?[encodeOid(OID.digest256)]:[]));
  return encodeSequence(encodeOid(curve.size===64?OID.publicKey512:OID.publicKey256),params);
}

export function encodePrivateKeyInfo(privateKey: GostPrivateKey, options: EncodePrivateKeyOptions={}): Uint8Array {
  const blob=maskPrivateKey(privateKey,options.masks??0,options.fillRandom);
  return encodeSequence(encodeDer(0x02,Uint8Array.of(0)),algorithmIdentifier(privateKey.curve),encodeDer(0x04,blob));
}

function parseBlob(content: Uint8Array, curve: GostCurve): Uint8Array {
  if(content.length>0&&content[0]===0x30){try{const sequence=readDer(content);if(sequence.end===content.length){const fields=readDerChildren(sequence.content);if(fields[0]?.tag===0x04&&fields[0].content.length>0&&fields[0].content.length%curve.size===0)return fields[0].content;}}catch{/* A raw little-endian scalar may start with the same byte as a DER tag. */}}
  if(content.length>0&&content[0]===0x04){try{const octets=readDer(content);if(octets.end===content.length&&octets.content.length>0&&octets.content.length%curve.size===0)return octets.content;}catch{/* Fall through to the raw-key representation. */}}
  if(content.length>0&&content.length%curve.size===0)return content;
  throw new RangeError("malformed PKCS#8 private key blob");
}

export function parsePrivateKeyInfo(der: Uint8Array): GostPrivateKey {
  const outer=readDer(der);if(outer.tag!==0x30||outer.end!==der.length)throw new RangeError("malformed PKCS#8 PrivateKeyInfo");
  const fields=readDerChildren(outer.content);if(fields.length<3||fields[0]!.tag!==0x02||fields[1]!.tag!==0x30||fields[2]!.tag!==0x04)throw new RangeError("malformed PKCS#8 PrivateKeyInfo");
  if(fields[0]!.content.length!==1||fields[0]!.content[0]!==0)throw new RangeError("unsupported PKCS#8 version");
  const algorithm=readDerChildren(fields[1]!.content);if(algorithm.length!==2||algorithm[0]!.tag!==0x06||algorithm[1]!.tag!==0x30)throw new RangeError("malformed PKCS#8 algorithm");
  const algorithmOid=decodeOid(algorithm[0]!);
  if(![OID.publicKey256,OID.publicKey512,OID.publicKey2001].some((value)=>value===algorithmOid))throw new RangeError("unsupported PKCS#8 algorithm");
  const parameters=readDerChildren(algorithm[1]!.content);if(parameters.length<1)throw new RangeError("malformed PKCS#8 parameters");
  const parameterOid=decodeOid(parameters[0]!);const curve=curveByOid(parameterOid);if(curve===undefined)throw new RangeError("unsupported PKCS#8 curve");
  if((algorithmOid===OID.publicKey512)!==(curve.size===64))throw new RangeError("PKCS#8 algorithm and curve size differ");
  return unmaskPrivateKey(curve,parseBlob(fields[2]!.content,curve));
}

export const PBES2_OID="1.2.840.113549.1.5.13",PBKDF2_OID="1.2.840.113549.1.5.12";
export interface EncryptPrivateKeyOptions extends EncodePrivateKeyOptions {readonly iterations?:number;readonly saltSize?:number;readonly parameterSetOid?:string;}
const sboxes=new Map<string,()=>Gost28147SBox>([[OID.cipherParamZ,paramZ],[OID.cipherTestParamSet,paramTest],[OID.cipherCryptoProA,paramCryptoProA],[OID.cipherCryptoProB,paramCryptoProB],[OID.cipherCryptoProC,paramCryptoProC],[OID.cipherCryptoProD,paramCryptoProD]]);
function randomBytes(length:number,fill?:RandomFill):Uint8Array{const output=new Uint8Array(length);if(fill!==undefined)fill(output);else{if(globalThis.crypto===undefined)throw new Error("Web Crypto getRandomValues is unavailable");globalThis.crypto.getRandomValues(output);}return output;}
function encodeInteger(value:number):Uint8Array{if(!Number.isSafeInteger(value)||value<0)throw new RangeError("invalid DER integer");const bytes:number[]=[];do{bytes.unshift(value&255);value=Math.floor(value/256);}while(value>0);if((bytes[0]!&128)!==0)bytes.unshift(0);return encodeDer(0x02,Uint8Array.from(bytes));}
function decodeInteger(element:ReturnType<typeof readDer>):number{if(element.tag!==0x02||element.content.length===0||(element.content[0]!&128)!==0)throw new RangeError("malformed DER integer");let value=0;for(const byte of element.content)value=value*256+byte;if(!Number.isSafeInteger(value))throw new RangeError("DER integer too large");return value;}
function encodePbes2Algorithm(salt:Uint8Array,iv:Uint8Array,iterations:number,parameterSetOid:string):Uint8Array{const prf=encodeSequence(encodeOid(OID.hmac512),encodeDer(0x05,new Uint8Array()));const kdfParams=encodeSequence(encodeDer(0x04,salt),encodeInteger(iterations),prf);const kdf=encodeSequence(encodeOid(PBKDF2_OID),kdfParams);const cipherParams=encodeSequence(encodeDer(0x04,iv),encodeOid(parameterSetOid));const cipher=encodeSequence(encodeOid(OID.cipher28147),cipherParams);return encodeSequence(encodeOid(PBES2_OID),encodeSequence(kdf,cipher));}
function parseAlgorithmIdentifier(element:ReturnType<typeof readDer>):{oid:string;parameters:ReturnType<typeof readDer>}{if(element.tag!==0x30)throw new RangeError("malformed AlgorithmIdentifier");const fields=readDerChildren(element.content);if(fields.length!==2)throw new RangeError("malformed AlgorithmIdentifier");return{oid:decodeOid(fields[0]!),parameters:fields[1]!};}
function parsePbes2(algorithm:ReturnType<typeof readDer>):{salt:Uint8Array;iv:Uint8Array;iterations:number;sbox:Gost28147SBox}{const outer=parseAlgorithmIdentifier(algorithm);if(outer.oid!==PBES2_OID||outer.parameters.tag!==0x30)throw new RangeError("unsupported encryption algorithm");const params=readDerChildren(outer.parameters.content);if(params.length!==2)throw new RangeError("malformed PBES2 parameters");const kdf=parseAlgorithmIdentifier(params[0]!),cipher=parseAlgorithmIdentifier(params[1]!);if(kdf.oid!==PBKDF2_OID||cipher.oid!==OID.cipher28147)throw new RangeError("unsupported PBES2 scheme");const kp=readDerChildren(kdf.parameters.content);if(kp.length<2||kp[0]!.tag!==0x04)throw new RangeError("malformed PBKDF2 parameters");const iterations=decodeInteger(kp[1]!);if(iterations<=0)throw new RangeError("PBKDF2 iterations must be positive");if(kp.length>=3){const prf=parseAlgorithmIdentifier(kp[kp.length-1]!);if(prf.oid!==OID.hmac512)throw new RangeError("unsupported PBKDF2 PRF");}const cp=readDerChildren(cipher.parameters.content);if(cp.length!==2||cp[0]!.tag!==0x04||cp[0]!.content.length!==8)throw new RangeError("malformed GOST 28147 parameters");const parameterSetOid=decodeOid(cp[1]!),factory=sboxes.get(parameterSetOid);if(factory===undefined)throw new RangeError("unsupported GOST 28147 parameter set");return{salt:Uint8Array.from(kp[0]!.content),iv:Uint8Array.from(cp[0]!.content),iterations,sbox:factory()};}
export function encryptPbes2(data:Uint8Array,password:Uint8Array,options:EncryptPrivateKeyOptions={}):{algorithmIdentifier:Uint8Array;encryptedData:Uint8Array}{const iterations=options.iterations??2000,saltSize=options.saltSize??32,parameterSetOid=options.parameterSetOid??OID.cipherParamZ;if(iterations<=0||!Number.isSafeInteger(iterations))throw new RangeError("PBKDF2 iterations must be positive");if(saltSize<8||saltSize>32||!Number.isInteger(saltSize))throw new RangeError("salt size must be 8..32");const factory=sboxes.get(parameterSetOid);if(factory===undefined)throw new RangeError("unsupported GOST 28147 parameter set");const salt=randomBytes(saltSize,options.fillRandom),iv=randomBytes(8,options.fillRandom),key=pbkdf2Streebog512(password,salt,iterations,32);return{algorithmIdentifier:encodePbes2Algorithm(salt,iv,iterations,parameterSetOid),encryptedData:new Gost28147MeshedCfb(key,factory(),iv).update(data)};}
export function decryptPbes2(algorithmIdentifier:Uint8Array,encryptedData:Uint8Array,password:Uint8Array):Uint8Array{const element=readDer(algorithmIdentifier);if(element.end!==algorithmIdentifier.length)throw new RangeError("malformed AlgorithmIdentifier");const params=parsePbes2(element),key=pbkdf2Streebog512(password,params.salt,params.iterations,32);return new Gost28147MeshedCfb(key,params.sbox,params.iv,true).update(encryptedData);}
export function encodeEncryptedPrivateKeyInfo(privateKey:GostPrivateKey,password:Uint8Array,options:EncryptPrivateKeyOptions={}):Uint8Array{const plain=encodePrivateKeyInfo(privateKey,options),encrypted=encryptPbes2(plain,password,options);return encodeSequence(encrypted.algorithmIdentifier,encodeDer(0x04,encrypted.encryptedData));}
export function decryptPrivateKeyInfo(der:Uint8Array,password:Uint8Array):Uint8Array{const outer=readDer(der);if(outer.tag!==0x30||outer.end!==der.length)throw new RangeError("malformed EncryptedPrivateKeyInfo");const fields=readDerChildren(outer.content);if(fields.length!==2||fields[1]!.tag!==0x04)throw new RangeError("malformed EncryptedPrivateKeyInfo");return decryptPbes2(fields[0]!.full,fields[1]!.content,password);}
export function parseEncryptedPrivateKeyInfo(der:Uint8Array,password:Uint8Array):GostPrivateKey{return parsePrivateKeyInfo(decryptPrivateKeyInfo(der,password));}
