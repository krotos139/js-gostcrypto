import assert from "node:assert/strict";
import test from "node:test";
import { encodeBitString,encodeDer,encodeOid,encodeSequence,encodeSubjectPublicKeyInfo } from "@gostcrypto/asn1";
import { CmsError,parseSignedData,signCms } from "@gostcrypto/cms";
import { streebog256,streebog512 } from "@gostcrypto/hash";
import { createPrivateKey,encodePkixSignature,signDigest,TC26_PARAM_SET_256_A,TC26_PARAM_SET_512_A } from "@gostcrypto/signature";

const ascii=(value)=>new TextEncoder().encode(value);
const integer=(value)=>encodeDer(0x02,Uint8Array.of(value));
const deterministic=(target)=>target.fill(1);
function certificate(privateKey,serial=1){
  const signatureOid=privateKey.curve.size===32?"1.2.643.7.1.1.3.2":"1.2.643.7.1.1.3.3",algorithm=encodeSequence(encodeOid(signatureOid));
  const cn=encodeSequence(encodeDer(0x31,encodeSequence(encodeOid("2.5.4.3"),encodeDer(0x0c,ascii("CMS test"))))),validity=encodeSequence(encodeDer(0x17,ascii("260101000000Z")),encodeDer(0x17,ascii("360101000000Z")));
  const tbs=encodeSequence(encodeDer(0xa0,integer(2)),integer(serial),algorithm,cn,validity,cn,encodeSubjectPublicKeyInfo(privateKey.publicKey));
  const digest=privateKey.curve.size===32?streebog256(tbs):streebog512(tbs),signature=encodePkixSignature(privateKey.curve,signDigest(privateKey,digest,deterministic));
  return encodeSequence(tbs,algorithm,encodeBitString(signature));
}

for(const [name,curve] of [["256",TC26_PARAM_SET_256_A],["512",TC26_PARAM_SET_512_A]])test(`CMS attached and detached signatures: ${name}`,()=>{
  const key=createPrivateKey(curve,123456789n),cert=certificate(key),content=ascii("подписанный документ"),when=new Date("2026-09-06T12:34:56Z");
  for(const detached of[false,true]){const encoded=signCms(content,cert,key,{detached,signingTime:when,fillRandom:deterministic}),signed=parseSignedData(encoded);assert.equal(signed.detached,detached);assert.equal(signed.signers.length,1);assert.equal(signed.signers[0].hasSigningCertificate,true);assert.equal(signed.signers[0].signingTime?.toISOString(),when.toISOString());signed.verify(detached?content:undefined);if(detached)assert.throws(()=>signed.verify(),(error)=>error instanceof CmsError&&error.code==="NO_CONTENT");}
});

test("CMS rejects changed content, signature and mismatched certificates",()=>{
  const key=createPrivateKey(TC26_PARAM_SET_256_A,7n),other=createPrivateKey(TC26_PARAM_SET_256_A,8n),cert=certificate(key),content=ascii("source");assert.throws(()=>signCms(content,certificate(other),key),(error)=>error instanceof CmsError&&error.code==="KEY_MISMATCH");
  const signed=parseSignedData(signCms(content,cert,key,{detached:true,fillRandom:deterministic}));assert.throws(()=>signed.verify(ascii("changed")),(error)=>error instanceof CmsError&&error.code==="DIGEST_MISMATCH");signed.signers[0].certificate=certificate(other);assert.throws(()=>signed.verify(content),(error)=>error instanceof CmsError&&["SIGNATURE","SIGNING_CERTIFICATE"].includes(error.code));
});

test("CMS parser rejects truncation and foreign content types",()=>{
  assert.throws(()=>parseSignedData(new Uint8Array()),(error)=>error instanceof CmsError&&error.code==="MALFORMED");const foreign=encodeSequence(encodeOid("1.2.840.113549.1.7.1"));assert.throws(()=>parseSignedData(foreign),(error)=>error instanceof CmsError&&error.code==="UNSUPPORTED");
});
