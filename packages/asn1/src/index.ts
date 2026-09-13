import { streebog256, streebog512 } from "@gostcrypto/hash";
import { gost341194 } from "@gostcrypto/legacy-gost341194";
import {
  RFC7091_TEST_CURVE_256, RFC9215_TEST_CURVE_512,
  TC26_PARAM_SET_256_A, TC26_PARAM_SET_256_B, TC26_PARAM_SET_256_C, TC26_PARAM_SET_256_D,
  TC26_PARAM_SET_512_A, TC26_PARAM_SET_512_B, TC26_PARAM_SET_512_C,
  createPublicKey, decodePkixSignature, encodePublicKey, verifyDigest, type GostCurve, type GostPublicKey,
} from "@gostcrypto/signature";
import { decodeOid, encodeBitString, encodeOctetString, encodeOid, encodeSequence, readDer, readDerChildren } from "./der.js";

export * from "./der.js";

export const OID = Object.freeze({
  publicKey256: "1.2.643.7.1.1.1.1", publicKey512: "1.2.643.7.1.1.1.2",
  digest256: "1.2.643.7.1.1.2.2", digest512: "1.2.643.7.1.1.2.3",
  signWithDigest256: "1.2.643.7.1.1.3.2", signWithDigest512: "1.2.643.7.1.1.3.3",
  hmac256: "1.2.643.7.1.1.4.1", hmac512: "1.2.643.7.1.1.4.2",
  cipherParamZ: "1.2.643.7.1.2.5.1.1",
  cipher28147: "1.2.643.2.2.21", cipherTestParamSet: "1.2.643.2.2.31.0",
  cipherCryptoProA: "1.2.643.2.2.31.1", cipherCryptoProB: "1.2.643.2.2.31.2",
  cipherCryptoProC: "1.2.643.2.2.31.3", cipherCryptoProD: "1.2.643.2.2.31.4",
  publicKey2001: "1.2.643.2.2.19", digest94: "1.2.643.2.2.9", signWithDigest2001: "1.2.643.2.2.3",
  hashParamCryptoPro: "1.2.643.2.2.30.1", hashParamTest: "1.2.643.2.2.30.0",
  paramSet256A: "1.2.643.7.1.2.1.1.1", paramSet256B: "1.2.643.7.1.2.1.1.2",
  paramSet256C: "1.2.643.7.1.2.1.1.3", paramSet256D: "1.2.643.7.1.2.1.1.4",
  paramSet512A: "1.2.643.7.1.2.1.2.1", paramSet512B: "1.2.643.7.1.2.1.2.2",
  paramSet512C: "1.2.643.7.1.2.1.2.3", paramSet512Test: "1.2.643.7.1.2.1.2.0",
  paramSetCryptoProTest: "1.2.643.2.2.35.0", paramSetCryptoProA: "1.2.643.2.2.35.1",
  paramSetCryptoProB: "1.2.643.2.2.35.2", paramSetCryptoProC: "1.2.643.2.2.35.3",
  paramSetCryptoProXchA: "1.2.643.2.2.36.0", paramSetCryptoProXchB: "1.2.643.2.2.36.1",
  ogrn: "1.2.643.100.1", snils: "1.2.643.100.3", innLegalEntity: "1.2.643.100.4",
  ogrnip: "1.2.643.100.5", identificationKind: "1.2.643.100.114", inn: "1.2.643.3.131.1.1",
  subjectSignTool: "1.2.643.100.111", issuerSignTool: "1.2.643.100.112",
});

const curveEntries: readonly (readonly [string, GostCurve])[] = [
  [OID.paramSet256A,TC26_PARAM_SET_256_A],[OID.paramSet256B,TC26_PARAM_SET_256_B],[OID.paramSet256C,TC26_PARAM_SET_256_C],[OID.paramSet256D,TC26_PARAM_SET_256_D],
  [OID.paramSet512A,TC26_PARAM_SET_512_A],[OID.paramSet512B,TC26_PARAM_SET_512_B],[OID.paramSet512C,TC26_PARAM_SET_512_C],[OID.paramSet512Test,RFC9215_TEST_CURVE_512],
  [OID.paramSetCryptoProTest,RFC7091_TEST_CURVE_256],[OID.paramSetCryptoProA,TC26_PARAM_SET_256_B],[OID.paramSetCryptoProB,TC26_PARAM_SET_256_C],
  [OID.paramSetCryptoProC,TC26_PARAM_SET_256_D],[OID.paramSetCryptoProXchA,TC26_PARAM_SET_256_B],[OID.paramSetCryptoProXchB,TC26_PARAM_SET_256_D],
];

export function curveByOid(oid: string): GostCurve | undefined { return curveEntries.find(([candidate])=>candidate===oid)?.[1]; }
export function oidByCurve(curve: GostCurve): string | undefined { return curveEntries.find(([,candidate])=>candidate===curve)?.[0]; }

export interface ParsedSubjectPublicKeyInfo { readonly publicKey: GostPublicKey; readonly algorithmOid: string; readonly parameterSetOid: string; readonly digestParamSetOid?: string; }

export function parseSubjectPublicKeyInfo(der: Uint8Array): ParsedSubjectPublicKeyInfo {
  const outer=readDer(der);if(outer.tag!==0x30||outer.end!==der.length)throw new RangeError("malformed SubjectPublicKeyInfo");
  const fields=readDerChildren(outer.content);if(fields.length!==2||fields[0]!.tag!==0x30||fields[1]!.tag!==0x03)throw new RangeError("malformed SubjectPublicKeyInfo");
  const algorithm=readDerChildren(fields[0]!.content);if(algorithm.length!==2||algorithm[1]!.tag!==0x30)throw new RangeError("malformed GOST algorithm parameters");
  const algorithmOid=decodeOid(algorithm[0]!);
  if(![OID.publicKey256,OID.publicKey512,OID.publicKey2001].some((candidate)=>candidate===algorithmOid))throw new RangeError("unsupported public key algorithm");
  const parameters=readDerChildren(algorithm[1]!.content);if(parameters.length<1||parameters.length>2)throw new RangeError("malformed GOST algorithm parameters");
  const parameterSetOid=decodeOid(parameters[0]!);const digestParamSetOid=parameters[1]===undefined?undefined:decodeOid(parameters[1]);
  const curve=curveByOid(parameterSetOid);if(curve===undefined)throw new RangeError("unsupported GOST curve");
  const expectedSize=algorithmOid===OID.publicKey512?64:32;if(curve.size!==expectedSize)throw new RangeError("public key algorithm and curve size differ");
  const bits=fields[1]!.content;if(bits.length<1||bits[0]!==0)throw new RangeError("malformed public key BIT STRING");
  const octets=readDer(bits.subarray(1));if(octets.tag!==0x04||octets.end!==bits.length-1||octets.content.length!==curve.size*2)throw new RangeError("malformed GOST public key");
  const raw=octets.content;let x=0n,y=0n;for(let i=curve.size-1;i>=0;i-=1){x=(x<<8n)|BigInt(raw[i]!);y=(y<<8n)|BigInt(raw[curve.size+i]!);}
  return{publicKey:createPublicKey(curve,x,y),algorithmOid,parameterSetOid,...(digestParamSetOid===undefined?{}:{digestParamSetOid})};
}

export function encodeSubjectPublicKeyInfo(publicKey: GostPublicKey): Uint8Array {
  const parameterSetOid=oidByCurve(publicKey.curve);if(parameterSetOid===undefined)throw new RangeError("curve has no registered OID");
  const legacy=parameterSetOid.startsWith("1.2.643.2.2.");
  const parameters=encodeSequence(encodeOid(parameterSetOid),...(legacy?[encodeOid(OID.digest256)]:[]));
  const algorithmOid=publicKey.curve.size===64?OID.publicKey512:OID.publicKey256;
  return encodeSequence(encodeSequence(encodeOid(algorithmOid),parameters),encodeBitString(encodeOctetString(encodePublicKey(publicKey))));
}

export function extractSubjectPublicKeyInfo(certificateDer: Uint8Array): Uint8Array {
  const certificate=readDer(certificateDer);if(certificate.tag!==0x30||certificate.end!==certificateDer.length)throw new RangeError("malformed certificate");
  const certificateFields=readDerChildren(certificate.content);if(certificateFields.length!==3||certificateFields[0]!.tag!==0x30)throw new RangeError("malformed certificate");
  const tbs=readDerChildren(certificateFields[0]!.content);const hasVersion=tbs[0]?.tag===0xa0;const index=hasVersion?6:5;
  const spki=tbs[index];if(spki?.tag!==0x30)throw new RangeError("certificate has no SubjectPublicKeyInfo");return Uint8Array.from(spki.full);
}

export interface CertificateEnvelope {
  readonly tbsCertificate: Uint8Array;
  readonly signatureAlgorithmOid: string;
  readonly signature: Uint8Array;
}

export function parseCertificateEnvelope(certificateDer: Uint8Array): CertificateEnvelope {
  const certificate=readDer(certificateDer);if(certificate.tag!==0x30||certificate.end!==certificateDer.length)throw new RangeError("malformed certificate");
  const fields=readDerChildren(certificate.content);if(fields.length!==3||fields[0]!.tag!==0x30||fields[1]!.tag!==0x30||fields[2]!.tag!==0x03)throw new RangeError("malformed certificate");
  const algorithm=readDerChildren(fields[1]!.content);if(algorithm.length<1)throw new RangeError("malformed certificate signature algorithm");
  const signatureBits=fields[2]!.content;if(signatureBits.length<1||signatureBits[0]!==0)throw new RangeError("malformed certificate signature BIT STRING");
  return{tbsCertificate:Uint8Array.from(fields[0]!.full),signatureAlgorithmOid:decodeOid(algorithm[0]!),signature:Uint8Array.from(signatureBits.subarray(1))};
}

export function publicKeyFromCertificate(certificateDer: Uint8Array): GostPublicKey {
  return parseSubjectPublicKeyInfo(extractSubjectPublicKeyInfo(certificateDer)).publicKey;
}

export function verifyCertificateSignature(certificateDer: Uint8Array, issuerPublicKey: GostPublicKey): boolean {
  try {
    const envelope=parseCertificateEnvelope(certificateDer);
    const digest=envelope.signatureAlgorithmOid===OID.signWithDigest256?streebog256(envelope.tbsCertificate):envelope.signatureAlgorithmOid===OID.signWithDigest512?streebog512(envelope.tbsCertificate):[OID.signWithDigest2001,OID.publicKey2001].some((candidate)=>candidate===envelope.signatureAlgorithmOid)?gost341194(envelope.tbsCertificate):undefined;
    if(digest===undefined||envelope.signature.length!==issuerPublicKey.curve.size*2)return false;
    return verifyDigest(issuerPublicKey,digest,decodePkixSignature(issuerPublicKey.curve,envelope.signature));
  } catch { return false; }
}

function digestForSignatureOid(oid:string,data:Uint8Array):Uint8Array|undefined{return oid===OID.signWithDigest256?streebog256(data):oid===OID.signWithDigest512?streebog512(data):[OID.signWithDigest2001,OID.publicKey2001].some((candidate)=>candidate===oid)?gost341194(data):undefined;}
export function publicKeyFromCertificateRequest(requestDer:Uint8Array):GostPublicKey{const outer=readDer(requestDer);if(outer.tag!==0x30||outer.end!==requestDer.length)throw new RangeError("malformed certificate request");const fields=readDerChildren(outer.content);if(fields.length!==3||fields[0]!.tag!==0x30)throw new RangeError("malformed certificate request");const tbs=readDerChildren(fields[0]!.content);if(tbs.length<3||tbs[2]!.tag!==0x30)throw new RangeError("certificate request has no SubjectPublicKeyInfo");return parseSubjectPublicKeyInfo(tbs[2]!.full).publicKey;}
export function verifyCertificateRequestSignature(requestDer:Uint8Array):boolean{try{const outer=readDer(requestDer),fields=readDerChildren(outer.content);if(outer.tag!==0x30||outer.end!==requestDer.length||fields.length!==3||fields[0]!.tag!==0x30||fields[1]!.tag!==0x30||fields[2]!.tag!==0x03)return false;const alg=readDerChildren(fields[1]!.content),oid=decodeOid(alg[0]!),bits=fields[2]!.content;if(bits.length<1||bits[0]!==0)return false;const key=publicKeyFromCertificateRequest(requestDer),digest=digestForSignatureOid(oid,fields[0]!.full);return digest!==undefined&&verifyDigest(key,digest,decodePkixSignature(key.curve,bits.subarray(1)));}catch{return false;}}
export function verifyCertificateRevocationListSignature(crlDer:Uint8Array,issuerPublicKey:GostPublicKey):boolean{try{const outer=readDer(crlDer),fields=readDerChildren(outer.content);if(outer.tag!==0x30||outer.end!==crlDer.length||fields.length!==3||fields[0]!.tag!==0x30||fields[1]!.tag!==0x30||fields[2]!.tag!==0x03)return false;const oid=decodeOid(readDerChildren(fields[1]!.content)[0]!),bits=fields[2]!.content,digest=digestForSignatureOid(oid,fields[0]!.full);return bits.length>0&&bits[0]===0&&digest!==undefined&&verifyDigest(issuerPublicKey,digest,decodePkixSignature(issuerPublicKey.curve,bits.subarray(1)));}catch{return false;}}

export function swapSignatureHalves(signature: Uint8Array): Uint8Array {if(signature.length===0||signature.length%2!==0)throw new RangeError("invalid signature length");const half=signature.length/2;return Uint8Array.from([...signature.subarray(half),...signature.subarray(0,half)]);}
