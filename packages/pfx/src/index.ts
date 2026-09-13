import { OID, decodeOid, encodeDer, encodeOctetString, encodeOid, encodeSequence, publicKeyFromCertificate, readDer, readDerChildren, type DerElement } from "@gostcrypto/asn1";
import { encryptCms, parseEnvelopedData, parseSignedData, signCms } from "@gostcrypto/cms";
import { hmacStreebog512, pbkdf2Streebog512 } from "@gostcrypto/kdf";
import { decryptPbes2, encodeEncryptedPrivateKeyInfo, encodePrivateKeyInfo, encryptPbes2, parseEncryptedPrivateKeyInfo, parsePrivateKeyInfo, type EncryptPrivateKeyOptions } from "@gostcrypto/pkcs8";
import type { GostPrivateKey, RandomFill } from "@gostcrypto/signature";

const DATA_OID="1.2.840.113549.1.7.1",ENCRYPTED_DATA_OID="1.2.840.113549.1.7.6",ENVELOPED_DATA_OID="1.2.840.113549.1.7.3";
const KEY_BAG_OID="1.2.840.113549.1.12.10.1.1",SHROUDED_KEY_BAG_OID="1.2.840.113549.1.12.10.1.2",CERT_BAG_OID="1.2.840.113549.1.12.10.1.3";
const X509_CERTIFICATE_OID="1.2.840.113549.1.9.22.1",FRIENDLY_NAME_OID="1.2.840.113549.1.9.20",LOCAL_KEY_ID_OID="1.2.840.113549.1.9.21";

export class PfxError extends Error {
  constructor(public readonly code:"MALFORMED"|"UNSUPPORTED"|"MAC"|"NO_KEY"|"NO_RECIPIENTS"|"NO_SENDER",message:string){super(message);this.name="PfxError";}
}

export interface PfxKeyEntry {readonly key:GostPrivateKey;readonly localKeyId:Uint8Array;readonly friendlyName?:string;readonly encrypted:boolean;}
export interface PfxCertificateEntry {readonly certificate:Uint8Array;readonly localKeyId:Uint8Array;readonly friendlyName?:string;}

function bytesEqual(left:Uint8Array,right:Uint8Array):boolean {if(left.length!==right.length)return false;let difference=0;for(let i=0;i<left.length;i+=1)difference|=left[i]!^right[i]!;return difference===0;}

export class PfxContainer {
  constructor(public readonly keys:PfxKeyEntry[],public readonly certificates:PfxCertificateEntry[],public readonly hasMac:boolean,public readonly skippedSections:number,public readonly signers:Uint8Array[]=[]){ }
  certificateFor(key:PfxKeyEntry):PfxCertificateEntry|undefined {
    if(key.localKeyId.length>0){const match=this.certificates.find((item)=>item.localKeyId.length>0&&bytesEqual(item.localKeyId,key.localKeyId));if(match!==undefined)return match;}
    for(const certificate of this.certificates){try{const publicKey=publicKeyFromCertificate(certificate.certificate);if(publicKey.x===key.key.publicKey.x&&publicKey.y===key.key.publicKey.y&&publicKey.curve.size===key.key.curve.size)return certificate;}catch{/* Ignore unrelated or unsupported certificates. */}}
    return undefined;
  }
}

function integer(element:DerElement):number {if(element.tag!==0x02||element.content.length===0||(element.content[0]!&0x80)!==0)throw malformed();let result=0;for(const byte of element.content)result=result*256+byte;if(!Number.isSafeInteger(result))throw malformed();return result;}
function encodeInteger(value:number):Uint8Array {if(!Number.isSafeInteger(value)||value<0)throw new RangeError("invalid integer");const bytes:number[]=[];do{bytes.unshift(value&255);value=Math.floor(value/256);}while(value>0);if((bytes[0]!&0x80)!==0)bytes.unshift(0);return encodeDer(0x02,Uint8Array.from(bytes));}
function malformed():PfxError{return new PfxError("MALFORMED","malformed PFX container");}
function unsupported():PfxError{return new PfxError("UNSUPPORTED","unsupported PFX container variant");}
function sequence(der:Uint8Array):DerElement[]{const outer=readDer(der);if(outer.tag!==0x30||outer.end!==der.length)throw malformed();return readDerChildren(outer.content);}
function contentInfo(element:DerElement):{oid:string;content?:DerElement}{if(element.tag!==0x30)throw malformed();const fields=readDerChildren(element.content);if(fields.length<1||fields.length>2||fields[0]!.tag!==0x06||fields[1]?.tag!==0xa0)throw malformed();return{oid:decodeOid(fields[0]!),...(fields[1]===undefined?{}:{content:fields[1]})};}
function explicitOctets(element:DerElement|undefined):Uint8Array {if(element?.tag!==0xa0)throw malformed();const value=readDer(element.content);if(value.tag!==0x04||value.end!==element.content.length)throw malformed();return Uint8Array.from(value.content);}
function macKey(password:Uint8Array,salt:Uint8Array,iterations:number):Uint8Array{return pbkdf2Streebog512(password,salt,iterations,96).subarray(64);}

function verifyMac(mac:DerElement,authSafe:Uint8Array,password:Uint8Array):void {
  if(mac.tag!==0x30)throw malformed();const fields=readDerChildren(mac.content);if(fields.length<2||fields.length>3||fields[0]!.tag!==0x30||fields[1]!.tag!==0x04)throw malformed();
  const digestInfo=readDerChildren(fields[0]!.content);if(digestInfo.length!==2||digestInfo[0]!.tag!==0x30||digestInfo[1]!.tag!==0x04)throw malformed();
  const algorithm=readDerChildren(digestInfo[0]!.content);if(algorithm.length<1||decodeOid(algorithm[0]!)!==OID.digest512)throw unsupported();
  const iterations=fields[2]===undefined?1:integer(fields[2]);if(iterations<=0)throw malformed();
  const expected=hmacStreebog512(macKey(password,fields[1]!.content,iterations),authSafe);if(!bytesEqual(expected,digestInfo[1]!.content))throw new PfxError("MAC","PFX MAC verification failed");
}

function attributes(element:DerElement|undefined):{localKeyId:Uint8Array;friendlyName?:string}{
  let localKeyId=new Uint8Array(),friendlyName:string|undefined;if(element===undefined)return{localKeyId};if(element.tag!==0x31)throw malformed();
  for(const attribute of readDerChildren(element.content)){if(attribute.tag!==0x30)throw malformed();const fields=readDerChildren(attribute.content);if(fields.length!==2||fields[0]!.tag!==0x06||fields[1]!.tag!==0x31)throw malformed();const oid=decodeOid(fields[0]!),values=readDerChildren(fields[1]!.content);if(values.length===0)continue;
    if(oid===LOCAL_KEY_ID_OID&&values[0]!.tag===0x04)localKeyId=Uint8Array.from(values[0]!.content);
    if(oid===FRIENDLY_NAME_OID&&values[0]!.tag===0x1e){const value=values[0]!.content;if(value.length%2===0){let text="";for(let i=0;i<value.length;i+=2)text+=String.fromCharCode(value[i]!*256+value[i+1]!);friendlyName=text;}}
  }
  return{localKeyId,...(friendlyName===undefined?{}:{friendlyName})};
}

function addBags(raw:Uint8Array,password:Uint8Array|undefined,keys:PfxKeyEntry[],certificates:PfxCertificateEntry[]):void {
  const bags=sequence(raw);for(const bag of bags){if(bag.tag!==0x30)throw malformed();const fields=readDerChildren(bag.content);if(fields.length<2||fields.length>3||fields[0]!.tag!==0x06||fields[1]!.tag!==0xa0)throw malformed();const oid=decodeOid(fields[0]!),attrs=attributes(fields[2]);
    if(oid===KEY_BAG_OID){keys.push({key:parsePrivateKeyInfo(fields[1]!.content),...attrs,encrypted:false});continue;}
    if(oid===SHROUDED_KEY_BAG_OID){if(password===undefined)throw unsupported();keys.push({key:parseEncryptedPrivateKeyInfo(fields[1]!.content,password),...attrs,encrypted:true});continue;}
    if(oid===CERT_BAG_OID){const certFields=sequence(fields[1]!.content);if(certFields.length!==2||decodeOid(certFields[0]!)!==X509_CERTIFICATE_OID||certFields[1]!.tag!==0xa0)continue;certificates.push({certificate:explicitOctets(certFields[1]),...attrs});}
  }
}

function sectionPayload(section:DerElement,password:Uint8Array):Uint8Array|undefined {
  const info=contentInfo(section);if(info.oid===DATA_OID)return explicitOctets(info.content);if(info.oid===ENVELOPED_DATA_OID)return undefined;if(info.oid!==ENCRYPTED_DATA_OID) return undefined;
  if(info.content===undefined)throw malformed();const encrypted=sequence(info.content.content);if(encrypted.length!==2||integer(encrypted[0]!)!==0||encrypted[1]!.tag!==0x30)throw malformed();const content=readDerChildren(encrypted[1]!.content);if(content.length!==3||decodeOid(content[0]!)!==DATA_OID||content[1]!.tag!==0x30||content[2]!.tag!==0x80)throw malformed();return decryptPbes2(content[1]!.full,content[2]!.content,password);
}

export function parsePfx(der:Uint8Array,password:Uint8Array):PfxContainer {
  try {const fields=sequence(der);if(fields.length<2||fields.length>3||integer(fields[0]!)!==3)throw unsupported();const authSafeInfo=contentInfo(fields[1]!);if(authSafeInfo.oid!==DATA_OID)throw unsupported();const authSafe=explicitOctets(authSafeInfo.content);let hasMac=false;if(fields[2]!==undefined){verifyMac(fields[2],authSafe,password);hasMac=true;}
    const keys:PfxKeyEntry[]=[],certificates:PfxCertificateEntry[]=[];let skippedSections=0;for(const section of sequence(authSafe)){const payload=sectionPayload(section,password);if(payload===undefined){skippedSections+=1;continue;}addBags(payload,password,keys,certificates);}return new PfxContainer(keys,certificates,hasMac,skippedSections);
  } catch(error){if(error instanceof PfxError)throw error;throw malformed();}
}

export function decodePfx(der:Uint8Array,password:Uint8Array):{key:GostPrivateKey;certificate?:Uint8Array}{const container=parsePfx(der,password);const entry=container.keys[0];if(entry===undefined)throw new PfxError("NO_KEY","PFX container contains no private key");const certificate=container.certificateFor(entry)?.certificate;return{key:entry.key,...(certificate===undefined?{}:{certificate})};}

export interface MarshalPfxOptions {readonly iterations?:number;readonly plainCertificates?:boolean;readonly keyOptions?:EncryptPrivateKeyOptions;readonly localKeyId?:Uint8Array;readonly friendlyName?:string;readonly signingTime?:Date;readonly fillRandom?:RandomFill;}
function randomBytes(size:number,fill?:RandomFill):Uint8Array {const result=new Uint8Array(size);if(fill!==undefined)fill(result);else{if(globalThis.crypto===undefined)throw new Error("Web Crypto getRandomValues is unavailable");globalThis.crypto.getRandomValues(result);}return result;}
function encodeBmp(value:string):Uint8Array {const bytes=new Uint8Array(value.length*2);for(let i=0;i<value.length;i+=1){const unit=value.charCodeAt(i);bytes[i*2]=unit>>>8;bytes[i*2+1]=unit&255;}return encodeDer(0x1e,bytes);}
function encodeAttribute(oid:string,value:Uint8Array):Uint8Array{return encodeSequence(encodeOid(oid),encodeDer(0x31,value));}
function encodeBag(oid:string,value:Uint8Array,localKeyId?:Uint8Array,friendlyName?:string):Uint8Array {const attrs:Uint8Array[]=[];if(localKeyId!==undefined&&localKeyId.length>0)attrs.push(encodeAttribute(LOCAL_KEY_ID_OID,encodeOctetString(localKeyId)));if(friendlyName!==undefined)attrs.push(encodeAttribute(FRIENDLY_NAME_OID,encodeBmp(friendlyName)));return encodeSequence(encodeOid(oid),encodeDer(0xa0,value),...(attrs.length===0?[]:[encodeDer(0x31,Uint8Array.from(attrs.flatMap((item)=>[...item])))]));}
function dataSection(safeContents:Uint8Array):Uint8Array{return encodeSequence(encodeOid(DATA_OID),encodeDer(0xa0,encodeOctetString(safeContents)));}
function encryptedSection(safeContents:Uint8Array,password:Uint8Array,options:EncryptPrivateKeyOptions):Uint8Array {const encrypted=encryptPbes2(safeContents,password,{...options,saltSize:32});const eci=encodeSequence(encodeOid(DATA_OID),encrypted.algorithmIdentifier,encodeDer(0x80,encrypted.encryptedData));return encodeSequence(encodeOid(ENCRYPTED_DATA_OID),encodeDer(0xa0,encodeSequence(encodeInteger(0),eci)));}

export function marshalPfx(privateKey:GostPrivateKey,certificates:readonly Uint8Array[],password:Uint8Array,options:MarshalPfxOptions={}):Uint8Array {
  const iterations=options.iterations??2000;if(!Number.isSafeInteger(iterations)||iterations<=0)throw new RangeError("iterations must be positive");const fill=options.fillRandom??options.keyOptions?.fillRandom;const localKeyId=options.localKeyId===undefined||options.localKeyId.length===0?randomBytes(20,fill):Uint8Array.from(options.localKeyId);
  const keyOptions:EncryptPrivateKeyOptions={...options.keyOptions,iterations,fillRandom:fill};const shrouded=encodeEncryptedPrivateKeyInfo(privateKey,password,keyOptions);const sections=[dataSection(encodeSequence(encodeBag(SHROUDED_KEY_BAG_OID,shrouded,localKeyId,options.friendlyName)))];
  if(certificates.length>0){const bags=certificates.map((certificate,index)=>encodeBag(CERT_BAG_OID,encodeSequence(encodeOid(X509_CERTIFICATE_OID),encodeDer(0xa0,encodeOctetString(certificate))),index===0?localKeyId:undefined,index===0?options.friendlyName:undefined));const contents=encodeSequence(...bags);sections.push(options.plainCertificates===true?dataSection(contents):encryptedSection(contents,password,{iterations,parameterSetOid:keyOptions.parameterSetOid,fillRandom:fill}));}
  const authSafe=encodeSequence(...sections),macSalt=randomBytes(32,fill),digest=hmacStreebog512(macKey(password,macSalt,iterations),authSafe);const digestInfo=encodeSequence(encodeSequence(encodeOid(OID.digest512)),encodeOctetString(digest));const macData=encodeSequence(digestInfo,encodeOctetString(macSalt),encodeInteger(iterations));return encodeSequence(encodeInteger(3),dataSection(authSafe),macData);
}

export function marshalPlainKeyBag(privateKey:GostPrivateKey,localKeyId?:Uint8Array):Uint8Array{return encodeBag(KEY_BAG_OID,encodePrivateKeyInfo(privateKey),localKeyId);}

export interface PfxRecipient {readonly key:GostPrivateKey;readonly certificate:Uint8Array;}
export interface PfxSender {readonly key:GostPrivateKey;readonly certificate:Uint8Array;}
function keySectionPayload(section:DerElement,recipient:PfxRecipient):Uint8Array|undefined {const info=contentInfo(section);if(info.oid===DATA_OID)return explicitOctets(info.content);if(info.oid!==ENVELOPED_DATA_OID)return undefined;return parseEnvelopedData(section.full).decrypt(recipient.key,recipient.certificate);}

export function parsePfxWithKey(der:Uint8Array,recipient:PfxRecipient):PfxContainer {
  if(recipient?.key===undefined)throw new PfxError("NO_KEY","recipient private key is required");
  try{const fields=sequence(der);if(fields.length<2||fields.length>3||integer(fields[0]!)!==3)throw unsupported();const info=contentInfo(fields[1]!);if(info.oid!=="1.2.840.113549.1.7.2")throw unsupported();if(fields.length!==2)throw malformed();const signed=parseSignedData(fields[1]!.full);if(signed.detached||signed.content.length===0)throw malformed();signed.verify();const keys:PfxKeyEntry[]=[],certificates:PfxCertificateEntry[]=[];let skippedSections=0;for(const section of sequence(signed.content)){const payload=keySectionPayload(section,recipient);if(payload===undefined){skippedSections+=1;continue;}addBags(payload,undefined,keys,certificates);}const signers=signed.signers.flatMap((signer)=>signer.certificate===undefined?[]:[Uint8Array.from(signer.certificate)]);return new PfxContainer(keys,certificates,false,skippedSections,signers);}catch(error){if(error instanceof PfxError)throw error;throw error;}
}

export function decodePfxWithKey(der:Uint8Array,recipient:PfxRecipient):{key:GostPrivateKey;certificate?:Uint8Array}{const container=parsePfxWithKey(der,recipient),entry=container.keys[0];if(entry===undefined)throw new PfxError("NO_KEY","PFX container contains no private key");const certificate=container.certificateFor(entry)?.certificate;return{key:entry.key,...(certificate===undefined?{}:{certificate})};}

export function marshalPfxWithKey(privateKey:GostPrivateKey,certificates:readonly Uint8Array[],recipientCertificates:readonly Uint8Array[],sender:PfxSender,options:MarshalPfxOptions={}):Uint8Array {
  if(privateKey===undefined)throw new PfxError("NO_KEY","private key is required");if(recipientCertificates.length===0)throw new PfxError("NO_RECIPIENTS","at least one recipient is required");if(sender?.key===undefined||sender.certificate===undefined)throw new PfxError("NO_SENDER","sender key and certificate are required");const fill=options.fillRandom??options.keyOptions?.fillRandom,localKeyId=options.localKeyId===undefined||options.localKeyId.length===0?randomBytes(20,fill):Uint8Array.from(options.localKeyId),plainKey=encodePrivateKeyInfo(privateKey,{masks:options.keyOptions?.masks,fillRandom:fill}),keyContents=encodeSequence(encodeBag(KEY_BAG_OID,plainKey,localKeyId,options.friendlyName)),sections=[encryptCms(keyContents,recipientCertificates,{fillRandom:fill})];
  if(certificates.length>0){const certBags=certificates.map((certificate,index)=>encodeBag(CERT_BAG_OID,encodeSequence(encodeOid(X509_CERTIFICATE_OID),encodeDer(0xa0,encodeOctetString(certificate))),index===0?localKeyId:undefined,index===0?options.friendlyName:undefined)),contents=encodeSequence(...certBags);sections.push(options.plainCertificates===true?dataSection(contents):encryptCms(contents,recipientCertificates,{fillRandom:fill}));}
  const authSafe=encodeSequence(...sections),signed=signCms(authSafe,sender.certificate,sender.key,{signingTime:options.signingTime,fillRandom:fill});return encodeSequence(encodeInteger(3),signed);
}
