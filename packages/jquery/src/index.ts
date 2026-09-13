import type { Bytes,CertificateProvider,SignOptions } from "@gostcrypto/core";
export interface JQueryGostCrypto {readonly provider:CertificateProvider;listCertificates:CertificateProvider["listCertificates"];sign(certificateId:string,data:Bytes,options:SignOptions):Promise<Bytes>;}
export interface JQueryStaticLike {gostCrypto?:JQueryGostCrypto;}
/** Installs `$.gostCrypto` without coupling the cryptographic core to jQuery. */
export function installGostCrypto($:JQueryStaticLike,provider:CertificateProvider):JQueryGostCrypto {const api:JQueryGostCrypto={provider,listCertificates:()=>provider.listCertificates(),sign:(certificateId,data,options)=>provider.sign(certificateId,data,options)};$.gostCrypto=api;return api;}
