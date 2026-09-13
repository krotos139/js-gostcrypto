import { decodeOid } from "@gostcrypto/asn1";
import { signCms } from "@gostcrypto/cms";
import type { Bytes,CertificateInfo,CertificateProvider,CertificateValidationResult,SignOptions } from "@gostcrypto/core";
import { streebog256 } from "@gostcrypto/hash";
import { parsePfx,type PfxContainer,type PfxKeyEntry } from "@gostcrypto/pfx";

const hex=(value:Uint8Array)=>Array.from(value,(byte)=>byte.toString(16).padStart(2,"0")).join("");
function readDer(input:Uint8Array,offset=0):{tag:number;content:Uint8Array;full:Uint8Array;end:number}{const start=offset;if(offset+2>input.length)throw new RangeError("malformed DER");const tag=input[offset++]!;let length=input[offset++]!;if((length&128)!==0){const count=length&127;if(count===0||count>4||offset+count>input.length)throw new RangeError("malformed DER");length=0;for(let i=0;i<count;i+=1)length=length*256+input[offset++]!;}const end=offset+length;if(end>input.length)throw new RangeError("malformed DER");return{tag,content:input.subarray(offset,end),full:input.subarray(start,end),end};}
function children(content:Uint8Array){const result:ReturnType<typeof readDer>[]=[];for(let offset=0;offset<content.length;){const item=readDer(content,offset);result.push(item);offset=item.end;}return result;}
const nameOids=new Map([["2.5.4.3","CN"],["2.5.4.6","C"],["2.5.4.7","L"],["2.5.4.8","ST"],["2.5.4.10","O"],["2.5.4.11","OU"],["1.2.840.113549.1.9.1","E"]]);
function text(item:ReturnType<typeof readDer>):string {if(item.tag===0x1e){let result="";for(let i=0;i<item.content.length;i+=2)result+=String.fromCharCode(item.content[i]!*256+item.content[i+1]!);return result;}return new TextDecoder(item.tag===0x0c?"utf-8":"latin1").decode(item.content);}
function name(item:ReturnType<typeof readDer>):string {const values:string[]=[];for(const set of children(item.content))for(const attribute of children(set.content)){const fields=children(attribute.content);if(fields.length===2&&fields[0]!.tag===0x06){const attributeOid=decodeOid(fields[0]!);values.push(`${nameOids.get(attributeOid)??attributeOid}=${text(fields[1]!)}`);}}return values.join(", ");}
function time(item:ReturnType<typeof readDer>):Date {const value=new TextDecoder("ascii").decode(item.content),match=item.tag===0x17?/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value):/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value);if(match===null)throw new RangeError("unsupported certificate time");const year=item.tag===0x17?(Number(match[1])>=50?1900:2000)+Number(match[1]):Number(match[1]);return new Date(Date.UTC(year,Number(match[2])-1,Number(match[3]),Number(match[4]),Number(match[5]),Number(match[6])));}
function info(der:Uint8Array,hasPrivateKey:boolean):CertificateInfo {const certificate=children(readDer(der).content),tbs=children(certificate[0]!.content),offset=tbs[0]?.tag===0xa0?1:0,serial=tbs[offset]!,issuer=tbs[offset+2]!,validity=children(tbs[offset+3]!.content),subject=tbs[offset+4]!;return{id:hex(streebog256(der)),subject:name(subject),issuer:name(issuer),serialNumber:hex(serial.content[0]===0?serial.content.subarray(1):serial.content),validFrom:time(validity[0]!),validTo:time(validity[1]!),der:Uint8Array.from(der),hasPrivateKey};}

/** Password PFX provider. The private key lives in the JavaScript process. */
export class PfxCertificateProvider implements CertificateProvider {
  readonly #container:PfxContainer;readonly #entries:readonly {info:CertificateInfo;key?:PfxKeyEntry}[];
  constructor(container:PfxContainer){this.#container=container;this.#entries=container.certificates.map((certificate)=>{const key=container.keys.find((candidate)=>container.certificateFor(candidate)===certificate);return{info:info(certificate.certificate,key!==undefined),key};});}
  static open(der:Uint8Array,password:Uint8Array):PfxCertificateProvider{return new PfxCertificateProvider(parsePfx(der,password));}
  async listCertificates():Promise<readonly CertificateInfo[]>{return this.#entries.map((entry)=>({...entry.info,der:Uint8Array.from(entry.info.der)}));}
  async sign(certificateId:string,data:Bytes,options:SignOptions):Promise<Bytes>{const entry=this.#entries.find((item)=>item.info.id===certificateId);if(entry?.key===undefined)throw new RangeError("certificate with private key was not found");const expected=entry.key.key.curve.size===32?"gost3410-2012-256":"gost3410-2012-512";if(options.algorithm!==expected)throw new RangeError(`certificate requires ${expected}`);return signCms(data,entry.info.der,entry.key.key,{detached:options.detached??true});}
}

export type CertificateBridgeMethod="certificates.list"|"certificates.sign"|"certificates.validate";
export interface CertificateBridgeTransport {request(method:CertificateBridgeMethod,parameters:unknown):Promise<unknown>;}
export interface FetchResponseLike {readonly ok:boolean;readonly status:number;json():Promise<unknown>;}
export type FetchLike=(input:string,init:{method:string;headers:Record<string,string>;body:string;signal?:AbortSignal})=>Promise<FetchResponseLike>;
export interface HttpCertificateBridgeOptions {readonly fetch?:FetchLike;readonly bearerToken?:string;readonly timeoutMilliseconds?:number;}
/** JSON-RPC 2.0 transport for a local native agent or remote signing service. */
export class HttpCertificateBridgeTransport implements CertificateBridgeTransport {#id=0;readonly #fetch:FetchLike;constructor(private readonly endpoint:string,private readonly options:HttpCertificateBridgeOptions={}){const implementation=options.fetch??globalThis.fetch;if(implementation===undefined)throw new Error("Fetch API is unavailable");this.#fetch=implementation as FetchLike;}
  async request(method:CertificateBridgeMethod,parameters:unknown):Promise<unknown>{const id=++this.#id,controller=this.options.timeoutMilliseconds===undefined?undefined:new AbortController(),timeout=controller===undefined?undefined:setTimeout(()=>controller.abort(),this.options.timeoutMilliseconds),headers:Record<string,string>={"content-type":"application/json"};if(this.options.bearerToken!==undefined)headers.authorization=`Bearer ${this.options.bearerToken}`;try{const response=await this.#fetch(this.endpoint,{method:"POST",headers,body:JSON.stringify({jsonrpc:"2.0",id,method,params:parameters}),...(controller===undefined?{}:{signal:controller.signal})});if(!response.ok)throw new Error(`certificate bridge HTTP ${response.status}`);const payload=record(await response.json());if(payload.jsonrpc!=="2.0"||payload.id!==id)throw new TypeError("invalid certificate bridge JSON-RPC response");if(payload.error!==undefined){const error=record(payload.error),message=typeof error.message==="string"?error.message:"certificate bridge error";throw new Error(message);}if(!("result" in payload))throw new TypeError("certificate bridge response has no result");return payload.result;}finally{if(timeout!==undefined)clearTimeout(timeout);}}
}
export function createHttpCertificateProvider(endpoint:string,options:HttpCertificateBridgeOptions={}):BridgeCertificateProvider{return new BridgeCertificateProvider(new HttpCertificateBridgeTransport(endpoint,options));}
function encodeBase64(bytes:Uint8Array):string {const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";let result="";for(let i=0;i<bytes.length;i+=3){const value=bytes[i]!<<16|(bytes[i+1]??0)<<8|(bytes[i+2]??0);result+=alphabet[value>>>18&63]!+alphabet[value>>>12&63]!+(i+1<bytes.length?alphabet[value>>>6&63]!:"=")+(i+2<bytes.length?alphabet[value&63]!:"=");}return result;}
function decodeBase64(value:string):Uint8Array {const clean=value.replace(/\s/g,"");if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(clean))throw new TypeError("bridge returned invalid base64");const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",out:number[]=[];for(let i=0;i<clean.length;i+=4){const a=alphabet.indexOf(clean[i]!),b=alphabet.indexOf(clean[i+1]!),c=clean[i+2]==="="?0:alphabet.indexOf(clean[i+2]!),d=clean[i+3]==="="?0:alphabet.indexOf(clean[i+3]!);out.push(a<<2|b>>>4);if(clean[i+2]!=="=")out.push((b&15)<<4|c>>>2);if(clean[i+3]!=="=")out.push((c&3)<<6|d);}return Uint8Array.from(out);}
function record(value:unknown):Record<string,unknown>{if(value===null||typeof value!=="object"||Array.isArray(value))throw new TypeError("invalid certificate bridge response");return value as Record<string,unknown>;}
/** Provider for a native agent, CSP browser extension, or hardware-token bridge. */
export class BridgeCertificateProvider implements CertificateProvider {constructor(private readonly transport:CertificateBridgeTransport){}
  async listCertificates():Promise<readonly CertificateInfo[]>{const response=await this.transport.request("certificates.list",{});if(!Array.isArray(response))throw new TypeError("invalid certificate list response");return response.map((value)=>{const item=record(value);if(typeof item.id!=="string"||typeof item.subject!=="string"||typeof item.issuer!=="string"||typeof item.serialNumber!=="string"||typeof item.validFrom!=="string"||typeof item.validTo!=="string"||typeof item.der!=="string"||typeof item.hasPrivateKey!=="boolean")throw new TypeError("invalid certificate bridge entry");return{id:item.id,subject:item.subject,issuer:item.issuer,serialNumber:item.serialNumber,validFrom:new Date(item.validFrom),validTo:new Date(item.validTo),der:decodeBase64(item.der),hasPrivateKey:item.hasPrivateKey};});}
  async sign(certificateId:string,data:Bytes,options:SignOptions):Promise<Bytes>{const response=record(await this.transport.request("certificates.sign",{certificateId,data:encodeBase64(data),options}));if(typeof response.signature!=="string")throw new TypeError("invalid certificate bridge signature response");return decodeBase64(response.signature);}
  async validateCertificate(certificateId:string):Promise<CertificateValidationResult>{const response=record(await this.transport.request("certificates.validate",{certificateId}));if(typeof response.valid!=="boolean"||typeof response.checkedAt!=="string")throw new TypeError("invalid certificate bridge validation response");const checkedAt=new Date(response.checkedAt);if(Number.isNaN(checkedAt.valueOf()))throw new TypeError("invalid certificate bridge validation date");return{valid:response.valid,checkedAt};}
}

type CadesObject = Record<string, unknown>;
type CadesMethod = (...arguments_: unknown[]) => unknown;

export interface CryptoProBrowserPlugin {
  CreateObjectAsync(name: string): unknown;
  getLastError?(error: unknown): string;
}

export interface CryptoProBrowserProviderOptions {
  /** Defaults to `globalThis.cadesplugin`, installed by CryptoPro's browser API script. */
  readonly plugin?: unknown;
}

function cadesObject(value: unknown, label: string): CadesObject {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) throw new TypeError(`invalid CryptoPro browser ${label}`);
  return value as CadesObject;
}

async function cadesCall(object: CadesObject, method: string, ...arguments_: unknown[]): Promise<unknown> {
  const implementation = object[method];
  if (typeof implementation !== "function") throw new TypeError(`CryptoPro browser object has no ${method} method`);
  return await (implementation as CadesMethod).apply(object, arguments_);
}

async function cadesProperty(object: CadesObject, property: string): Promise<unknown> { return await object[property]; }

function cadesString(value: unknown, label: string): string {
  if (typeof value !== "string") throw new TypeError(`invalid CryptoPro browser ${label}`);
  return value;
}

function cadesDate(value: unknown, label: string): Date {
  const result = value instanceof Date ? new Date(value.valueOf()) : new Date(cadesString(value, label));
  if (Number.isNaN(result.valueOf())) throw new TypeError(`invalid CryptoPro browser ${label}`);
  return result;
}

function cadesThumbprint(value: unknown): string {
  const result = cadesString(value, "certificate thumbprint").replace(/[^0-9a-f]/gi, "").toUpperCase();
  if (!/^[0-9A-F]{40}$/.test(result)) throw new TypeError("invalid CryptoPro browser certificate thumbprint");
  return result;
}

/** Direct adapter for the official CryptoPro CAdES browser plug-in API. */
export class CryptoProBrowserCertificateProvider implements CertificateProvider {
  readonly #source: unknown;
  public constructor(options: CryptoProBrowserProviderOptions = {}) {
    this.#source = options.plugin ?? (globalThis as unknown as Record<string, unknown>).cadesplugin;
  }
  async #plugin(): Promise<CadesObject> {
    let candidate = this.#source;
    if (candidate === undefined) throw new Error("CryptoPro browser plug-in is unavailable; load cadesplugin_api.js first");
    const direct = cadesObject(candidate, "plug-in");
    if (typeof direct.CreateObjectAsync === "function") {
      // CryptoPro decorates its readiness Promise with CreateObjectAsync. The
      // Promise resolves without a value. An async function would assimilate
      // the decorated Promise again when returning it, so expose only the
      // bound plug-in methods through a plain, non-thenable facade.
      if (typeof direct.then === "function") {
        await candidate;
        const ready: CadesObject = {
          CreateObjectAsync: (...arguments_: unknown[]) => (direct.CreateObjectAsync as CadesMethod).apply(direct, arguments_),
        };
        if (typeof direct.getLastError === "function") ready.getLastError = (...arguments_: unknown[]) => (direct.getLastError as CadesMethod).apply(direct, arguments_);
        return ready;
      }
      return direct;
    }
    candidate = await candidate;
    const resolved = cadesObject(candidate, "plug-in");
    if (typeof resolved.CreateObjectAsync !== "function") throw new TypeError("CryptoPro browser plug-in has no CreateObjectAsync method");
    return resolved;
  }
  async #create(name: string): Promise<CadesObject> { return cadesObject(await cadesCall(await this.#plugin(), "CreateObjectAsync", name), name); }
  async #withError<T>(operation: () => Promise<T>): Promise<T> {
    try { return await operation(); }
    catch (error) {
      const plugin = await this.#plugin().catch(() => undefined);
      const getLastError = plugin?.getLastError;
      if (typeof getLastError === "function") {
        const message = (getLastError as CadesMethod).call(plugin, error);
        if (typeof message === "string" && message.length > 0) throw new Error(message, { cause: error });
      }
      throw error;
    }
  }
  public async listCertificates(): Promise<readonly CertificateInfo[]> {
    return this.#withError(async () => {
      const store = await this.#create("CAdESCOM.Store");
      try {
        await cadesCall(store, "Open", 2, "My", 0);
        const certificates = cadesObject(await cadesProperty(store, "Certificates"), "certificate collection");
        const count = Number(await cadesProperty(certificates, "Count"));
        if (!Number.isSafeInteger(count) || count < 0) throw new TypeError("invalid CryptoPro browser certificate count");
        const result: CertificateInfo[] = [];
        for (let index = 1; index <= count; index += 1) {
          const certificate = cadesObject(await cadesCall(certificates, "Item", index), "certificate");
          const thumbprint = cadesThumbprint(await cadesProperty(certificate, "Thumbprint"));
          const der = decodeBase64(cadesString(await cadesCall(certificate, "Export", 0), "certificate DER"));
          if (der.length === 0) throw new TypeError("invalid CryptoPro browser certificate DER");
          result.push({
            id: `sha1:${thumbprint}`,
            subject: cadesString(await cadesProperty(certificate, "SubjectName"), "certificate subject"),
            issuer: cadesString(await cadesProperty(certificate, "IssuerName"), "certificate issuer"),
            serialNumber: cadesString(await cadesProperty(certificate, "SerialNumber"), "certificate serial number"),
            validFrom: cadesDate(await cadesProperty(certificate, "ValidFromDate"), "certificate valid-from date"),
            validTo: cadesDate(await cadesProperty(certificate, "ValidToDate"), "certificate valid-to date"),
            der,
            hasPrivateKey: Boolean(await cadesCall(certificate, "HasPrivateKey")),
          });
        }
        return result;
      } finally { await cadesCall(store, "Close").catch(() => undefined); }
    });
  }
  public async validateCertificate(certificateId: string): Promise<CertificateValidationResult> {
    if (!/^sha1:[0-9a-f]{40}$/i.test(certificateId)) throw new TypeError("certificate id must be a SHA-1 thumbprint");
    return this.#withError(async () => {
      const store = await this.#create("CAdESCOM.Store");
      try {
        await cadesCall(store, "Open", 2, "My", 0);
        const certificates = cadesObject(await cadesProperty(store, "Certificates"), "certificate collection");
        const matches = cadesObject(await cadesCall(certificates, "Find", 0, certificateId.slice(5)), "matching certificates");
        const count = Number(await cadesProperty(matches, "Count"));
        if (count !== 1) throw new RangeError(`expected one CryptoPro certificate, found ${count}`);
        const certificate = cadesObject(await cadesCall(matches, "Item", 1), "certificate");
        const certificateStatus = cadesObject(await cadesCall(certificate, "IsValid"), "certificate status");
        return { valid: Boolean(await cadesProperty(certificateStatus, "Result")), checkedAt: new Date() };
      } finally { await cadesCall(store, "Close").catch(() => undefined); }
    });
  }
  public async sign(certificateId: string, data: Bytes, options: SignOptions): Promise<Bytes> {
    if (!/^sha1:[0-9a-f]{40}$/i.test(certificateId)) throw new TypeError("certificate id must be a SHA-1 thumbprint");
    if (!(data instanceof Uint8Array)) throw new TypeError("signing data must be Uint8Array");
    if (options.algorithm !== "gost3410-2012-256" && options.algorithm !== "gost3410-2012-512") throw new TypeError("unsupported signature algorithm");
    return this.#withError(async () => {
      const store = await this.#create("CAdESCOM.Store");
      try {
        await cadesCall(store, "Open", 2, "My", 0);
        const certificates = cadesObject(await cadesProperty(store, "Certificates"), "certificate collection");
        const matches = cadesObject(await cadesCall(certificates, "Find", 0, certificateId.slice(5)), "matching certificates");
        const count = Number(await cadesProperty(matches, "Count"));
        if (count !== 1) throw new RangeError(`expected one CryptoPro certificate, found ${count}`);
        const certificate = cadesObject(await cadesCall(matches, "Item", 1), "certificate");
        if (!Boolean(await cadesCall(certificate, "HasPrivateKey"))) throw new RangeError("the selected certificate has no private key");
        const publicKey = cadesObject(await cadesCall(certificate, "PublicKey"), "public key");
        const algorithm = cadesObject(await cadesProperty(publicKey, "Algorithm"), "public-key algorithm");
        const oid = cadesString(await cadesProperty(algorithm, "Value"), "public-key algorithm OID");
        const expectedOid = options.algorithm === "gost3410-2012-256" ? "1.2.643.7.1.1.1.1" : "1.2.643.7.1.1.1.2";
        if (oid !== expectedOid) throw new RangeError(`certificate algorithm ${oid} does not match requested ${options.algorithm}`);
        const signer = await this.#create("CAdESCOM.CPSigner");
        await cadesCall(signer, "propset_Certificate", certificate);
        await cadesCall(signer, "propset_Options", 2);
        if (options.checkCertificate !== undefined) await cadesCall(signer, "propset_CheckCertificate", options.checkCertificate);
        const signedData = await this.#create("CAdESCOM.CadesSignedData");
        await cadesCall(signedData, "propset_ContentEncoding", 1);
        await cadesCall(signedData, "propset_Content", encodeBase64(data));
        const signature = cadesString(await cadesCall(signedData, "SignCades", signer, 1, options.detached ?? true, 0), "signature");
        return decodeBase64(signature);
      } finally { await cadesCall(store, "Close").catch(() => undefined); }
    });
  }
}

export function createCryptoProBrowserProvider(options: CryptoProBrowserProviderOptions = {}): CryptoProBrowserCertificateProvider {
  return new CryptoProBrowserCertificateProvider(options);
}
