import assert from "node:assert/strict";
import test from "node:test";
import { OID,encodeBitString,encodeDer,encodeOid,encodeSequence,encodeSubjectPublicKeyInfo } from "@gostcrypto/asn1";
import { parseSignedData } from "@gostcrypto/cms";
import { streebog256 } from "@gostcrypto/hash";
import { marshalPfx } from "@gostcrypto/pfx";
import { BridgeCertificateProvider,CryptoProBrowserCertificateProvider,HttpCertificateBridgeTransport,PfxCertificateProvider,createCryptoProBrowserProvider,createHttpCertificateProvider } from "@gostcrypto/providers";
import { createPrivateKey,encodePkixSignature,signDigest,TC26_PARAM_SET_256_B } from "@gostcrypto/signature";

const ascii=(value)=>new TextEncoder().encode(value),integer=(value)=>encodeDer(0x02,Uint8Array.of(value)),fill=(target)=>target.fill(1);
function certificate(privateKey){const algorithm=encodeSequence(encodeOid(OID.signWithDigest256)),name=encodeSequence(encodeDer(0x31,encodeSequence(encodeOid("2.5.4.3"),encodeDer(0x0c,new TextEncoder().encode("Provider Test"))))),validity=encodeSequence(encodeDer(0x17,ascii("260101000000Z")),encodeDer(0x17,ascii("360101000000Z"))),tbs=encodeSequence(encodeDer(0xa0,integer(2)),integer(42),algorithm,name,validity,name,encodeSubjectPublicKeyInfo(privateKey.publicKey)),signature=encodePkixSignature(privateKey.curve,signDigest(privateKey,streebog256(tbs),fill));return encodeSequence(tbs,algorithm,encodeBitString(signature));}

test("PFX certificate provider lists metadata and creates detached CMS",async()=>{const key=createPrivateKey(TC26_PARAM_SET_256_B,123n),cert=certificate(key),password=ascii("secret"),provider=PfxCertificateProvider.open(marshalPfx(key,[cert],password,{iterations:2,fillRandom:fill}),password),certificates=await provider.listCertificates();assert.equal(certificates.length,1);assert.equal(certificates[0].subject,"CN=Provider Test");assert.equal(certificates[0].issuer,"CN=Provider Test");assert.equal(certificates[0].serialNumber,"2a");assert.equal(certificates[0].hasPrivateKey,true);const content=ascii("document"),signature=await provider.sign(certificates[0].id,content,{algorithm:"gost3410-2012-256",detached:true});const signed=parseSignedData(signature);assert.equal(signed.detached,true);signed.verify(content);await assert.rejects(()=>provider.sign(certificates[0].id,content,{algorithm:"gost3410-2012-512"}),/requires/);});

test("bridge certificate provider validates and translates JSON messages",async()=>{const calls=[];const provider=new BridgeCertificateProvider({async request(method,parameters){calls.push({method,parameters});if(method==="certificates.list")return[{id:"store:1",subject:"CN=User",issuer:"CN=CA",serialNumber:"01",validFrom:"2026-01-01T00:00:00Z",validTo:"2027-01-01T00:00:00Z",der:Buffer.from([1,2,3]).toString("base64"),hasPrivateKey:true}];if(method==="certificates.validate")return{valid:true,checkedAt:"2026-06-01T00:00:00Z"};return{signature:Buffer.from([4,5,6]).toString("base64")};}});const listed=await provider.listCertificates();assert.deepEqual(listed[0].der,Uint8Array.of(1,2,3));assert.equal(listed[0].validFrom instanceof Date,true);const signature=await provider.sign("store:1",Uint8Array.of(7,8),{algorithm:"gost3410-2012-256",detached:true,checkCertificate:true});assert.deepEqual(signature,Uint8Array.of(4,5,6));assert.deepEqual(calls[1].parameters.data,"Bwg=");assert.deepEqual(await provider.validateCertificate("store:1"),{valid:true,checkedAt:new Date("2026-06-01T00:00:00Z")});});

test("bridge certificate provider rejects malformed agent responses",async()=>{const provider=new BridgeCertificateProvider({async request(){return{unexpected:true};}});await assert.rejects(()=>provider.listCertificates(),/invalid certificate list/);await assert.rejects(()=>provider.sign("id",new Uint8Array(),{algorithm:"gost3410-2012-256"}),/signature response/);});
test("HTTP bridge uses authenticated JSON-RPC and validates responses",async()=>{const calls=[],transport=new HttpCertificateBridgeTransport("https://127.0.0.1:19443/rpc",{bearerToken:"token",fetch:async(input,init)=>{calls.push({input,init});const request=JSON.parse(init.body);return{ok:true,status:200,async json(){return{jsonrpc:"2.0",id:request.id,result:[]};}};}});assert.deepEqual(await transport.request("certificates.list",{}),[]);assert.equal(calls[0].init.headers.authorization,"Bearer token");assert.equal(JSON.parse(calls[0].init.body).method,"certificates.list");assert.equal(createHttpCertificateProvider("https://localhost",{fetch:async()=>({ok:true,status:200,async json(){return{jsonrpc:"2.0",id:1,result:[]};}})}) instanceof BridgeCertificateProvider,true);const failing=new HttpCertificateBridgeTransport("https://localhost",{fetch:async()=>({ok:false,status:503,async json(){return{};}})});await assert.rejects(()=>failing.request("certificates.list",{}),/HTTP 503/);});

function fakeCryptoProPlugin() {
  const calls=[],thumbprint="AABBCCDDEEFF0011223344556677889900AABBCC";
  const certificate={
    Thumbprint:Promise.resolve(thumbprint),SubjectName:Promise.resolve("CN=Browser User"),IssuerName:Promise.resolve("CN=Browser CA"),SerialNumber:Promise.resolve("10"),ValidFromDate:Promise.resolve("2026-01-02T03:04:05.000Z"),ValidToDate:Promise.resolve("2027-01-02T03:04:05.000Z"),
    async Export(encoding){calls.push(["Export",encoding]);return"AQID";},async HasPrivateKey(){return true;},async PublicKey(){return{Algorithm:Promise.resolve({Value:Promise.resolve("1.2.643.7.1.1.1.1")})};},async IsValid(){calls.push(["IsValid"]);return{Result:Promise.resolve(true)};},
  };
  const collection={Count:Promise.resolve(1),async Item(index){calls.push(["Item",index]);return certificate;},async Find(kind,value){calls.push(["Find",kind,value]);return this;}};
  const store={Certificates:Promise.resolve(collection),async Open(...args){calls.push(["Open",...args]);},async Close(){calls.push(["Close"]);}};
  const signer={async propset_Certificate(value){calls.push(["Certificate",value]);},async propset_Options(value){calls.push(["Options",value]);},async propset_CheckCertificate(value){calls.push(["CheckCertificate",value]);}};
  const signedData={async propset_ContentEncoding(value){calls.push(["ContentEncoding",value]);},async propset_Content(value){calls.push(["Content",value]);},async SignCades(...args){calls.push(["SignCades",...args]);return"BAUG";}};
  const plugin={async CreateObjectAsync(name){calls.push(["Create",name]);if(name==="CAdESCOM.Store")return store;if(name==="CAdESCOM.CPSigner")return signer;if(name==="CAdESCOM.CadesSignedData")return signedData;throw new Error("unknown object");}};
  return{plugin,calls,thumbprint};
}

test("CryptoPro browser provider lists the current-user certificate store",async()=>{
  const {plugin,calls,thumbprint}=fakeCryptoProPlugin(),provider=createCryptoProBrowserProvider({plugin:Promise.resolve(plugin)});
  assert.equal(provider instanceof CryptoProBrowserCertificateProvider,true);
  const certificates=await provider.listCertificates();
  assert.deepEqual(certificates,[{id:`sha1:${thumbprint}`,subject:"CN=Browser User",issuer:"CN=Browser CA",serialNumber:"10",validFrom:new Date("2026-01-02T03:04:05.000Z"),validTo:new Date("2027-01-02T03:04:05.000Z"),der:Uint8Array.of(1,2,3),hasPrivateKey:true}]);
  assert.deepEqual(calls.filter(([name])=>name==="Open"||name==="Close"),[["Open",2,"My",0],["Close"]]);
});

test("CryptoPro browser provider creates detached CAdES-BES",async()=>{
  const {plugin,calls,thumbprint}=fakeCryptoProPlugin(),provider=createCryptoProBrowserProvider({plugin});
  assert.deepEqual(await provider.sign(`sha1:${thumbprint}`,Uint8Array.of(1,2,3),{algorithm:"gost3410-2012-256",checkCertificate:true}),Uint8Array.of(4,5,6));
  assert.deepEqual(calls.find(([name])=>name==="Find"),["Find",0,thumbprint]);
  assert.deepEqual(calls.find(([name])=>name==="Content"),["Content","AQID"]);
  const signCall=calls.find(([name])=>name==="SignCades");assert.equal(signCall[2],1);assert.equal(signCall[3],true);assert.equal(signCall[4],0);
  assert.deepEqual(calls.find(([name])=>name==="CheckCertificate"),["CheckCertificate",true]);
});

test("CryptoPro browser provider checks certificate trust through CAdESCOM",async()=>{
  const {plugin,calls,thumbprint}=fakeCryptoProPlugin(),provider=createCryptoProBrowserProvider({plugin});
  const result=await provider.validateCertificate(`sha1:${thumbprint}`);
  assert.equal(result.valid,true);assert.equal(result.checkedAt instanceof Date,true);
  assert.equal(calls.some(([name])=>name==="IsValid"),true);
});

test("CryptoPro browser provider waits for the vendor readiness promise",async()=>{
  const {plugin,calls}=fakeCryptoProPlugin();let ready=false,resolveReady;
  const vendorPromise=new Promise((resolve)=>{resolveReady=resolve;});
  vendorPromise.CreateObjectAsync=(name)=>{if(!ready)throw new Error("plug-in is not ready");return plugin.CreateObjectAsync(name);};
  queueMicrotask(()=>{ready=true;resolveReady();});
  const certificates=await createCryptoProBrowserProvider({plugin:vendorPromise}).listCertificates();
  assert.equal(certificates.length,1);
  assert.equal(calls.some(([name])=>name==="Create"),true);
});

test("CryptoPro browser provider exposes plug-in errors and validates certificate algorithms",async()=>{
  const broken={async CreateObjectAsync(){throw new Error("raw");},getLastError(){return"CryptoPro failure 0x80090016";}};
  await assert.rejects(()=>createCryptoProBrowserProvider({plugin:broken}).listCertificates(),/CryptoPro failure/);
  const {plugin,thumbprint}=fakeCryptoProPlugin();
  await assert.rejects(()=>createCryptoProBrowserProvider({plugin}).sign(`sha1:${thumbprint}`,new Uint8Array(),{algorithm:"gost3410-2012-512"}),/does not match/);
});
