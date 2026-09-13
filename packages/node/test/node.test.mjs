import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createCertificateBridgeServer, createCryptoProCertificateProvider, openPfxFile } from "@gostcrypto/node";
import { createHttpCertificateProvider } from "@gostcrypto/providers";

test("Node adapter reports filesystem errors when opening PFX",async()=>{await assert.rejects(()=>openPfxFile("Z:/definitely-missing/gostcrypto.pfx","password"),/ENOENT/);});

test("certificate bridge CLI documents options and requires explicit transport security",()=>{
  const cli=fileURLToPath(new URL("../dist/bridge-cli.js",import.meta.url));
  const help=spawnSync(process.execPath,[cli,"--help"],{encoding:"utf8"});assert.equal(help.status,0);assert.match(help.stdout,/Usage: gostcrypto-bridge/);assert.match(help.stdout,/--tls-cert/);
  const insecure=spawnSync(process.execPath,[cli],{encoding:"utf8",env:{...process.env,GOSTCRYPTO_BRIDGE_TOKEN:"x".repeat(32)}});assert.equal(insecure.status,1);assert.match(insecure.stderr,/TLS is required/);
});

test("CryptoPro provider maps Windows certificate metadata",async()=>{
  const commands=[];
  const id="sha1:AABBCCDDEEFF0011223344556677889900AABBCC";
  const provider=createCryptoProCertificateProvider({runner:async(command)=>{commands.push(command);return[{id,subject:"CN=User",issuer:"CN=CA",serialNumber:"10",validFrom:"2026-01-02T03:04:05.000Z",validTo:"2027-01-02T03:04:05.000Z",der:"AQID",hasPrivateKey:true}];}});
  assert.deepEqual(await provider.listCertificates(),[{id,subject:"CN=User",issuer:"CN=CA",serialNumber:"10",validFrom:new Date("2026-01-02T03:04:05.000Z"),validTo:new Date("2027-01-02T03:04:05.000Z"),der:Uint8Array.of(1,2,3),hasPrivateKey:true}]);
  assert.deepEqual(commands,[{operation:"list"}]);
});

test("CryptoPro provider passes binary signing input without command-line interpolation",async()=>{
  const commands=[];
  const id="sha1:AABBCCDDEEFF0011223344556677889900AABBCC";
  const provider=createCryptoProCertificateProvider({runner:async(command)=>{commands.push(command);return{signature:"BAUG"};}});
  assert.deepEqual(await provider.sign(id,Uint8Array.of(1,2,3),{algorithm:"gost3410-2012-256"}),Uint8Array.of(4,5,6));
  assert.deepEqual(commands,[{operation:"sign",certificateId:id,data:"AQID",algorithm:"gost3410-2012-256",detached:true,checkCertificate:false}]);
});

test("CryptoPro provider exposes native certificate trust validation",async()=>{
  const commands=[],id="sha1:AABBCCDDEEFF0011223344556677889900AABBCC";
  const provider=createCryptoProCertificateProvider({runner:async(command)=>{commands.push(command);return{valid:false};}});
  const result=await provider.validateCertificate(id);
  assert.equal(result.valid,false);assert.equal(result.checkedAt instanceof Date,true);
  assert.deepEqual(commands,[{operation:"validate",certificateId:id}]);
});

test("CryptoPro provider rejects malformed native responses",async()=>{
  await assert.rejects(()=>createCryptoProCertificateProvider({runner:async()=>[{id:"bad"}]}).listCertificates(),/invalid CryptoPro certificate response/);
  await assert.rejects(()=>createCryptoProCertificateProvider({runner:async()=>({signature:"!"})}).sign("sha1:AABBCCDDEEFF0011223344556677889900AABBCC",new Uint8Array(),{algorithm:"gost3410-2012-512",detached:false}),/invalid CryptoPro signature/);
  await assert.rejects(()=>createCryptoProCertificateProvider({runner:async()=>({signature:""})}).sign("sha1:AABB",new Uint8Array(),{algorithm:"gost3410-2012-256"}),/SHA-1 thumbprint/);
});

test("Node certificate bridge serves authenticated browser JSON-RPC",async(t)=>{
  const calls=[],certificate={id:"store:1",subject:"CN=User",issuer:"CN=CA",serialNumber:"01",validFrom:new Date("2026-01-01T00:00:00Z"),validTo:new Date("2027-01-01T00:00:00Z"),der:Uint8Array.of(1,2,3),hasPrivateKey:true};
  const checkedAt=new Date("2026-06-01T00:00:00Z");
  const server=createCertificateBridgeServer({async listCertificates(){return[certificate];},async sign(id,data,options){calls.push({id,data,options});return Uint8Array.of(4,5,6);},async validateCertificate(id){calls.push({validate:id});return{valid:true,checkedAt};}},{bearerToken:"secret",allowedOrigins:["https://app.example"]});
  await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);});
  t.after(()=>new Promise((resolve,reject)=>server.close((error)=>error?reject(error):resolve())));
  const address=server.address();assert.equal(typeof address,"object");const endpoint=`http://127.0.0.1:${address.port}/rpc`,provider=createHttpCertificateProvider(endpoint,{bearerToken:"secret"});
  const listed=await provider.listCertificates();assert.deepEqual(listed[0],certificate);
  assert.deepEqual(await provider.sign("store:1",Uint8Array.of(7,8),{algorithm:"gost3410-2012-256",detached:true}),Uint8Array.of(4,5,6));
  assert.deepEqual(calls[0],{id:"store:1",data:Uint8Array.of(7,8),options:{algorithm:"gost3410-2012-256",detached:true}});
  assert.deepEqual(await provider.validateCertificate("store:1"),{valid:true,checkedAt});
  assert.deepEqual(calls[1],{validate:"store:1"});
  assert.equal((await fetch(endpoint,{method:"POST"})).status,401);
  assert.equal((await fetch(endpoint,{method:"OPTIONS",headers:{origin:"https://evil.example"}})).status,403);
  const preflight=await fetch(endpoint,{method:"OPTIONS",headers:{origin:"https://app.example"}});assert.equal(preflight.status,204);assert.equal(preflight.headers.get("access-control-allow-origin"),"https://app.example");
});
