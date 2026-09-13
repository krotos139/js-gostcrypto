import { performance } from "node:perf_hooks";
import { KuznyechikCipher, MagmaCipher } from "../packages/ciphers/dist/index.js";
import { streebog256, streebog512 } from "../packages/hash/dist/index.js";
import { Mgm } from "../packages/mgm/dist/index.js";
import { TC26_PARAM_SET_256_B, createPrivateKey, signDigestWithK, verifyDigest } from "../packages/signature/dist/index.js";

function elapsed(action) { const started=performance.now();action();return performance.now()-started; }
function rate(bytes,milliseconds) { return bytes/1048576/(milliseconds/1000); }
const rows=[];

const hashInput=new Uint8Array(64*1024);for(let index=0;index<2;index+=1)streebog256(hashInput);
let milliseconds=elapsed(()=>{for(let index=0;index<16;index+=1)streebog256(hashInput);});
rows.push({operation:"Streebog-256",result:`${rate(hashInput.length*16,milliseconds).toFixed(2)} MiB/s`});
for(let index=0;index<2;index+=1)streebog512(hashInput);
milliseconds=elapsed(()=>{for(let index=0;index<16;index+=1)streebog512(hashInput);});
rows.push({operation:"Streebog-512",result:`${rate(hashInput.length*16,milliseconds).toFixed(2)} MiB/s`});

for(const [name,cipher,count] of [["Kuznyechik",new KuznyechikCipher(new Uint8Array(32)),100000],["Magma",new MagmaCipher(new Uint8Array(32)),200000]]){
  let block=new Uint8Array(cipher.blockSize);for(let index=0;index<2000;index+=1)block=cipher.encryptBlock(block);
  milliseconds=elapsed(()=>{for(let index=0;index<count;index+=1)block=cipher.encryptBlock(block);});
  rows.push({operation:`${name} encrypt`,result:`${rate(count*cipher.blockSize,milliseconds).toFixed(2)} MiB/s`});
  milliseconds=elapsed(()=>{for(let index=0;index<count;index+=1)block=cipher.decryptBlock(block);});
  rows.push({operation:`${name} decrypt`,result:`${rate(count*cipher.blockSize,milliseconds).toFixed(2)} MiB/s`});
}

const key=createPrivateKey(TC26_PARAM_SET_256_B,123456789n),digest=new Uint8Array(32),signingNonce=987654321n,signature=signDigestWithK(key,digest,signingNonce);
milliseconds=elapsed(()=>{for(let index=0;index<50;index+=1)signDigestWithK(key,digest,signingNonce+BigInt(index));});
rows.push({operation:"GOST 34.10 sign 256",result:`${(milliseconds/50).toFixed(2)} ms/op`});
milliseconds=elapsed(()=>{for(let index=0;index<20;index+=1)verifyDigest(key.publicKey,digest,signature);});
rows.push({operation:"GOST 34.10 verify 256",result:`${(milliseconds/20).toFixed(2)} ms/op`});

const mgmInput=new Uint8Array(64*1024),mgm=new Mgm(new KuznyechikCipher(new Uint8Array(32))),mgmNonce=new Uint8Array(16);mgm.seal(mgmNonce,mgmInput);
milliseconds=elapsed(()=>{for(let index=0;index<8;index+=1)mgm.seal(mgmNonce,mgmInput);});
rows.push({operation:"MGM Kuznyechik seal",result:`${rate(mgmInput.length*8,milliseconds).toFixed(2)} MiB/s`});

console.table(rows);
