import { streebog256, streebog512 } from "@gostcrypto/hash";

export interface GostCurve { readonly name:string; readonly p:bigint; readonly a:bigint; readonly b:bigint; readonly m:bigint; readonly q:bigint; readonly gx:bigint; readonly gy:bigint; readonly size:32|64; }
export interface GostPoint { readonly x:bigint; readonly y:bigint; }
export interface GostPrivateKey { readonly curve:GostCurve; readonly d:bigint; readonly publicKey:GostPublicKey; }
export interface GostPublicKey extends GostPoint { readonly curve:GostCurve; }
export interface GostSignature { readonly r:bigint; readonly s:bigint; }

const mod=(value:bigint,p:bigint):bigint=>{const r=value%p;return r<0n?r+p:r;};
function inverse(value:bigint,p:bigint):bigint { let a=mod(value,p),b=p,x=1n,y=0n; while(b!==0n){const q=a/b;[a,b]=[b,a%b];[x,y]=[y,x-q*y];} if(a!==1n)throw new RangeError("value has no modular inverse"); return mod(x,p); }
interface ProjectivePoint { readonly x:bigint;readonly y:bigint;readonly z:bigint; }
const infinity:ProjectivePoint={x:0n,y:1n,z:0n};
const projective=(point:GostPoint):ProjectivePoint=>({x:point.x,y:point.y,z:1n});

// Jacobian formulas minimize expensive BigInt modular reductions in JS.
// The native Go implementation uses complete RCB formulas over fixed limbs;
// copying those literally is slower here and cannot make JS BigInt constant-time.
function projectiveDouble(curve:GostCurve,point:ProjectivePoint):ProjectivePoint {
  if(point.z===0n||point.y===0n)return infinity;const p=curve.p,xx=mod(point.x*point.x,p),yy=mod(point.y*point.y,p),yyyy=mod(yy*yy,p),zz=mod(point.z*point.z,p),s=mod(2n*(mod((point.x+yy)*(point.x+yy),p)-xx-yyyy),p),m=mod(3n*xx+curve.a*mod(zz*zz,p),p),x=mod(m*m-2n*s,p),y=mod(m*(s-x)-8n*yyyy,p),z=mod((point.y+point.z)*(point.y+point.z)-yy-zz,p);return{x,y,z};
}
function projectiveAdd(curve:GostCurve,left:ProjectivePoint,right:ProjectivePoint):ProjectivePoint {
  if(left.z===0n)return right;if(right.z===0n)return left;const p=curve.p,z1z1=mod(left.z*left.z,p),z2z2=mod(right.z*right.z,p),u1=mod(left.x*z2z2,p),u2=mod(right.x*z1z1,p),s1=mod(left.y*right.z*z2z2,p),s2=mod(right.y*left.z*z1z1,p);if(u1===u2)return s1===s2?projectiveDouble(curve,left):infinity;const h=mod(u2-u1,p),i=mod(4n*h*h,p),j=mod(h*i,p),r=mod(2n*(s2-s1),p),v=mod(u1*i,p),x=mod(r*r-j-2n*v,p),y=mod(r*(v-x)-2n*s1*j,p),z=mod(((left.z+right.z)*(left.z+right.z)-z1z1-z2z2)*h,p);return{x,y,z};
}
function affine(curve:GostCurve,point:ProjectivePoint):GostPoint|null {if(point.z===0n)return null;const z=inverse(point.z,curve.p),z2=mod(z*z,curve.p);return{x:mod(point.x*z2,curve.p),y:mod(point.y*z2*z,curve.p)};}
function windowTable(curve:GostCurve,point:GostPoint):readonly ProjectivePoint[]{const table:ProjectivePoint[]=[infinity,projective(point)];for(let index=2;index<16;index+=1)table.push(projectiveAdd(curve,table[index-1]!,table[1]!));return table;}
function scalarMultiplyProjective(curve:GostCurve,point:GostPoint,scalar:bigint):ProjectivePoint {if(scalar<=0n)return infinity;const value=mod(scalar,curve.q),table=windowTable(curve,point),windows=Math.ceil(curve.q.toString(2).length/4);let result=infinity;for(let window=windows-1;window>=0;window-=1){for(let index=0;index<4;index+=1)result=projectiveDouble(curve,result);const digit=Number(value>>BigInt(window*4)&15n);result=projectiveAdd(curve,result,table[digit]!);}return result;}

const COMB_WIDTH=6;
interface CombTable {readonly table:readonly ProjectivePoint[];readonly columns:number;}
const generatorTables=new WeakMap<GostCurve,CombTable>();
function generatorTable(curve:GostCurve):CombTable {let cached=generatorTables.get(curve);if(cached!==undefined)return cached;const columns=Math.ceil(curve.q.toString(2).length/COMB_WIDTH),bases:ProjectivePoint[]=[],generator=projective({x:curve.gx,y:curve.gy});let current=generator;for(let row=0;row<COMB_WIDTH;row+=1){bases.push(current);for(let column=0;column<columns;column+=1)current=projectiveDouble(curve,current);}const table:ProjectivePoint[]=[infinity];for(let value=1;value<(1<<COMB_WIDTH);value+=1){let bit=0;while((value&(1<<bit))===0)bit+=1;table.push(projectiveAdd(curve,table[value&(value-1)]!,bases[bit]!));}cached={table,columns};generatorTables.set(curve,cached);return cached;}
function scalarBaseMultiplyProjective(curve:GostCurve,scalar:bigint):ProjectivePoint {if(scalar<=0n)return infinity;const value=mod(scalar,curve.q),{table,columns}=generatorTable(curve);let result=infinity;for(let column=columns-1;column>=0;column-=1){result=projectiveDouble(curve,result);let index=0;for(let row=COMB_WIDTH-1;row>=0;row-=1)index=index<<1|Number(value>>BigInt(row*columns+column)&1n);result=projectiveAdd(curve,result,table[index]!);}return result;}
export function scalarMultiply(curve:GostCurve,point:GostPoint,scalar:bigint):GostPoint|null {const result=point.x===curve.gx&&point.y===curve.gy?scalarBaseMultiplyProjective(curve,scalar):scalarMultiplyProjective(curve,point,scalar);return affine(curve,result);}
export function isOnCurve(curve:GostCurve,point:GostPoint):boolean{return point.x>=0n&&point.x<curve.p&&point.y>=0n&&point.y<curve.p&&mod(point.y*point.y-(point.x*point.x*point.x+curve.a*point.x+curve.b),curve.p)===0n;}
export function createPrivateKey(curve:GostCurve,d:bigint):GostPrivateKey {if(d<=0n||d>=curve.q)throw new RangeError("invalid private key");const point=scalarMultiply(curve,{x:curve.gx,y:curve.gy},d);if(point===null)throw new RangeError("invalid private key");return{curve,d,publicKey:{curve,...point}};}
export function createPublicKey(curve:GostCurve,x:bigint,y:bigint):GostPublicKey {const point={x,y};if(!isOnCurve(curve,point)||scalarMultiply(curve,point,curve.q)!==null)throw new RangeError("invalid public key");return{curve,x,y};}
export function digestToInt(digest:Uint8Array):bigint{let result=0n;for(let i=digest.length-1;i>=0;i-=1)result=(result<<8n)|BigInt(digest[i]!);return result;}
function digestE(curve:GostCurve,digest:Uint8Array):bigint{const e=digestToInt(digest)%curve.q;return e===0n?1n:e;}
export function signDigestWithK(privateKey:GostPrivateKey,digest:Uint8Array,k:bigint):GostSignature {const {curve,d}=privateKey;if(k<=0n||k>=curve.q)throw new RangeError("invalid signature nonce");const point=scalarMultiply(curve,{x:curve.gx,y:curve.gy},k);if(point===null)throw new RangeError("invalid signature nonce");const r=point.x%curve.q,s=(r*d+k*digestE(curve,digest))%curve.q;if(r===0n||s===0n)throw new RangeError("signature nonce produced zero component");return{r,s};}
export function verifyDigest(publicKey:GostPublicKey,digest:Uint8Array,signature:GostSignature):boolean {const {curve}=publicKey,{r,s}=signature;if(r<=0n||r>=curve.q||s<=0n||s>=curve.q||!isOnCurve(curve,publicKey))return false;const v=inverse(digestE(curve,digest),curve.q),z1=mod(s*v,curve.q),z2=mod(-r*v,curve.q),sum=affine(curve,projectiveAdd(curve,scalarBaseMultiplyProjective(curve,z1),scalarMultiplyProjective(curve,publicKey,z2)));return sum!==null&&sum.x%curve.q===r;}
function encode(value:bigint,size:number):Uint8Array{const out=new Uint8Array(size);let v=value;for(let i=size-1;i>=0;i-=1){out[i]=Number(v&0xffn);v>>=8n;}if(v!==0n)throw new RangeError("signature component too large");return out;}
export function encodeSignature(curve:GostCurve,signature:GostSignature):Uint8Array{return Uint8Array.from([...encode(signature.r,curve.size),...encode(signature.s,curve.size)]);}
export function decodeSignature(curve:GostCurve,encoded:Uint8Array):GostSignature{if(encoded.length!==curve.size*2)throw new RangeError("invalid signature length");const read=(bytes:Uint8Array)=>{let v=0n;for(const b of bytes)v=(v<<8n)|BigInt(b);return v;};return{r:read(encoded.subarray(0,curve.size)),s:read(encoded.subarray(curve.size))};}

export type RandomFill = (target: Uint8Array) => void;

function defaultRandomFill(target: Uint8Array): void {
  const cryptoApi = globalThis.crypto;
  if (cryptoApi === undefined) throw new Error("Web Crypto getRandomValues is unavailable");
  for (let offset = 0; offset < target.length; offset += 65_536) cryptoApi.getRandomValues(target.subarray(offset, offset + 65_536));
}

export function randomScalar(curve: GostCurve, fillRandom: RandomFill = defaultRandomFill): bigint {
  const bitLength = curve.q.toString(2).length;
  const byteLength = Math.ceil(bitLength / 8);
  const excessBits = byteLength * 8 - bitLength;
  const bytes = new Uint8Array(byteLength);
  for (let attempt = 0; attempt < 1_000; attempt += 1) {
    fillRandom(bytes);
    if (excessBits > 0) bytes[0]! &= 0xff >>> excessBits;
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    if (value > 0n && value < curve.q) return value;
  }
  throw new Error("failed to generate a random scalar");
}

export function generatePrivateKey(curve: GostCurve, fillRandom: RandomFill = defaultRandomFill): GostPrivateKey {
  return createPrivateKey(curve, randomScalar(curve, fillRandom));
}

export function signDigest(privateKey: GostPrivateKey, digest: Uint8Array, fillRandom: RandomFill = defaultRandomFill): GostSignature {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { return signDigestWithK(privateKey, digest, randomScalar(privateKey.curve, fillRandom)); }
    catch (error) { if (!(error instanceof RangeError) || !error.message.includes("zero component")) throw error; }
  }
  throw new Error("failed to generate a signature nonce");
}

export function signData(privateKey: GostPrivateKey, data: Uint8Array, fillRandom: RandomFill = defaultRandomFill): Uint8Array {
  const digest = privateKey.curve.size === 32 ? streebog256(data) : streebog512(data);
  return encodeSignature(privateKey.curve, signDigest(privateKey, digest, fillRandom));
}

export function verifyData(publicKey: GostPublicKey, data: Uint8Array, signature: Uint8Array): boolean {
  try {
    const digest = publicKey.curve.size === 32 ? streebog256(data) : streebog512(data);
    return verifyDigest(publicKey, digest, decodeSignature(publicKey.curve, signature));
  } catch { return false; }
}

function encodeLittleEndian(value: bigint, size: number): Uint8Array {
  const result = new Uint8Array(size);
  let current = value;
  for (let index = 0; index < size; index += 1) { result[index] = Number(current & 0xffn); current >>= 8n; }
  if (current !== 0n) throw new RangeError("key component too large");
  return result;
}

function decodeLittleEndian(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) result = (result << 8n) | BigInt(bytes[index]!);
  return result;
}

export function encodePrivateKey(privateKey: GostPrivateKey): Uint8Array { return encodeLittleEndian(privateKey.d, privateKey.curve.size); }
export function decodePrivateKey(curve: GostCurve, encoded: Uint8Array): GostPrivateKey { if(encoded.length!==curve.size)throw new RangeError("invalid private key length");return createPrivateKey(curve,decodeLittleEndian(encoded)); }
export function encodePublicKey(publicKey: GostPublicKey): Uint8Array { return Uint8Array.from([...encodeLittleEndian(publicKey.x,publicKey.curve.size),...encodeLittleEndian(publicKey.y,publicKey.curve.size)]); }
export function decodePublicKey(curve: GostCurve, encoded: Uint8Array): GostPublicKey { if(encoded.length!==curve.size*2)throw new RangeError("invalid public key length");return createPublicKey(curve,decodeLittleEndian(encoded.subarray(0,curve.size)),decodeLittleEndian(encoded.subarray(curve.size))); }
export function encodePkixSignature(curve: GostCurve, signature: GostSignature): Uint8Array { return Uint8Array.from([...encode(signature.s,curve.size),...encode(signature.r,curve.size)]); }
export function decodePkixSignature(curve: GostCurve, encoded: Uint8Array): GostSignature { const decoded=decodeSignature(curve,encoded);return{r:decoded.s,s:decoded.r}; }
export * from "./curves.js";
