import type { BlockCipher } from "@gostcrypto/core";

export const GOST28147_BLOCK_SIZE=8, GOST28147_KEY_SIZE=32, GOST28147_SBOX_SIZE=64;
export type Gost28147SBox = readonly (readonly number[])[];

export function validateSBox(sbox: Gost28147SBox): boolean {
  return sbox.length===8&&sbox.every((row)=>row.length===16&&row.every((value)=>Number.isInteger(value)&&value>=0&&value<16)&&new Set(row).size===16);
}
export function unpackSBox(packed: Uint8Array): Gost28147SBox {
  if(packed.length!==64)throw new RangeError("invalid GOST 28147 S-box");const result=Array.from({length:8},()=>Array<number>(16));
  for(let n=0;n<128;n+=1)result[n%8]![Math.floor(n/8)]=(n%2===0?packed[Math.floor(n/2)]!>>>4:packed[Math.floor(n/2)]!&15);
  if(!validateSBox(result))throw new RangeError("invalid GOST 28147 S-box");return result.map((row)=>Object.freeze(row));
}
const fromHex=(hex:string)=>Uint8Array.from(hex.match(/../g)!.map((value)=>Number.parseInt(value,16)));
const named=(hex:string)=>()=>unpackSBox(fromHex(hex));
export const paramTest=named("4cde389c2989efb6ffeb56c55ec29b029875613b113f896003970c798aa1d55de210ad43375db38eb42c77e7cd46cafad66a201f70f41ea4ab03f22165b844d8");
export const paramCryptoProA=named("93eeb31b67475ada3e6a1d2f292c9c9588bd8170ba31d2ac1fd3f06e70890b08a5c0e78642f245c2e65b2943fca43459cb0fc8f104787f37dd15aebd519666e4");
export const paramCryptoProB=named("80e7285041c57324b200c2ab1aadf6be349b94985d265d1305d1aec79cb2bb3129731c7ae75a4142a38c07d9cfffdf06db346a6f686e80fd7619e985fe4835ec");
export const paramCryptoProC=named("10838ca7b126d994c750bb602d0101859b4548dad49d5ee205fa122ff2a8240e483b97fc5e7233368fc9c651ecd7e5bba96e6a4d7aeff019661cafc333b47d78");
export const paramCryptoProD=named("fb110831c6c5c00a23be8f66a40c93f86cfad21f4fe725eb5e60ae90025dbb2477a671dc9dd23a83e84b64c5d084574915994cb7ba33e9ad897ffd523128167e");
export const paramZ=named("c6bc75814838fde762525f2e2381a65da92d89605af41295b5af6c189cd6dac3e1e70bf48e10974fd47a38ba7745e1060bc3b4d93d9e43acf0692e3b1f0bc072");
export const paramHashTest=named("4e5764d1ab8dcbbf941a7a4d2cd11010d6a057358d38f2f70f49d15aea2f8d9462ee4309b3f4a6a218c698e3c17ce57e706b0966f7023c8b5595bf2839b32ecc");
export const paramHashCryptoPro=named("a57477d14ffa66e354c7424a60ecb41982909d751d4fc90b3b122f547908a0afd13e1a38c7b181c6e65605870325ebfe9c6df86d2eabde20ba893c92f8d353bc");

const read32=(b:Uint8Array,o:number)=>(b[o]!|b[o+1]!<<8|b[o+2]!<<16|b[o+3]!<<24)>>>0;
const write32=(b:Uint8Array,o:number,v:number)=>{b[o]=v&255;b[o+1]=v>>>8&255;b[o+2]=v>>>16&255;b[o+3]=v>>>24&255;};
const rotl11=(v:number)=>((v<<11)|(v>>>21))>>>0;

export class Gost28147Cipher implements BlockCipher {
  readonly blockSize=8; readonly #table=new Uint32Array(4*256); #roundKeys=new Uint32Array(32);
  constructor(key:Uint8Array,sbox:Gost28147SBox=paramZ()){if(!validateSBox(sbox))throw new RangeError("invalid GOST 28147 S-box");for(let byte=0;byte<4;byte+=1)for(let value=0;value<256;value+=1){const substituted=sbox[byte*2]![value&15]!|sbox[byte*2+1]![value>>>4]!<<4;this.#table[byte*256+value]=rotl11(substituted<<(byte*8));}this.setKey(key);}
  setKey(key:Uint8Array):void{if(key.length!==32)throw new RangeError("GOST 28147 key must be 32 bytes");const words=Array.from({length:8},(_,i)=>read32(key,i*4));for(let i=0;i<24;i+=1)this.#roundKeys[i]=words[i%8]!;for(let i=0;i<8;i+=1)this.#roundKeys[24+i]=words[7-i]!;}
  #f(a:number,k:number):number{const sum=(a+k)>>>0;return(this.#table[sum&255]!^this.#table[256+(sum>>>8&255)]!^this.#table[512+(sum>>>16&255)]!^this.#table[768+(sum>>>24)]!)>>>0;}
  /** @internal */ round(a:number,index:number):number{return this.#f(a,this.#roundKeys[index]!);}
  #crypt(block:Uint8Array,decrypt:boolean):Uint8Array{if(block.length!==8)throw new RangeError("GOST 28147 block must be 8 bytes");let n1=read32(block,0),n2=read32(block,4);for(let i=0;i<31;i+=1){const j=decrypt?31-i:i,previous=n1;n1=(n2^this.#f(n1,this.#roundKeys[j]!))>>>0;n2=previous;}n2=(n2^this.#f(n1,this.#roundKeys[decrypt?0:31]!))>>>0;const out=new Uint8Array(8);write32(out,0,n1);write32(out,4,n2);return out;}
  encryptBlock(block:Uint8Array):Uint8Array{return this.#crypt(block,false);} decryptBlock(block:Uint8Array):Uint8Array{return this.#crypt(block,true);}
}

export class Gost28147Gamma {
  readonly #cipher:Gost28147Cipher;#y:number;#z:number;#gamma:Uint8Array=new Uint8Array(8);#offset=8;
  constructor(cipher:Gost28147Cipher,iv:Uint8Array){if(iv.length!==8)throw new RangeError("GOST 28147 IV must be 8 bytes");this.#cipher=cipher;const state=cipher.encryptBlock(iv);this.#y=read32(state,0);this.#z=read32(state,4);}
  #next(){this.#y=(this.#y+0x01010101)>>>0;const sum=this.#z+0x01010104;this.#z=(sum>=0xffffffff?sum-0xffffffff:sum)>>>0;const input=new Uint8Array(8);write32(input,0,this.#y);write32(input,4,this.#z);this.#gamma=this.#cipher.encryptBlock(input);this.#offset=0;}
  update(data:Uint8Array):Uint8Array{const out=new Uint8Array(data.length);for(let i=0;i<data.length;i+=1){if(this.#offset===8)this.#next();out[i]=data[i]!^this.#gamma[this.#offset++]!;}return out;}
}

export class Gost28147Cfb {
  readonly #cipher:Gost28147Cipher;readonly #decrypt:boolean;#state:Uint8Array;#gamma:Uint8Array=new Uint8Array(8);#feed=new Uint8Array(8);#offset=8;
  constructor(cipher:Gost28147Cipher,iv:Uint8Array,decrypt=false){if(iv.length!==8)throw new RangeError("GOST 28147 IV must be 8 bytes");this.#cipher=cipher;this.#state=Uint8Array.from(iv);this.#decrypt=decrypt;}
  update(data:Uint8Array):Uint8Array{const out=new Uint8Array(data.length);for(let i=0;i<data.length;i+=1){if(this.#offset===8){this.#gamma=this.#cipher.encryptBlock(this.#state);this.#offset=0;}out[i]=data[i]!^this.#gamma[this.#offset]!;this.#feed[this.#offset]=this.#decrypt?data[i]!:out[i]!;this.#offset+=1;if(this.#offset===8)this.#state=Uint8Array.from(this.#feed);}return out;}
  /** Feedback register; exposed for CryptoPro key meshing. */ feedback():Uint8Array{return Uint8Array.from(this.#state);}
}

export const GOST28147_MESHING_PERIOD=1024;
const MESHING_CONSTANT=fromHex("6900722264c904238d3adb9646e92ac418feac9400ed0712c086dcc2ef4ca92b");
export function meshGost28147Key(key:Uint8Array,sbox:Gost28147SBox,iv:Uint8Array):{key:Uint8Array;iv:Uint8Array}{const current=new Gost28147Cipher(key,sbox),nextKey=new Uint8Array(32);for(let offset=0;offset<32;offset+=8)nextKey.set(current.decryptBlock(MESHING_CONSTANT.subarray(offset,offset+8)),offset);const nextCipher=new Gost28147Cipher(nextKey,sbox);return{key:nextKey,iv:nextCipher.encryptBlock(iv)};}
export class Gost28147MeshedCfb {
  readonly #sbox:Gost28147SBox;readonly #decrypt:boolean;#key:Uint8Array;#stream:Gost28147Cfb;#done=0;
  constructor(key:Uint8Array,sbox:Gost28147SBox,iv:Uint8Array,decrypt=false){this.#key=Uint8Array.from(key);this.#sbox=sbox;this.#decrypt=decrypt;this.#stream=new Gost28147Cfb(new Gost28147Cipher(this.#key,sbox),iv,decrypt);}
  update(data:Uint8Array):Uint8Array{const output=new Uint8Array(data.length);let offset=0;while(offset<data.length){if(this.#done===1024){const next=meshGost28147Key(this.#key,this.#sbox,this.#stream.feedback());this.#key=next.key;this.#stream=new Gost28147Cfb(new Gost28147Cipher(this.#key,this.#sbox),next.iv,this.#decrypt);this.#done=0;}const length=Math.min(1024-this.#done,data.length-offset);output.set(this.#stream.update(data.subarray(offset,offset+length)),offset);offset+=length;this.#done+=length;}return output;}
}

export class Gost28147Mac {
  readonly #cipher:Gost28147Cipher;readonly #size:number;readonly #initial:Uint8Array;#state:Uint8Array;#buffer:number[]=[];
  constructor(key:Uint8Array,sbox:Gost28147SBox=paramZ(),iv:Uint8Array=new Uint8Array(8),size=4){if(iv.length!==8)throw new RangeError("GOST 28147 MAC IV must be 8 bytes");if(size<1||size>4)throw new RangeError("GOST 28147 MAC size must be 1..4");this.#cipher=new Gost28147Cipher(key,sbox);this.#size=size;this.#initial=Uint8Array.from(iv);this.#state=Uint8Array.from(iv);}
  reset():this{this.#state=Uint8Array.from(this.#initial);this.#buffer=[];return this;}
  #block(block:Uint8Array){const n1=read32(this.#state,0)^read32(block,0),n2=read32(this.#state,4)^read32(block,4);this.#state=macRounds(this.#cipher,n1>>>0,n2>>>0);}
  update(data:Uint8Array):this{this.#buffer.push(...data);while(this.#buffer.length>=8)this.#block(Uint8Array.from(this.#buffer.splice(0,8)));return this;}
  digest():Uint8Array{return this.#digestCopy();}
  #digestCopy():Uint8Array{let state:Uint8Array=Uint8Array.from(this.#state);if(this.#buffer.length>0){const block=new Uint8Array(8);block.set(this.#buffer);state=macRounds(this.#cipher,(read32(state,0)^read32(block,0))>>>0,(read32(state,4)^read32(block,4))>>>0);}return state.slice(4-this.#size,4);}
}

function macRounds(cipher:Gost28147Cipher,n1:number,n2:number):Uint8Array {for(let i=0;i<16;i+=1){const previous=n1;n1=(n2^cipher.round(n1,i))>>>0;n2=previous;}const out=new Uint8Array(8);write32(out,0,n1);write32(out,4,n2);return out;}
export function gost28147Mac(key:Uint8Array,data:Uint8Array,options:{sbox?:Gost28147SBox;iv?:Uint8Array;size?:number}={}):Uint8Array{return new Gost28147Mac(key,options.sbox,options.iv,options.size).update(data).digest();}
