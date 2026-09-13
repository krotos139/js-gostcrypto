import { Gost28147Cipher,paramHashCryptoPro,paramHashTest,type Gost28147SBox } from "@gostcrypto/legacy-gost28147";
export const GOST341194_SIZE=32,GOST341194_BLOCK_SIZE=32;
const xor=(a:Uint8Array,b:Uint8Array)=>Uint8Array.from(a,(value,index)=>value^b[index]!);
function transformA(x:Uint8Array):Uint8Array{const out=new Uint8Array(32);out.set(x.subarray(8),0);for(let i=0;i<8;i+=1)out[24+i]=x[i]!^x[8+i]!;return out;}
const permutation=Uint8Array.from({length:32},(_,position)=>{const k=Math.floor(position/4),i=position%4;return 8*i+k;});
const transformP=(x:Uint8Array)=>Uint8Array.from(permutation,(position)=>x[position]!);
function psi(x:Uint8Array):Uint8Array{const out=new Uint8Array(32);out.set(x.subarray(2),0);out[30]=x[0]!^x[2]!^x[4]!^x[6]!^x[24]!^x[30]!;out[31]=x[1]!^x[3]!^x[5]!^x[7]!^x[25]!^x[31]!;return out;}
const c3=Uint8Array.from([0xff,0x00,0xff,0xff,0x00,0x00,0x00,0xff,0xff,0x00,0x00,0xff,0x00,0xff,0xff,0x00,0x00,0xff,0x00,0xff,0x00,0xff,0x00,0xff,0xff,0x00,0xff,0x00,0xff,0x00,0xff,0x00].reverse());
function add(left:Uint8Array,right:Uint8Array):void{let carry=0;for(let i=0;i<32;i+=1){const sum=left[i]!+right[i]!+carry;left[i]=sum&255;carry=sum>>>8;}}
function addBits(left:Uint8Array,bits:number):void{const right=new Uint8Array(32);let value=BigInt(bits);for(let i=0;i<8;i+=1){right[i]=Number(value&255n);value>>=8n;}add(left,right);}

export class Gost341194Hash {
  readonly size=32;readonly blockSize=32;readonly #sbox:Gost28147SBox;readonly #initial:Uint8Array;#h:Uint8Array;#sigma=new Uint8Array(32);#length=new Uint8Array(32);#buffer:number[]=[];
  constructor(sbox:Gost28147SBox=paramHashCryptoPro(),h0:Uint8Array=new Uint8Array(32)){if(h0.length!==32)throw new RangeError("GOST 34.11-94 h0 must be 32 bytes");new Gost28147Cipher(new Uint8Array(32),sbox);this.#sbox=sbox;this.#initial=Uint8Array.from(h0);this.#h=Uint8Array.from(h0);}
  reset():this{this.#h=Uint8Array.from(this.#initial);this.#sigma=new Uint8Array(32);this.#length=new Uint8Array(32);this.#buffer=[];return this;}
  #keys(message:Uint8Array):Uint8Array[]{const keys:Uint8Array[]=[];let u:Uint8Array=Uint8Array.from(this.#h),v:Uint8Array=Uint8Array.from(message);keys.push(transformP(xor(u,v)));for(let i=1;i<4;i+=1){u=transformA(u);if(i===2)u=xor(u,c3);v=transformA(transformA(v));keys.push(transformP(xor(u,v)));}return keys;}
  #chi(message:Uint8Array):void{const keys=this.#keys(message),s=new Uint8Array(32);for(let i=0;i<4;i+=1)s.set(new Gost28147Cipher(keys[i]!,this.#sbox).encryptBlock(this.#h.subarray(i*8,i*8+8)),i*8);let current:Uint8Array=s;for(let i=0;i<12;i+=1)current=psi(current);current=psi(xor(message,current));current=xor(this.#h,current);for(let i=0;i<61;i+=1)current=psi(current);this.#h=current;}
  #block(block:Uint8Array):void{this.#chi(block);addBits(this.#length,256);add(this.#sigma,block);}
  update(data:Uint8Array):this{this.#buffer.push(...data);while(this.#buffer.length>32)this.#block(Uint8Array.from(this.#buffer.splice(0,32)));return this;}
  #finalize():Uint8Array{const message=new Uint8Array(32);message.set(this.#buffer);addBits(this.#length,this.#buffer.length*8);add(this.#sigma,message);this.#chi(message);this.#chi(this.#length);this.#chi(this.#sigma);return Uint8Array.from(this.#h);}
  digest():Uint8Array{const copy=new Gost341194Hash(this.#sbox,this.#initial);copy.#h=Uint8Array.from(this.#h);copy.#sigma=Uint8Array.from(this.#sigma);copy.#length=Uint8Array.from(this.#length);copy.#buffer=[...this.#buffer];return copy.#finalize();}
}
export const gost341194=(data:Uint8Array)=>new Gost341194Hash().update(data).digest();
export const gost341194Test=(data:Uint8Array)=>new Gost341194Hash(paramHashTest()).update(data).digest();
