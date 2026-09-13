import type { BlockCipher, Bytes } from "@gostcrypto/core";

export class MgmAuthenticationError extends Error {
  public constructor() { super("MGM authentication tag mismatch"); this.name = "MgmAuthenticationError"; }
}

function concat(...parts: readonly Bytes[]): Bytes {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0; for (const part of parts) { output.set(part, offset); offset += part.length; } return output;
}
function increment(value: Bytes, start: number, end: number): void {
  for (let index = end - 1; index >= start; index -= 1) { value[index] = (value[index]! + 1) & 0xff; if (value[index] !== 0) return; }
}
const REDUCTION_64=Uint32Array.from({length:16},(_,value)=>{let result=0;for(let bit=0;bit<4;bit+=1)if((value&(1<<bit))!==0)result^=0x1b<<bit;return result;});
const REDUCTION_128=Uint32Array.from({length:16},(_,value)=>{let result=0;for(let bit=0;bit<4;bit+=1)if((value&(1<<bit))!==0)result^=0x87<<bit;return result;});
const readWord=(input:Bytes,offset:number)=>(input[offset]!<<24|input[offset+1]!<<16|input[offset+2]!<<8|input[offset+3]!)>>>0;
const writeWord=(output:Bytes,offset:number,value:number)=>{output[offset]=value>>>24;output[offset+1]=value>>>16;output[offset+2]=value>>>8;output[offset+3]=value;};
function shiftWords(words:Uint32Array,bits:number):number {const top=words[0]!>>>(32-bits);for(let index=0;index<words.length;index+=1)words[index]=((words[index]!<<bits)|(index+1<words.length?words[index+1]!>>>(32-bits):0))>>>0;return top;}
function multiplyInto(output:Bytes,x:Bytes,y:Bytes,table:Uint32Array,left:Uint32Array,product:Uint32Array):void {
  const words=x.length/4,reduction=x.length===8?REDUCTION_64:REDUCTION_128;table.fill(0);product.fill(0);
  for(let index=0;index<words;index+=1){left[index]=readWord(x,index*4);table[words+index]=left[index]!;}
  for(let value=2;value<16;value+=2){const source=value/2,target=value*words;for(let word=0;word<words;word+=1)table[target+word]=table[source*words+word]!;const high=shiftWords(table.subarray(target,target+words),1);table[target+words-1]=table[target+words-1]!^(high===0?0:x.length===8?0x1b:0x87);for(let word=0;word<words;word+=1)table[target+words+word]=table[target+word]!^left[word]!;}
  for(const byte of y)for(let shift=4;shift>=0;shift-=4){const nibble=byte>>>shift&15,high=shiftWords(product,4);product[words-1]=product[words-1]!^reduction[high]!;for(let word=0;word<words;word+=1)product[word]=product[word]!^table[nibble*words+word]!;}
  for(let word=0;word<words;word+=1)writeWord(output,word*4,product[word]!);
}
function xorInto(target: Bytes, value: Bytes): void { for (let index = 0; index < target.length; index += 1) target[index] = target[index]! ^ value[index]!; }
function putLength(target: Bytes, bitLength: number): void { let value = BigInt(bitLength); for (let index = target.length - 1; index >= 0; index -= 1) { target[index] = Number(value & 0xffn); value >>= 8n; } }
function equalConstantTime(left: Bytes, right: Bytes): boolean { if (left.length !== right.length) return false; let difference = 0; for (let index = 0; index < left.length; index += 1) difference |= left[index]! ^ right[index]!; return difference === 0; }

/** MGM authenticated encryption from RFC 9058. */
export class Mgm {
  public readonly nonceSize: number;
  public constructor(readonly cipher: BlockCipher, public readonly tagSize = cipher.blockSize) {
    if (cipher.blockSize !== 8 && cipher.blockSize !== 16) throw new RangeError("MGM requires an 8- or 16-byte block cipher");
    if (!Number.isInteger(tagSize) || tagSize < 4 || tagSize > cipher.blockSize) throw new RangeError("MGM tag size is invalid");
    this.nonceSize = cipher.blockSize;
  }
  public seal(nonce: Bytes, plaintext: Bytes, additionalData = new Uint8Array()): Bytes {
    this.#checkNonce(nonce); if (plaintext.length === 0 && additionalData.length === 0) throw new RangeError("MGM requires plaintext or additional data");
    const ciphertext = this.#crypt(nonce, plaintext); return concat(ciphertext, this.#tag(nonce, additionalData, ciphertext));
  }
  public open(nonce: Bytes, sealed: Bytes, additionalData = new Uint8Array()): Bytes {
    this.#checkNonce(nonce); if (sealed.length < this.tagSize) throw new MgmAuthenticationError();
    const ciphertext = sealed.subarray(0, sealed.length - this.tagSize); const expected = sealed.subarray(sealed.length - this.tagSize);
    if (ciphertext.length === 0 && additionalData.length === 0) throw new MgmAuthenticationError();
    if (!equalConstantTime(this.#tag(nonce, additionalData, ciphertext), expected)) throw new MgmAuthenticationError();
    return this.#crypt(nonce, ciphertext);
  }
  #checkNonce(nonce: Bytes): void { if (nonce.length !== this.nonceSize || (nonce[0]! & 0x80) !== 0) throw new RangeError("invalid MGM nonce"); }
  #crypt(nonce: Bytes, input: Bytes): Bytes {
    const half = this.cipher.blockSize / 2; const counter = this.cipher.encryptBlock(nonce); const output = new Uint8Array(input.length);
    for (let offset = 0; offset < input.length; offset += this.cipher.blockSize) { const gamma = this.cipher.encryptBlock(counter); const count = Math.min(this.cipher.blockSize, input.length - offset); for (let index = 0; index < count; index += 1) output[offset + index] = input[offset + index]! ^ gamma[index]!; increment(counter, half, counter.length); }
    return output;
  }
  #tag(nonce: Bytes, additionalData: Bytes, ciphertext: Bytes): Bytes {
    const blockSize = this.cipher.blockSize; const half = blockSize / 2; const initial = Uint8Array.from(nonce); initial[0] = initial[0]! | 0x80; const counter = this.cipher.encryptBlock(initial),sum = new Uint8Array(blockSize),block = new Uint8Array(blockSize),productBytes = new Uint8Array(blockSize),words=blockSize/4,table=new Uint32Array(16*words),left=new Uint32Array(words),product=new Uint32Array(words);
    const feed = (data: Bytes): void => { for (let offset = 0; offset < data.length; offset += blockSize) { block.fill(0); block.set(data.subarray(offset, offset + blockSize)); multiplyInto(productBytes,this.cipher.encryptBlock(counter),block,table,left,product);xorInto(sum,productBytes);increment(counter, 0, half); } };
    feed(additionalData); feed(ciphertext); const lengths = new Uint8Array(blockSize); putLength(lengths.subarray(0, half), additionalData.length * 8); putLength(lengths.subarray(half), ciphertext.length * 8); multiplyInto(productBytes,this.cipher.encryptBlock(counter),lengths,table,left,product);xorInto(sum,productBytes);return this.cipher.encryptBlock(sum).slice(0, this.tagSize);
  }
}
