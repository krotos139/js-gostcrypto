import type { BlockCipher, Bytes } from "@gostcrypto/core";

export type CipherFactory = (key: Bytes) => BlockCipher;

const D = Uint8Array.from({ length: 128 }, (_, index) => 0x80 + index);

/** ACPKM key derivation from RFC 8645 section 6.2.1. */
export function deriveAcpkm(cipher: BlockCipher, keyLength: number): Bytes {
  if (!Number.isInteger(keyLength) || keyLength <= 0 || keyLength > D.length) throw new RangeError("invalid ACPKM key length");
  const blocks = Math.ceil(keyLength / cipher.blockSize);
  if (blocks * cipher.blockSize > D.length) throw new RangeError("ACPKM key length exceeds derivation constants");
  const material = new Uint8Array(blocks * cipher.blockSize);
  for (let index = 0; index < blocks; index += 1) material.set(cipher.encryptBlock(D.subarray(index * cipher.blockSize, (index + 1) * cipher.blockSize)), index * cipher.blockSize);
  return material.slice(0, keyLength);
}

/** Streaming CTR-ACPKM from RFC 8645 section 6.2.2. */
export class CtrAcpkm {
  readonly #factory: CipherFactory;
  readonly #keyLength: number;
  readonly #sectionBlocks: number;
  readonly #counterBytes: number;
  #cipher: BlockCipher;
  #key: Bytes;
  #counter: Bytes;
  #keyStream: Bytes;
  #position: number;
  #blocksInSection = 0;

  public constructor(factory: CipherFactory, key: Bytes, icn: Bytes, sectionSize: number) {
    const cipher = factory(key);
    if (!Number.isInteger(sectionSize) || sectionSize <= 0 || sectionSize % cipher.blockSize !== 0) throw new RangeError("ACPKM section size must be a positive multiple of block size");
    const counterBytes = cipher.blockSize - icn.length;
    if (counterBytes < 4 || counterBytes * 4 > cipher.blockSize * 3) throw new RangeError("invalid ACPKM ICN length");
    deriveAcpkm(cipher, key.length);
    this.#factory = factory; this.#keyLength = key.length; this.#sectionBlocks = sectionSize / cipher.blockSize; this.#counterBytes = counterBytes;
    this.#cipher = cipher; this.#key = Uint8Array.from(key); this.#counter = new Uint8Array(cipher.blockSize); this.#counter.set(icn);
    this.#keyStream = new Uint8Array(cipher.blockSize); this.#position = cipher.blockSize;
  }

  /** Encrypts or decrypts while retaining key and counter state. */
  public update(input: Bytes): Bytes {
    const output = new Uint8Array(input.length);
    let offset = 0;
    while (offset < input.length) {
      if (this.#position === this.#keyStream.length) this.#next();
      const count = Math.min(this.#keyStream.length - this.#position, input.length - offset);
      for (let index = 0; index < count; index += 1) output[offset + index] = input[offset + index]! ^ this.#keyStream[this.#position + index]!;
      offset += count; this.#position += count;
    }
    return output;
  }

  /** Copies the complete stream state without sharing mutable byte arrays. */
  public clone(): CtrAcpkm {
    const copy = new CtrAcpkm(this.#factory, this.#key, this.#counter.subarray(0, this.#counter.length - this.#counterBytes), this.#sectionBlocks * this.#counter.length);
    copy.#cipher = this.#cipher;
    copy.#key = Uint8Array.from(this.#key);
    copy.#counter = Uint8Array.from(this.#counter);
    copy.#keyStream = Uint8Array.from(this.#keyStream);
    copy.#position = this.#position;
    copy.#blocksInSection = this.#blocksInSection;
    return copy;
  }

  #next(): void {
    if (this.#blocksInSection === this.#sectionBlocks) { this.#key = deriveAcpkm(this.#cipher, this.#keyLength); this.#cipher = this.#factory(this.#key); this.#blocksInSection = 0; }
    this.#keyStream = this.#cipher.encryptBlock(this.#counter); this.#position = 0; this.#blocksInSection += 1;
    for (let index = this.#counter.length - 1; index >= this.#counter.length - this.#counterBytes; index -= 1) { this.#counter[index] = (this.#counter[index]! + 1) & 0xff; if (this.#counter[index] !== 0) break; }
  }
}

function xor(left: Bytes, right: Bytes): Bytes {
  const output = new Uint8Array(left.length);
  for (let index = 0; index < output.length; index += 1) output[index] = left[index]! ^ right[index]!;
  return output;
}

function masterStream(factory: CipherFactory, key: Bytes, masterSectionSize: number): CtrAcpkm {
  const cipher = factory(key);
  if (!Number.isInteger(masterSectionSize) || masterSectionSize <= 0 || masterSectionSize % cipher.blockSize !== 0) {
    throw new RangeError("ACPKM master section size must be a positive multiple of block size");
  }
  return new CtrAcpkm(factory, key, new Uint8Array(cipher.blockSize / 2).fill(0xff), masterSectionSize);
}

/** Derives concatenated section-key material with ACPKM-Master (RFC 8645 section 6.3.1). */
export function deriveAcpkmMasterKeys(factory: CipherFactory, key: Bytes, masterSectionSize: number, materialSize: number, sectionCount: number): Bytes {
  if (!Number.isSafeInteger(materialSize) || materialSize <= 0 || !Number.isSafeInteger(sectionCount) || sectionCount <= 0) {
    throw new RangeError("ACPKM master material size and section count must be positive integers");
  }
  const length = materialSize * sectionCount;
  if (!Number.isSafeInteger(length)) throw new RangeError("ACPKM master material is too large");
  return masterStream(factory, key, masterSectionSize).update(new Uint8Array(length));
}

class MasterSectionSource {
  #stream: CtrAcpkm;
  readonly #factory: CipherFactory;
  readonly #key: Bytes;
  readonly #sectionSize: number;
  readonly #masterSectionSize: number;
  readonly #keyLength: number;
  readonly #extraLength: number;
  readonly #blocksPerSection: number;
  #used = 0;
  #cipher?: BlockCipher;
  #extra = new Uint8Array();

  public constructor(factory: CipherFactory, key: Bytes, sectionSize: number, masterSectionSize: number, extraLength = 0) {
    const cipher = factory(key);
    if (!Number.isInteger(sectionSize) || sectionSize <= 0 || sectionSize % cipher.blockSize !== 0) {
      throw new RangeError("ACPKM section size must be a positive multiple of block size");
    }
    this.#stream = masterStream(factory, key, masterSectionSize);
    this.#factory = factory;
    this.#key = Uint8Array.from(key);
    this.#sectionSize = sectionSize;
    this.#masterSectionSize = masterSectionSize;
    this.#keyLength = key.length;
    this.#extraLength = extraLength;
    this.#blocksPerSection = sectionSize / cipher.blockSize;
  }

  public peek(): BlockCipher {
    if (this.#cipher === undefined || this.#used === this.#blocksPerSection) {
      const material = this.#stream.update(new Uint8Array(this.#keyLength + this.#extraLength));
      this.#cipher = this.#factory(material.subarray(0, this.#keyLength));
      this.#extra = material.slice(this.#keyLength);
      this.#used = 0;
    }
    return this.#cipher;
  }

  public next(): BlockCipher {
    const cipher = this.peek();
    this.#used += 1;
    return cipher;
  }

  public get extra(): Bytes {
    this.peek();
    return this.#extra;
  }

  public clone(): MasterSectionSource {
    const copy = new MasterSectionSource(this.#factory, this.#key, this.#sectionSize, this.#masterSectionSize, this.#extraLength);
    copy.#stream = this.#stream.clone();
    copy.#used = this.#used;
    copy.#cipher = this.#cipher;
    copy.#extra = Uint8Array.from(this.#extra);
    return copy;
  }
}

/** Streaming CTR-ACPKM-Master from RFC 8645 section 6.3.2. */
export class CtrAcpkmMaster {
  readonly #keys: MasterSectionSource;
  readonly #counterBytes: number;
  readonly #counter: Bytes;
  #keyStream: Bytes;
  #position: number;

  public constructor(factory: CipherFactory, key: Bytes, icn: Bytes, sectionSize: number, masterSectionSize: number) {
    const cipher = factory(key);
    const counterBytes = cipher.blockSize - icn.length;
    if (counterBytes < 4 || counterBytes * 4 > cipher.blockSize * 3) throw new RangeError("invalid ACPKM ICN length");
    this.#keys = new MasterSectionSource(factory, key, sectionSize, masterSectionSize);
    this.#counterBytes = counterBytes;
    this.#counter = new Uint8Array(cipher.blockSize);
    this.#counter.set(icn);
    this.#keyStream = new Uint8Array(cipher.blockSize);
    this.#position = cipher.blockSize;
  }

  /** Encrypts or decrypts while retaining section-key and counter state. */
  public update(input: Bytes): Bytes {
    const output = new Uint8Array(input.length);
    let offset = 0;
    while (offset < input.length) {
      if (this.#position === this.#keyStream.length) this.#next();
      const count = Math.min(this.#keyStream.length - this.#position, input.length - offset);
      for (let index = 0; index < count; index += 1) output[offset + index] = input[offset + index]! ^ this.#keyStream[this.#position + index]!;
      offset += count;
      this.#position += count;
    }
    return output;
  }

  #next(): void {
    this.#keyStream = this.#keys.next().encryptBlock(this.#counter);
    this.#position = 0;
    for (let index = this.#counter.length - 1; index >= this.#counter.length - this.#counterBytes; index -= 1) {
      this.#counter[index] = (this.#counter[index]! + 1) & 0xff;
      if (this.#counter[index] !== 0) break;
    }
  }
}

/** Streaming CBC-ACPKM-Master. Input to each update must contain complete blocks. */
export class CbcAcpkmMaster {
  readonly #keys: MasterSectionSource;
  readonly #decrypt: boolean;
  #previous: Bytes;

  public constructor(factory: CipherFactory, key: Bytes, iv: Bytes, sectionSize: number, masterSectionSize: number, decrypt = false) {
    const cipher = factory(key);
    if (iv.length !== cipher.blockSize) throw new RangeError("ACPKM CBC IV must occupy one block");
    this.#keys = new MasterSectionSource(factory, key, sectionSize, masterSectionSize);
    this.#decrypt = decrypt;
    this.#previous = Uint8Array.from(iv);
  }

  public update(input: Bytes): Bytes {
    if (input.length % this.#previous.length !== 0) throw new RangeError("ACPKM CBC input must contain complete blocks");
    const output = new Uint8Array(input.length);
    for (let offset = 0; offset < input.length; offset += this.#previous.length) {
      const block = input.subarray(offset, offset + this.#previous.length);
      if (this.#decrypt) {
        output.set(xor(this.#keys.next().decryptBlock(block), this.#previous), offset);
        this.#previous = Uint8Array.from(block);
      } else {
        const encrypted = this.#keys.next().encryptBlock(xor(block, this.#previous));
        output.set(encrypted, offset);
        this.#previous = encrypted;
      }
    }
    return output;
  }
}

/** Streaming full-block CFB-ACPKM-Master from RFC 8645 section 6.3.5. */
export class CfbAcpkmMaster {
  readonly #keys: MasterSectionSource;
  readonly #decrypt: boolean;
  #state: Bytes;
  #gamma: Bytes;
  #feedback: Bytes;
  #position: number;

  public constructor(factory: CipherFactory, key: Bytes, iv: Bytes, sectionSize: number, masterSectionSize: number, decrypt = false) {
    const cipher = factory(key);
    if (iv.length !== cipher.blockSize) throw new RangeError("ACPKM CFB IV must occupy one block");
    this.#keys = new MasterSectionSource(factory, key, sectionSize, masterSectionSize);
    this.#decrypt = decrypt;
    this.#state = Uint8Array.from(iv);
    this.#gamma = new Uint8Array(cipher.blockSize);
    this.#feedback = new Uint8Array(cipher.blockSize);
    this.#position = cipher.blockSize;
  }

  public update(input: Bytes): Bytes {
    const output = new Uint8Array(input.length);
    let offset = 0;
    while (offset < input.length) {
      if (this.#position === this.#gamma.length) {
        this.#gamma = this.#keys.next().encryptBlock(this.#state);
        this.#position = 0;
      }
      const count = Math.min(this.#gamma.length - this.#position, input.length - offset);
      for (let index = 0; index < count; index += 1) {
        const source = input[offset + index]!;
        const result = source ^ this.#gamma[this.#position + index]!;
        output[offset + index] = result;
        this.#feedback[this.#position + index] = this.#decrypt ? source : result;
      }
      offset += count;
      this.#position += count;
      if (this.#position === this.#gamma.length) this.#state = Uint8Array.from(this.#feedback);
    }
    return output;
  }
}

function shiftMasterSubkey(input: Bytes, constant: number): Bytes {
  const output = new Uint8Array(input.length);
  let carry = 0;
  for (let index = input.length - 1; index >= 0; index -= 1) {
    const value = input[index]!;
    output[index] = (value << 1) | carry;
    carry = value >>> 7;
  }
  if (carry !== 0) output[output.length - 1] = output[output.length - 1]! ^ constant;
  return output;
}

/** Streaming OMAC-ACPKM-Master from RFC 8645 section 6.3.6. */
export class OmacAcpkmMaster {
  readonly #factory: CipherFactory;
  readonly #key: Bytes;
  readonly #sectionSize: number;
  readonly #masterSectionSize: number;
  readonly #tagSize: number;
  readonly #blockSize: number;
  readonly #constant: number;
  #keys: MasterSectionSource;
  #chain: Bytes;
  #buffer: Bytes;
  #buffered = 0;
  #total = 0;

  public constructor(factory: CipherFactory, key: Bytes, sectionSize: number, masterSectionSize: number, tagSize?: number) {
    const cipher = factory(key);
    const constant = cipher.blockSize === 8 ? 0x1b : cipher.blockSize === 16 ? 0x87 : undefined;
    if (constant === undefined) throw new RangeError("ACPKM OMAC supports 8- and 16-byte blocks");
    const size = tagSize ?? cipher.blockSize;
    if (!Number.isInteger(size) || size <= 0 || size > cipher.blockSize) throw new RangeError("invalid ACPKM OMAC tag size");
    this.#keys = new MasterSectionSource(factory, key, sectionSize, masterSectionSize, cipher.blockSize);
    this.#factory = factory;
    this.#key = Uint8Array.from(key);
    this.#sectionSize = sectionSize;
    this.#masterSectionSize = masterSectionSize;
    this.#tagSize = size;
    this.#blockSize = cipher.blockSize;
    this.#constant = constant;
    this.#chain = new Uint8Array(cipher.blockSize);
    this.#buffer = new Uint8Array(cipher.blockSize);
  }

  public reset(): this {
    this.#keys = new MasterSectionSource(this.#factory, this.#key, this.#sectionSize, this.#masterSectionSize, this.#blockSize);
    this.#chain.fill(0);
    this.#buffer.fill(0);
    this.#buffered = 0;
    this.#total = 0;
    return this;
  }

  public update(input: Bytes): this {
    this.#total += input.length;
    let offset = 0;
    while (offset < input.length) {
      if (this.#buffered === this.#blockSize) {
        this.#chain = this.#keys.next().encryptBlock(xor(this.#chain, this.#buffer));
        this.#buffered = 0;
      }
      const count = Math.min(this.#blockSize - this.#buffered, input.length - offset);
      this.#buffer.set(input.subarray(offset, offset + count), this.#buffered);
      this.#buffered += count;
      offset += count;
    }
    return this;
  }

  /** Returns a tag without mutating the ongoing state. */
  public digest(): Bytes {
    const keys = this.#keys.clone(), completeLast = this.#total > 0 && this.#buffered === this.#blockSize;
    const cipher = keys.peek();
    const last = new Uint8Array(this.#blockSize);
    last.set(this.#buffer.subarray(0, this.#buffered));
    let subkey = keys.extra;
    if (!completeLast) {
      last[this.#buffered] = 0x80;
      subkey = shiftMasterSubkey(subkey, this.#constant);
    }
    return cipher.encryptBlock(xor(xor(this.#chain, last), subkey)).slice(0, this.#tagSize);
  }
}

/** Computes OMAC-ACPKM-Master in one call. */
export function omacAcpkmMaster(factory: CipherFactory, key: Bytes, data: Bytes, sectionSize: number, masterSectionSize: number, tagSize?: number): Bytes {
  return new OmacAcpkmMaster(factory, key, sectionSize, masterSectionSize, tagSize).update(data).digest();
}
