/** ГОСТ Р 34.11-2012 / RFC 6986. */

export const BLOCK_SIZE = 64;
export const STREEBOG_512_SIZE = 64;
export const STREEBOG_256_SIZE = 32;

const PI = Uint8Array.from([
  252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
  233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
  249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
  5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
  235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
  181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
  21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
  50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
  223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
  224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
  167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
  173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
  7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
  225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
  32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
  89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
]);

const A = [
  "8e20faa72ba0b470", "47107ddd9b505a38", "ad08b0e0c3282d1c", "d8045870ef14980e",
  "6c022c38f90a4c07", "3601161cf205268d", "1b8e0b0e798c13c8", "83478b07b2468764",
  "a011d380818e8f40", "5086e740ce47c920", "2843fd2067adea10", "14aff010bdd87508",
  "0ad97808d06cb404", "05e23c0468365a02", "8c711e02341b2d01", "46b60f011a83988e",
  "90dab52a387ae76f", "486dd4151c3dfdb9", "24b86a840e90f0d2", "125c354207487869",
  "092e94218d243cba", "8a174a9ec8121e5d", "4585254f64090fa0", "accc9ca9328a8950",
  "9d4df05d5f661451", "c0a878a0a1330aa6", "60543c50de970553", "302a1e286fc58ca7",
  "18150f14b9ec46dd", "0c84890ad27623e0", "0642ca05693b9f70", "0321658cba93c138",
  "86275df09ce8aaa8", "439da0784e745554", "afc0503c273aa42a", "d960281e9d1d5215",
  "e230140fc0802984", "71180a8960409a42", "b60c05ca30204d21", "5b068c651810a89e",
  "456c34887a3805b9", "ac361a443d1c8cd2", "561b0d22900e4669", "2b838811480723ba",
  "9bcf4486248d9f5d", "c3e9224312c8c1a0", "effa11af0964ee50", "f97d86d98a327728",
  "e4fa2054a80b329c", "727d102a548b194e", "39b008152acb8227", "9258048415eb419d",
  "492c024284fbaec0", "aa16012142f35760", "550b8e9e21f7a530", "a48b474f9ef5dc18",
  "70a6a56e2440598e", "3853dc371220a247", "1ca76e95091051ad", "0edd37c48a08a6d8",
  "07e095624504536c", "8d70c431ac02a736", "c83862965601dd1b", "641c314b2b8ee083",
].map((value) => BigInt(`0x${value}`));

const C_HEX = [
  "b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507",
  "6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7",
  "f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2",
  "ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e",
  "4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57",
  "ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e",
  "f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493",
  "9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e",
  "378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb",
  "abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced",
  "7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b",
  "378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720",
];

const C = C_HEX.map((hex) => reverse(hexToBytes(hex)));

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string must contain full bytes");
  const output = new Uint8Array(hex.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

function reverse(input: Uint8Array): Uint8Array {
  return Uint8Array.from(input).reverse();
}

function xorFourInto(
  output: Uint8Array,
  first: Uint8Array,
  second: Uint8Array,
  third: Uint8Array,
  fourth: Uint8Array,
): void {
  for (let index = 0; index < BLOCK_SIZE; index += 1) {
    output[index] =
      first[index]! ^ second[index]! ^ third[index]! ^ fourth[index]!;
  }
}

function add(target: Uint8Array, source: Uint8Array): void {
  let carry = 0;
  for (let index = 0; index < BLOCK_SIZE; index += 1) {
    const sum = target[index]! + source[index]! + carry;
    target[index] = sum & 0xff;
    carry = sum >>> 8;
  }
}

function addUint(target: Uint8Array, value: number): void {
  let carry = value;
  for (let index = 0; index < BLOCK_SIZE && carry > 0; index += 1) {
    const sum = target[index]! + (carry & 0xff);
    target[index] = sum & 0xff;
    carry = Math.floor(carry / 256) + (sum >>> 8);
  }
}

function linear(value: bigint): bigint {
  let output = 0n;
  for (let index = 0; index < 64; index += 1) {
    if ((value & (1n << BigInt(63 - index))) !== 0n) output ^= A[index]!;
  }
  return output;
}

function createLpsTables(): { low: Uint32Array; high: Uint32Array } {
  const low = new Uint32Array(8 * 256), high = new Uint32Array(8 * 256);
  for (let byte = 0; byte < 8; byte += 1) {
    for (let value = 0; value < 256; value += 1) {
      const transformed = linear(BigInt(PI[value]!) << BigInt(byte * 8)), offset = byte * 256 + value;
      low[offset] = Number(transformed & 0xffff_ffffn);
      high[offset] = Number(transformed >> 32n);
    }
  }
  return { low, high };
}

// Fuse S, P and L once at module initialization. The compression loop then
// uses only indexed 32-bit XORs, as in the optimized Go implementation.
const LPS_TABLE = createLpsTables();

/** Applies XOR followed by S, P and L without a temporary 64-byte pass. */
function xlpsInto(output: Uint8Array, left: Uint8Array, right: Uint8Array): void {
  for (let word = 0; word < 8; word += 1) {
    let low = 0, high = 0;
    for (let byte = 0; byte < 8; byte += 1) {
      const index = byte * 8 + word;
      const offset = byte * 256 + (left[index]! ^ right[index]!);
      low ^= LPS_TABLE.low[offset]!;
      high ^= LPS_TABLE.high[offset]!;
    }
    const offset = word * 8;
    output[offset] = low;
    output[offset + 1] = low >>> 8;
    output[offset + 2] = low >>> 16;
    output[offset + 3] = low >>> 24;
    output[offset + 4] = high;
    output[offset + 5] = high >>> 8;
    output[offset + 6] = high >>> 16;
    output[offset + 7] = high >>> 24;
  }
}

/** Streaming Streebog hash. `digest()` does not alter the current state. */
export class StreebogHash {
  #h = new Uint8Array(BLOCK_SIZE);
  #n = new Uint8Array(BLOCK_SIZE);
  #sigma = new Uint8Array(BLOCK_SIZE);
  #buffer = new Uint8Array(BLOCK_SIZE);
  #buffered = 0;
  // Reused compression scratch space keeps the block hot path allocation-free.
  readonly #scratch = Array.from({ length: 4 }, () => new Uint8Array(BLOCK_SIZE));

  public constructor(public readonly size: 32 | 64 = STREEBOG_512_SIZE) {
    this.reset();
  }

  public reset(): this {
    this.#h.fill(this.size === STREEBOG_256_SIZE ? 1 : 0);
    this.#n.fill(0);
    this.#sigma.fill(0);
    this.#buffer.fill(0);
    this.#buffered = 0;
    return this;
  }

  public update(data: Uint8Array): this {
    let offset = 0;
    if (this.#buffered > 0) {
      const count = Math.min(BLOCK_SIZE - this.#buffered, data.length);
      this.#buffer.set(data.subarray(0, count), this.#buffered);
      this.#buffered += count;
      offset += count;
      if (this.#buffered === BLOCK_SIZE) {
        this.#processBlock(this.#buffer);
        this.#buffered = 0;
      }
    }
    while (offset + BLOCK_SIZE <= data.length) {
      this.#processBlock(data.subarray(offset, offset + BLOCK_SIZE));
      offset += BLOCK_SIZE;
    }
    if (offset < data.length) {
      this.#buffer.set(data.subarray(offset), 0);
      this.#buffered = data.length - offset;
    }
    return this;
  }

  public digest(): Uint8Array {
    const copy = this.#clone();
    return copy.#finalize();
  }

  #clone(): StreebogHash {
    const copy = new StreebogHash(this.size);
    copy.#h = Uint8Array.from(this.#h);
    copy.#n = Uint8Array.from(this.#n);
    copy.#sigma = Uint8Array.from(this.#sigma);
    copy.#buffer = Uint8Array.from(this.#buffer);
    copy.#buffered = this.#buffered;
    return copy;
  }

  #compress(message: Uint8Array, counter: Uint8Array): void {
    let key = this.#scratch[0]!;
    let keyNext = this.#scratch[1]!;
    let text = this.#scratch[2]!;
    let textNext = this.#scratch[3]!;
    xlpsInto(key, this.#h, counter);
    text.set(message);
    for (let index = 0; index < 12; index += 1) {
      xlpsInto(textNext, text, key);
      [text, textNext] = [textNext, text];
      xlpsInto(keyNext, key, C[index]!);
      [key, keyNext] = [keyNext, key];
    }
    xorFourInto(this.#h, this.#h, text, key, message);
  }

  #processBlock(block: Uint8Array): void {
    this.#compress(block, this.#n);
    addUint(this.#n, BLOCK_SIZE * 8);
    add(this.#sigma, block);
  }

  #finalize(): Uint8Array {
    const padded = new Uint8Array(BLOCK_SIZE);
    padded.set(this.#buffer.subarray(0, this.#buffered));
    padded[this.#buffered] = 1;
    this.#compress(padded, this.#n);
    addUint(this.#n, this.#buffered * 8);
    add(this.#sigma, padded);
    const zero = new Uint8Array(BLOCK_SIZE);
    this.#compress(this.#n, zero);
    this.#compress(this.#sigma, zero);
    return this.size === STREEBOG_256_SIZE ? this.#h.slice(32) : Uint8Array.from(this.#h);
  }
}

export function streebog512(data: Uint8Array): Uint8Array {
  return new StreebogHash(STREEBOG_512_SIZE).update(data).digest();
}

export function streebog256(data: Uint8Array): Uint8Array {
  return new StreebogHash(STREEBOG_256_SIZE).update(data).digest();
}
