export interface DerElement {
  readonly tag: number;
  readonly content: Uint8Array;
  readonly full: Uint8Array;
  readonly end: number;
}

export function readDer(input: Uint8Array, offset = 0): DerElement {
  if (offset < 0 || offset + 2 > input.length) throw new RangeError("malformed DER");
  const start = offset;
  const tag = input[offset++]!;
  if ((tag & 0x1f) === 0x1f) throw new RangeError("high-tag-number DER is unsupported");
  let length = input[offset++]!;
  if ((length & 0x80) !== 0) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || offset + count > input.length || input[offset] === 0) throw new RangeError("malformed DER length");
    length = 0;
    for (let index = 0; index < count; index += 1) length = length * 256 + input[offset++]!;
    if (length < 128) throw new RangeError("non-minimal DER length");
  }
  const end = offset + length;
  if (end > input.length) throw new RangeError("DER length exceeds input");
  return { tag, content: input.subarray(offset, end), full: input.subarray(start, end), end };
}

export function readDerChildren(content: Uint8Array): DerElement[] {
  const result: DerElement[] = [];
  let offset = 0;
  while (offset < content.length) { const element = readDer(content, offset); result.push(element); offset = element.end; }
  return result;
}

function lengthBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) throw new RangeError("invalid DER length");
  if (length < 128) return Uint8Array.of(length);
  const bytes: number[] = [];
  for (let value = length; value > 0; value = Math.floor(value / 256)) bytes.unshift(value & 0xff);
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

export function encodeDer(tag: number, content: Uint8Array): Uint8Array {
  return Uint8Array.from([tag, ...lengthBytes(content.length), ...content]);
}

export function encodeSequence(...elements: Uint8Array[]): Uint8Array { return encodeDer(0x30, Uint8Array.from(elements.flatMap((item) => [...item]))); }
export function encodeOctetString(value: Uint8Array): Uint8Array { return encodeDer(0x04, value); }
export function encodeBitString(value: Uint8Array): Uint8Array { return encodeDer(0x03, Uint8Array.from([0, ...value])); }

function encodeBase128(value: number): number[] {
  if (!Number.isSafeInteger(value) || value < 0) throw new RangeError("invalid OID component");
  const result = [value & 0x7f];
  for (value = Math.floor(value / 128); value > 0; value = Math.floor(value / 128)) result.unshift((value & 0x7f) | 0x80);
  return result;
}

export function encodeOid(oid: string): Uint8Array {
  const parts = oid.split(".").map(Number);
  if (parts.length < 2 || parts[0]! < 0 || parts[0]! > 2 || parts[1]! < 0 || (parts[0]! < 2 && parts[1]! > 39)) throw new RangeError("invalid OID");
  const body = [...encodeBase128(parts[0]! * 40 + parts[1]!)];
  for (const part of parts.slice(2)) body.push(...encodeBase128(part));
  return encodeDer(0x06, Uint8Array.from(body));
}

export function decodeOid(element: DerElement): string {
  if (element.tag !== 0x06 || element.content.length === 0) throw new RangeError("malformed DER OID");
  const values: number[] = [];
  let value = 0;
  for (const byte of element.content) {
    if (value > Number.MAX_SAFE_INTEGER / 128) throw new RangeError("DER OID component too large");
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) { values.push(value); value = 0; }
  }
  if ((element.content[element.content.length - 1]! & 0x80) !== 0) throw new RangeError("truncated DER OID");
  const first = values.shift()!;
  const firstArc = first < 40 ? 0 : first < 80 ? 1 : 2;
  return [firstArc, first - firstArc * 40, ...values].join(".");
}
