import { streebog256, streebog512 } from "@gostcrypto/hash";
import {
  isOnCurve,
  scalarMultiply,
  type GostCurve,
  type GostPoint,
  type GostPrivateKey,
  type GostPublicKey,
} from "@gostcrypto/signature";

export function ukmFromBytes(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index]!);
  }
  return value;
}

export function sharedPoint(privateKey: GostPrivateKey, publicKey: GostPublicKey, ukm: bigint): GostPoint {
  if (privateKey.curve !== publicKey.curve) {
    throw new RangeError("VKO keys use different curves");
  }
  if (ukm <= 0n) {
    throw new RangeError("VKO UKM must be positive");
  }
  if (!isOnCurve(privateKey.curve, publicKey)) {
    throw new RangeError("VKO public key is not on the curve");
  }
  const curve = privateKey.curve;
  const cofactor = curve.m / curve.q;
  const scalar = (cofactor * ukm * privateKey.d) % curve.q;
  if (scalar === 0n) {
    throw new RangeError("VKO shared point is degenerate");
  }
  const point = scalarMultiply(curve, publicKey, scalar);
  if (point === null) {
    throw new RangeError("VKO shared point is degenerate");
  }
  return point;
}

function writeLittleEndian(value: bigint, target: Uint8Array): void {
  let current = value;
  for (let index = 0; index < target.length; index += 1) {
    target[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  if (current !== 0n) {
    throw new RangeError("VKO coordinate does not fit the curve size");
  }
}

export function encodeSharedPoint(curve: GostCurve, point: GostPoint): Uint8Array {
  const encoded = new Uint8Array(curve.size * 2);
  writeLittleEndian(point.x, encoded.subarray(0, curve.size));
  writeLittleEndian(point.y, encoded.subarray(curve.size));
  return encoded;
}

export function deriveVkoKek256(privateKey: GostPrivateKey, publicKey: GostPublicKey, ukm: bigint): Uint8Array {
  return streebog256(encodeSharedPoint(privateKey.curve, sharedPoint(privateKey, publicKey, ukm)));
}

export function deriveVkoKek512(privateKey: GostPrivateKey, publicKey: GostPublicKey, ukm: bigint): Uint8Array {
  return streebog512(encodeSharedPoint(privateKey.curve, sharedPoint(privateKey, publicKey, ukm)));
}
