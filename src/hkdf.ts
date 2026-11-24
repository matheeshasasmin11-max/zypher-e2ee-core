import nacl from "tweetnacl";
import util from "tweetnacl-util";

const SHA512_BLOCK_SIZE = 128;
const SHA512_HASH_LEN = 64;

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) totalLength += arr.length;
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Overwrites sensitive key material in-place.
 * Note: JavaScript strings are immutable and subject to V8/Hermes GC; sensitive
 * intermediate secrets should be kept in Uint8Array buffers and zeroized after use.
 */
export function zeroize(buffer: Uint8Array | null | undefined): void {
  if (buffer) {
    buffer.fill(0);
  }
}

/**
 * Constant-time check for an all-zero buffer (e.g., RFC 7748 Section 6.1 low-order X25519 point rejection).
 */
export function isAllZero(bytes: Uint8Array): boolean {
  let acc = 0;
  for (let i = 0; i < bytes.length; i++) {
    acc |= bytes[i];
  }
  return acc === 0;
}

/**
 * Constant-time byte array equality check.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * RFC 2104 HMAC-SHA512 built strictly atop TweetNaCl's audited SHA-512 (`nacl.hash`).
 */
export function hmacSha512(key: Uint8Array, message: Uint8Array): Uint8Array {
  const normalizedKey = key.length > SHA512_BLOCK_SIZE ? nacl.hash(key) : key;
  const kPad = new Uint8Array(SHA512_BLOCK_SIZE);
  kPad.set(normalizedKey, 0);

  const iKeyPad = new Uint8Array(SHA512_BLOCK_SIZE);
  const oKeyPad = new Uint8Array(SHA512_BLOCK_SIZE);
  for (let i = 0; i < SHA512_BLOCK_SIZE; i++) {
    iKeyPad[i] = kPad[i] ^ 0x36;
    oKeyPad[i] = kPad[i] ^ 0x5c;
  }

  const innerInput = concatBytes(iKeyPad, message);
  const innerHash = nacl.hash(innerInput);
  const outerInput = concatBytes(oKeyPad, innerHash);
  const mac = nacl.hash(outerInput);

  zeroize(kPad);
  zeroize(iKeyPad);
  zeroize(oKeyPad);
  zeroize(innerInput);
  zeroize(innerHash);
  zeroize(outerInput);

  return mac;
}

/**
 * RFC 5869 Section 2.2: HKDF-Extract(salt, IKM) -> PRK (64 bytes for SHA-512).
 */
export function hkdfExtract(salt: Uint8Array | null | undefined, ikm: Uint8Array): Uint8Array {
  const actualSalt = salt && salt.length > 0 ? salt : new Uint8Array(SHA512_HASH_LEN);
  return hmacSha512(actualSalt, ikm);
}

/**
 * RFC 5869 Section 2.3: HKDF-Expand(PRK, info, L) -> OKM.
 */
export function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (prk.length < SHA512_HASH_LEN) {
    throw new Error("HKDF-Expand requires a PRK of at least HashLen (64) bytes");
  }
  if (length < 0 || length > 255 * SHA512_HASH_LEN) {
    throw new Error(`HKDF-Expand invalid output length: ${length}`);
  }
  if (length === 0) return new Uint8Array(0);

  const n = Math.ceil(length / SHA512_HASH_LEN);
  const okm = new Uint8Array(n * SHA512_HASH_LEN);
  let prevT: Uint8Array = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    const stepInput = concatBytes(prevT, info, new Uint8Array([i]));
    const nextT = hmacSha512(prk, stepInput);
    okm.set(nextT, (i - 1) * SHA512_HASH_LEN);
    zeroize(prevT);
    zeroize(stepInput);
    prevT = nextT;
  }
  zeroize(prevT);

  const result = okm.slice(0, length);
  zeroize(okm);
  return result;
}

/**
 * RFC 5869 HKDF-SHA512 (Extract-and-Expand).
 */
export function hkdfSha512(
  ikm: Uint8Array,
  salt: Uint8Array | null | undefined,
  info: Uint8Array | string,
  length: number
): Uint8Array {
  const infoBytes = typeof info === "string" ? util.decodeUTF8(info) : info;
  const prk = hkdfExtract(salt, ikm);
  try {
    return hkdfExpand(prk, infoBytes, length);
  } finally {
    zeroize(prk);
  }
}
