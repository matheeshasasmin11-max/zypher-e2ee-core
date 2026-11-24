import nacl from "tweetnacl";
import util from "tweetnacl-util";
import { randomBytesCSPRNG } from "./crypto";
import { zeroize } from "./hkdf";

export const E2EE_MEDIA_MAGIC_HEADER = "ZYPHER_E2EE_V1:";
const E2EE_MAGIC_BYTES = new Uint8Array(
  E2EE_MEDIA_MAGIC_HEADER.split("").map((c) => c.charCodeAt(0))
);

/**
 * Checks whether a binary blob carries the ZypherChats Zero-Knowledge E2EE media header.
 */
export function hasEncryptedMediaMagicHeader(bytes: Uint8Array): boolean {
  if (bytes.length < E2EE_MAGIC_BYTES.length + nacl.secretbox.nonceLength + nacl.secretbox.overheadLength) {
    return false;
  }
  for (let i = 0; i < E2EE_MAGIC_BYTES.length; i++) {
    if (bytes[i] !== E2EE_MAGIC_BYTES[i]) return false;
  }
  return true;
}

/**
 * Zero-Knowledge Binary Media Encryption (Photos, Videos, Voice Notes, Documents).
 *
 * 1. Generates a fresh 256-bit (32-byte) ephemeral key and 192-bit (24-byte) nonce via OS CSPRNG.
 * 2. Encrypts and authenticates raw bytes using XSalsa20-Poly1305 (`nacl.secretbox`).
 * 3. Prepends `ZYPHER_E2EE_V1:` + 24-byte nonce + authenticated ciphertext.
 *
 * Cloud object storage receives ONLY `encryptedBytes`.
 * `keyBase64` is transmitted exclusively inside the Double Ratchet E2EE message envelope (`#zk=...`),
 * ensuring neither object storage nor database servers ever receive the media decryption key.
 */
export function encryptBinaryMediaPayload(plainBytes: Uint8Array): {
  encryptedBytes: Uint8Array;
  keyBase64: string;
} {
  const key = randomBytesCSPRNG(nacl.secretbox.keyLength);
  const nonce = randomBytesCSPRNG(nacl.secretbox.nonceLength);

  try {
    const cipherBytes = nacl.secretbox(plainBytes, nonce, key);
    const combined = new Uint8Array(E2EE_MAGIC_BYTES.length + nonce.length + cipherBytes.length);
    combined.set(E2EE_MAGIC_BYTES, 0);
    combined.set(nonce, E2EE_MAGIC_BYTES.length);
    combined.set(cipherBytes, E2EE_MAGIC_BYTES.length + nonce.length);

    return {
      encryptedBytes: combined,
      keyBase64: util.encodeBase64(key),
    };
  } finally {
    zeroize(key);
    zeroize(nonce);
  }
}

/**
 * Verifies Poly1305 MAC and decrypts a Zero-Knowledge binary media payload on-device.
 * Returns `null` if the payload was tampered with or the key is invalid.
 */
export function decryptBinaryMediaPayload(
  encryptedBytes: Uint8Array,
  keyBase64: string
): Uint8Array | null {
  if (!hasEncryptedMediaMagicHeader(encryptedBytes) || !keyBase64) return null;
  let key: Uint8Array | null = null;
  try {
    key = util.decodeBase64(keyBase64);
    if (key.length !== nacl.secretbox.keyLength) return null;

    const nonceStart = E2EE_MAGIC_BYTES.length;
    const cipherStart = nonceStart + nacl.secretbox.nonceLength;

    const nonce = encryptedBytes.slice(nonceStart, cipherStart);
    const cipherBytes = encryptedBytes.slice(cipherStart);

    const opened = nacl.secretbox.open(cipherBytes, nonce, key);
    return opened || null;
  } catch {
    return null;
  } finally {
    zeroize(key);
  }
}
