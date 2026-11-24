import nacl from "tweetnacl";
import util from "tweetnacl-util";
import * as Crypto from "expo-crypto";

export const E2EE_MEDIA_MAGIC_HEADER = "ZYPHER_E2EE_V1:";
const E2EE_MAGIC_BYTES = new Uint8Array(
  E2EE_MEDIA_MAGIC_HEADER.split("").map((c) => c.charCodeAt(0))
);

/**
 * Checks whether a binary blob carries the ZypherChats Zero-Knowledge E2EE media header.
 */
export function hasEncryptedMediaMagicHeader(bytes: Uint8Array): boolean {
  if (bytes.length < E2EE_MAGIC_BYTES.length + nacl.secretbox.nonceLength) return false;
  for (let i = 0; i < E2EE_MAGIC_BYTES.length; i++) {
    if (bytes[i] !== E2EE_MAGIC_BYTES[i]) return false;
  }
  return true;
}

/**
 * Zero-Knowledge Binary Media Encryption (Photos, Videos, Voice Notes, Documents).
 *
 * 1. Generates a fresh 256-bit (32-byte) ephemeral key and 192-bit (24-byte) nonce via CSPRNG.
 * 2. Encrypts and authenticates raw bytes using XSalsa20-Poly1305 (`nacl.secretbox`).
 * 3. Prepends `ZYPHER_E2EE_V1:` + 24-byte nonce + authenticated ciphertext.
 *
 * Cloud object storage receives ONLY `encryptedBytes`.
 * `keyBase64` is transmitted exclusively inside the E2EE message ciphertext envelope (`#zk=...`),
 * ensuring neither object storage nor database servers ever see the media decryption key.
 */
export function encryptBinaryMediaPayload(plainBytes: Uint8Array): {
  encryptedBytes: Uint8Array;
  keyBase64: string;
} {
  let key: Uint8Array;
  let nonce: Uint8Array;
  try {
    key = Crypto.getRandomValues(new Uint8Array(nacl.secretbox.keyLength));
    nonce = Crypto.getRandomValues(new Uint8Array(nacl.secretbox.nonceLength));
  } catch {
    key = nacl.randomBytes(nacl.secretbox.keyLength);
    nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  }

  const cipherBytes = nacl.secretbox(plainBytes, nonce, key);
  const combined = new Uint8Array(E2EE_MAGIC_BYTES.length + nonce.length + cipherBytes.length);
  combined.set(E2EE_MAGIC_BYTES, 0);
  combined.set(nonce, E2EE_MAGIC_BYTES.length);
  combined.set(cipherBytes, E2EE_MAGIC_BYTES.length + nonce.length);

  return {
    encryptedBytes: combined,
    keyBase64: util.encodeBase64(key),
  };
}

/**
 * Verifies Poly1305 MAC and decrypts a Zero-Knowledge binary media payload on-device.
 * Returns `null` if the payload was modified or the key is invalid.
 */
export function decryptBinaryMediaPayload(
  encryptedBytes: Uint8Array,
  keyBase64: string
): Uint8Array | null {
  if (!hasEncryptedMediaMagicHeader(encryptedBytes) || !keyBase64) return null;
  try {
    const key = util.decodeBase64(keyBase64);
    if (key.length !== nacl.secretbox.keyLength) return null;

    const nonceStart = E2EE_MAGIC_BYTES.length;
    const cipherStart = nonceStart + nacl.secretbox.nonceLength;

    const nonce = encryptedBytes.slice(nonceStart, cipherStart);
    const cipherBytes = encryptedBytes.slice(cipherStart);

    const opened = nacl.secretbox.open(cipherBytes, nonce, key);
    return opened || null;
  } catch {
    return null;
  }
}
