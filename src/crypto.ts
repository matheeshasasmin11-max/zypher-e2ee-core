import nacl from "tweetnacl";
import util from "tweetnacl-util";
import * as Crypto from "expo-crypto";
import { setSecureItem, getSecureItem, removeSecureItem } from "./secureKeyVault";

// Bind TweetNaCl's PRNG directly to the OS Cryptographically Secure PRNG (CSPRNG)
// Never uses Math.random().
try {
  nacl.setPRNG((x: Uint8Array, n: number) => {
    const bytes = Crypto.getRandomValues(new Uint8Array(n));
    for (let i = 0; i < n; i++) {
      x[i] = bytes[i];
    }
  });
} catch {}

const PRIVATE_KEY_STORAGE = "@zypher_private_key";
const memoryPrivateKeyCache = new Map<string, string>();

export const clearMemoryKeyCache = () => {
  memoryPrivateKeyCache.clear();
};

/**
 * Generates a new Curve25519 (X25519) key pair on-device.
 * Returns { publicKey, secretKey } encoded in Base64.
 */
export const generateKeyPair = (): { publicKey: string; secretKey: string } => {
  try {
    const keyPair = nacl.box.keyPair();
    return {
      publicKey: util.encodeBase64(keyPair.publicKey),
      secretKey: util.encodeBase64(keyPair.secretKey),
    };
  } catch {
    const secretKey = Crypto.getRandomValues(new Uint8Array(32));
    const keyPair = nacl.box.keyPair.fromSecretKey(secretKey);
    return {
      publicKey: util.encodeBase64(keyPair.publicKey),
      secretKey: util.encodeBase64(keyPair.secretKey),
    };
  }
};

/**
 * Deterministically derives the Curve25519 public key from a Base64 secret key.
 */
export const getPublicKeyFromPrivateKey = (secretKeyBase64: string): string => {
  try {
    const secretKey = util.decodeBase64(secretKeyBase64);
    const keyPair = nacl.box.keyPair.fromSecretKey(secretKey);
    return util.encodeBase64(keyPair.publicKey);
  } catch {
    return "";
  }
};

/**
 * Stores the user's private key inside Android KeyStore / iOS Keychain, scoped strictly by UID.
 * Private keys never leave the user's device.
 */
export const storePrivateKey = async (secretKeyBase64: string, uid: string): Promise<void> => {
  if (!secretKeyBase64 || !uid) return;
  memoryPrivateKeyCache.set(uid, secretKeyBase64);
  await setSecureItem(`${PRIVATE_KEY_STORAGE}_${uid}`, secretKeyBase64);
};

/**
 * Retrieves the user's private key from hardware-backed storage, scoped strictly by UID.
 */
export const getPrivateKey = async (uid: string): Promise<string | null> => {
  if (!uid) return null;
  if (memoryPrivateKeyCache.has(uid)) {
    return memoryPrivateKeyCache.get(uid)!;
  }
  const userKey = await getSecureItem(`${PRIVATE_KEY_STORAGE}_${uid}`);
  if (userKey) {
    memoryPrivateKeyCache.set(uid, userKey);
    return userKey;
  }
  return null;
};

/**
 * Permanently erases the user's private key from memory and hardware storage upon account deletion.
 */
export const clearPrivateKey = async (uid: string): Promise<void> => {
  if (!uid) return;
  memoryPrivateKeyCache.delete(uid);
  await removeSecureItem(`${PRIVATE_KEY_STORAGE}_${uid}`);
};

/**
 * Encrypts a 1-on-1 message using X25519 + XSalsa20-Poly1305 authenticated encryption (`nacl.box`).
 * Generates a fresh 24-byte CSPRNG nonce for every message.
 */
export const encryptMessage = (
  message: string,
  recipientPublicKeyBase64: string,
  senderSecretKeyBase64: string
): string => {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const messageUint8 = util.decodeUTF8(message);

  const recipientPublicKey = util.decodeBase64(recipientPublicKeyBase64);
  const senderSecretKey = util.decodeBase64(senderSecretKeyBase64);

  const encrypted = nacl.box(messageUint8, nonce, recipientPublicKey, senderSecretKey);

  const fullMessage = new Uint8Array(nonce.length + encrypted.length);
  fullMessage.set(nonce);
  fullMessage.set(encrypted, nonce.length);

  return util.encodeBase64(fullMessage);
};

/**
 * Verifies the Poly1305 MAC and decrypts a 1-on-1 message (`nacl.box.open`).
 * Returns `null` if tampered, forged, or decrypted with the wrong key.
 */
export const decryptMessage = (
  encryptedMessageBase64: string,
  senderPublicKeyBase64: string,
  recipientSecretKeyBase64: string
): string | null => {
  if (!encryptedMessageBase64 || !senderPublicKeyBase64 || !recipientSecretKeyBase64) return null;
  try {
    const fullMessage = util.decodeBase64(encryptedMessageBase64);
    if (!fullMessage || fullMessage.length <= nacl.box.nonceLength) return null;

    const nonce = fullMessage.slice(0, nacl.box.nonceLength);
    const message = fullMessage.slice(nacl.box.nonceLength);

    const senderPublicKey = util.decodeBase64(senderPublicKeyBase64);
    const recipientSecretKey = util.decodeBase64(recipientSecretKeyBase64);

    if (
      senderPublicKey.length !== nacl.box.publicKeyLength ||
      recipientSecretKey.length !== nacl.box.secretKeyLength
    ) {
      return null;
    }

    const decrypted = nacl.box.open(message, nonce, senderPublicKey, recipientSecretKey);
    if (!decrypted) return null;

    return util.encodeUTF8(decrypted);
  } catch {
    return null;
  }
};

/**
 * Generates a 256-bit symmetric group key encoded in Base64.
 */
export const generateGroupKey = (): string => {
  const key = nacl.randomBytes(nacl.secretbox.keyLength);
  return util.encodeBase64(key);
};

/**
 * Encrypts a group message using XSalsa20-Poly1305 (`nacl.secretbox`) with a fresh 24-byte CSPRNG nonce.
 */
export const encryptGroupMessage = (message: string, groupKeyBase64: string): string => {
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const messageUint8 = util.decodeUTF8(message);
  const groupKey = util.decodeBase64(groupKeyBase64);

  const encrypted = nacl.secretbox(messageUint8, nonce, groupKey);

  const fullMessage = new Uint8Array(nonce.length + encrypted.length);
  fullMessage.set(nonce);
  fullMessage.set(encrypted, nonce.length);

  return util.encodeBase64(fullMessage);
};

/**
 * Verifies the Poly1305 MAC and decrypts a group message.
 */
export const decryptGroupMessage = (
  encryptedMessageBase64: string,
  groupKeyBase64: string
): string | null => {
  if (!encryptedMessageBase64 || !groupKeyBase64) return null;
  try {
    const fullMessage = util.decodeBase64(encryptedMessageBase64);
    if (!fullMessage || fullMessage.length <= nacl.secretbox.nonceLength) return null;

    const nonce = fullMessage.slice(0, nacl.secretbox.nonceLength);
    const message = fullMessage.slice(nacl.secretbox.nonceLength);
    const groupKey = util.decodeBase64(groupKeyBase64);

    if (groupKey.length !== nacl.secretbox.keyLength) return null;

    const decrypted = nacl.secretbox.open(message, nonce, groupKey);
    if (!decrypted) return null;

    return util.encodeUTF8(decrypted);
  } catch {
    return null;
  }
};
