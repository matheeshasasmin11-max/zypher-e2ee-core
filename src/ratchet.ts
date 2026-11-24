import nacl from "tweetnacl";
import util from "tweetnacl-util";
import { hkdfSha512, hmacSha512, isAllZero, zeroize } from "./hkdf";
import { ensureCSPRNG } from "./crypto";

export const MAX_SKIP = 1000;
export const MAX_TOTAL_SKIPPED_KEYS = 2000;

const RK_HKDF_INFO = "ZypherChats_DoubleRatchet_RK_v2";
const AEAD_HKDF_PREFIX = "ZypherChats_DoubleRatchet_AEAD_v2:";

export interface RatchetStorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
}

export const u8ToBase64 = (u8: Uint8Array): string => util.encodeBase64(u8);
export const base64ToU8 = (b64: string): Uint8Array => util.decodeBase64(b64);

function safeDH(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (secretKey.length !== 32 || publicKey.length !== 32) {
    throw new Error("Invalid X25519 key length in Double Ratchet");
  }
  const shared = nacl.scalarMult(secretKey, publicKey);
  if (isAllZero(shared)) {
    zeroize(shared);
    throw new Error("Rejected low-order X25519 public key in Double Ratchet (RFC 7748)");
  }
  return shared;
}

/**
 * Signal Double Ratchet Section 5.2: Root Key KDF using RFC 5869 HKDF-SHA512.
 * Salt = current 32-byte Root Key (`rk`), IKM = 32-byte X25519 DH output (`dhOut`).
 * Produces { rootKey (32B), chainKey (32B) }.
 */
export function KDF_RK(rk: Uint8Array, dhOut: Uint8Array): { rootKey: Uint8Array; chainKey: Uint8Array } {
  const okm = hkdfSha512(dhOut, rk, RK_HKDF_INFO, 64);
  const rootKey = okm.slice(0, 32);
  const chainKey = okm.slice(32, 64);
  zeroize(okm);
  return { rootKey, chainKey };
}

/**
 * Signal Double Ratchet Section 3.1: Symmetric Chain Key KDF using RFC 2104 HMAC-SHA512.
 * Uses domain-separated constants 0x01 (next Chain Key) and 0x02 (per-message Key).
 * Guarantees Forward Secrecy: knowing `chainKey_{i+1}` cannot invert HMAC to recover `messageKey_i`.
 */
export function KDF_CK(ck: Uint8Array): { chainKey: Uint8Array; messageKey: Uint8Array } {
  const ckMac = hmacSha512(ck, new Uint8Array([0x01]));
  const mkMac = hmacSha512(ck, new Uint8Array([0x02]));
  const chainKey = ckMac.slice(0, 32);
  const messageKey = mkMac.slice(0, 32);
  zeroize(ckMac);
  zeroize(mkMac);
  return { chainKey, messageKey };
}

/**
 * Derives a header-bound AEAD encryption key from `messageKey`, `nonce`, `header`, and session `associatedData`.
 * Tampering with `dhPub`, `pn`, `n`, `v`, or `associatedData` derives a distinct key and fails Poly1305 MAC verification.
 */
function deriveHeaderBoundCipherKey(
  messageKey: Uint8Array,
  nonce: Uint8Array,
  header: RatchetHeader,
  associatedDataBase64?: string
): Uint8Array {
  const canonicalHeader = `${AEAD_HKDF_PREFIX}v=${header.v ?? 2}|dh=${header.dhPub}|pn=${header.pn ?? 0}|n=${header.n}|ad=${associatedDataBase64 ?? ""}`;
  return hkdfSha512(messageKey, nonce, canonicalHeader, 32);
}

export interface RatchetHeader {
  /** Protocol version (2 = RFC 5869 HKDF + HMAC-SHA512 + Header-Authenticated AEAD) */
  v?: number;
  /** Sender's current ephemeral X25519 public key (Base64) */
  dhPub: string;
  /** Number of messages sent on the sender's previous sending chain */
  pn: number;
  /** Message index within the current sending chain */
  n: number;
}

export interface RatchetState {
  version: 2;
  rootKey: string;
  sendingChainKey: string | null;
  receivingChainKey: string | null;
  sendCount: number;
  recvCount: number;
  prevSendCount: number;
  myEphemeralKeyPair: { publicKey: string; secretKey: string };
  theirEphemeralPubKey: string | null;
  associatedData?: string;
  /** Bounded map of skipped out-of-order message keys (`${dhPub}_${n}` -> Base64 mk); deleted immediately upon use */
  skippedMessageKeys: Record<string, string>;
  skippedKeyOrder: string[];
}

function cloneState(s: RatchetState): RatchetState {
  return {
    version: 2,
    rootKey: s.rootKey,
    sendingChainKey: s.sendingChainKey,
    receivingChainKey: s.receivingChainKey,
    sendCount: s.sendCount,
    recvCount: s.recvCount,
    prevSendCount: s.prevSendCount ?? 0,
    myEphemeralKeyPair: { ...s.myEphemeralKeyPair },
    theirEphemeralPubKey: s.theirEphemeralPubKey,
    associatedData: s.associatedData,
    skippedMessageKeys: { ...(s.skippedMessageKeys || {}) },
    skippedKeyOrder: [...(s.skippedKeyOrder || Object.keys(s.skippedMessageKeys || {}))],
  };
}

/**
 * Signal Double Ratchet v2 State Machine.
 * - RFC 5869 HKDF-SHA512 Root KDF + RFC 2104 HMAC-SHA512 Chain KDF
 * - Header-Authenticated XSalsa20-Poly1305 AEAD (binds `dhPub`, `pn`, `n`, and X3DH `associatedData`)
 * - Bounded `MAX_SKIP` DoS protection & immediate one-time deletion of consumed message keys
 * - Atomic state transitions (ratchet state advances ONLY after Poly1305 MAC verification succeeds)
 */
export class DoubleRatchet {
  readonly chatId: string;
  readonly myUid?: string;
  state: RatchetState | null = null;
  private storage?: RatchetStorageAdapter;

  constructor(chatId: string, myUid?: string, storage?: RatchetStorageAdapter) {
    this.chatId = chatId;
    this.myUid = myUid;
    this.storage = storage;
  }

  private getStorageKey(): string {
    return this.myUid ? `ratchet_v2_${this.myUid}_${this.chatId}` : `ratchet_v2_${this.chatId}`;
  }

  async loadState(): Promise<RatchetState | null> {
    if (!this.storage) return this.state;
    try {
      const json = await this.storage.getItem(this.getStorageKey());
      if (json) {
        this.state = JSON.parse(json);
        return this.state;
      }
    } catch {}
    return null;
  }

  async saveState(): Promise<void> {
    if (this.state && this.storage) {
      await this.storage.setItem(this.getStorageKey(), JSON.stringify(this.state));
    }
  }

  /**
   * Initializes a Double Ratchet session from a 32-byte shared secret (e.g. X3DH `SK`).
   */
  async init(
    sharedSecretBase64: string,
    isInitiator: boolean,
    theirRatchetPublicKey: string,
    myInitialRatchetKeyPair?: { publicKey: string | Uint8Array; secretKey: string | Uint8Array },
    associatedDataBase64?: string
  ): Promise<void> {
    ensureCSPRNG();
    const sharedSecret = base64ToU8(sharedSecretBase64);
    if (sharedSecret.length !== 32) {
      zeroize(sharedSecret);
      throw new Error("DoubleRatchet.init requires a 32-byte shared secret");
    }

    let myEphemeralKeyPair: { publicKey: string; secretKey: string };
    if (!isInitiator && myInitialRatchetKeyPair) {
      const pubStr =
        typeof myInitialRatchetKeyPair.publicKey === "string"
          ? myInitialRatchetKeyPair.publicKey
          : u8ToBase64(myInitialRatchetKeyPair.publicKey);
      const secStr =
        typeof myInitialRatchetKeyPair.secretKey === "string"
          ? myInitialRatchetKeyPair.secretKey
          : u8ToBase64(myInitialRatchetKeyPair.secretKey);
      myEphemeralKeyPair = { publicKey: pubStr, secretKey: secStr };
    } else {
      const kp = nacl.box.keyPair();
      myEphemeralKeyPair = { publicKey: u8ToBase64(kp.publicKey), secretKey: u8ToBase64(kp.secretKey) };
    }

    this.state = {
      version: 2,
      rootKey: u8ToBase64(sharedSecret),
      sendingChainKey: null,
      receivingChainKey: null,
      sendCount: 0,
      recvCount: 0,
      prevSendCount: 0,
      myEphemeralKeyPair,
      theirEphemeralPubKey: isInitiator ? theirRatchetPublicKey : null,
      associatedData: associatedDataBase64,
      skippedMessageKeys: {},
      skippedKeyOrder: [],
    };

    if (isInitiator) {
      const mySec = base64ToU8(myEphemeralKeyPair.secretKey);
      const theirPub = base64ToU8(theirRatchetPublicKey);
      const dhOut = safeDH(mySec, theirPub);
      const { rootKey, chainKey } = KDF_RK(sharedSecret, dhOut);
      this.state.rootKey = u8ToBase64(rootKey);
      this.state.sendingChainKey = u8ToBase64(chainKey);
      zeroize(mySec);
      zeroize(dhOut);
      zeroize(rootKey);
      zeroize(chainKey);
    }

    zeroize(sharedSecret);
    await this.saveState();
  }

  async encryptMessage(plainText: string): Promise<{ ciphertext: string; header: RatchetHeader }> {
    ensureCSPRNG();
    if (!this.state) throw new Error("Ratchet not initialized");
    if (!this.state.sendingChainKey) throw new Error("Sending chain not ready before initial receiving ratchet step");

    const ck = base64ToU8(this.state.sendingChainKey);
    const { chainKey, messageKey } = KDF_CK(ck);
    zeroize(ck);

    this.state.sendingChainKey = u8ToBase64(chainKey);
    zeroize(chainKey);

    const header: RatchetHeader = {
      v: 2,
      dhPub: this.state.myEphemeralKeyPair.publicKey,
      pn: this.state.prevSendCount,
      n: this.state.sendCount,
    };

    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const cipherKey = deriveHeaderBoundCipherKey(messageKey, nonce, header, this.state.associatedData);
    zeroize(messageKey);

    const msgUint8 = util.decodeUTF8(plainText);
    const encrypted = nacl.secretbox(msgUint8, nonce, cipherKey);
    zeroize(cipherKey);

    const ciphertext = u8ToBase64(nonce) + ":" + u8ToBase64(encrypted);
    this.state.sendCount++;
    await this.saveState();

    return { ciphertext, header };
  }

  async decryptMessage(ciphertextStr: string, header: RatchetHeader): Promise<string> {
    ensureCSPRNG();
    if (!this.state) throw new Error("Ratchet not initialized");
    if (!header || typeof header.dhPub !== "string" || !Number.isInteger(header.n) || header.n < 0) {
      throw new Error("Invalid Double Ratchet header");
    }
    const pn = header.pn ?? 0;
    if (!Number.isInteger(pn) || pn < 0) {
      throw new Error("Invalid Double Ratchet previous chain count");
    }

    // Stage all mutations on a clone so forged ciphertexts cannot corrupt live ratchet state
    const staged = cloneState(this.state);
    const skipKey = `${header.dhPub}_${header.n}`;

    // 1. Check pre-derived skipped message keys (out-of-order delivery)
    if (staged.skippedMessageKeys[skipKey]) {
      const mk = base64ToU8(staged.skippedMessageKeys[skipKey]);
      try {
        const plain = this._decryptAndVerify(ciphertextStr, mk, header, staged.associatedData);
        delete staged.skippedMessageKeys[skipKey];
        staged.skippedKeyOrder = staged.skippedKeyOrder.filter((k) => k !== skipKey);
        this.state = staged;
        await this.saveState();
        return plain;
      } finally {
        zeroize(mk);
      }
    }

    // 2. If peer rotated their ephemeral DH public key, skip remaining keys on previous chain & advance DH ratchet
    if (header.dhPub !== staged.theirEphemeralPubKey) {
      this._skipMessageKeys(staged, pn);
      this._dhRatchet(staged, header.dhPub);
    }

    // 3. Advance current receiving chain up to `header.n` (bounded by MAX_SKIP)
    this._skipMessageKeys(staged, header.n);

    if (!staged.receivingChainKey) {
      throw new Error("Receiving chain uninitialized");
    }

    // 4. Derive the one-time message key for packet `n`
    const ck = base64ToU8(staged.receivingChainKey);
    const { chainKey, messageKey } = KDF_CK(ck);
    zeroize(ck);

    staged.receivingChainKey = u8ToBase64(chainKey);
    staged.recvCount++;
    zeroize(chainKey);

    try {
      const plain = this._decryptAndVerify(ciphertextStr, messageKey, header, staged.associatedData);
      // Commit state mutation ONLY after Poly1305 MAC succeeds
      this.state = staged;
      await this.saveState();
      return plain;
    } finally {
      zeroize(messageKey);
    }
  }

  private _skipMessageKeys(staged: RatchetState, until: number): void {
    if (!staged.receivingChainKey || !staged.theirEphemeralPubKey) return;
    if (staged.recvCount + MAX_SKIP < until) {
      throw new Error(`Double Ratchet exceeded MAX_SKIP (${MAX_SKIP}) — possible DoS header manipulation`);
    }
    while (staged.recvCount < until) {
      const ck = base64ToU8(staged.receivingChainKey);
      const { chainKey, messageKey } = KDF_CK(ck);
      zeroize(ck);

      staged.receivingChainKey = u8ToBase64(chainKey);
      const keyId = `${staged.theirEphemeralPubKey}_${staged.recvCount}`;
      staged.skippedMessageKeys[keyId] = u8ToBase64(messageKey);
      staged.skippedKeyOrder.push(keyId);
      staged.recvCount++;

      zeroize(chainKey);
      zeroize(messageKey);

      while (staged.skippedKeyOrder.length > MAX_TOTAL_SKIPPED_KEYS) {
        const oldest = staged.skippedKeyOrder.shift();
        if (oldest) delete staged.skippedMessageKeys[oldest];
      }
    }
  }

  private _dhRatchet(staged: RatchetState, newTheirPubBase64: string): void {
    const theirPub = base64ToU8(newTheirPubBase64);
    const myOldSec = base64ToU8(staged.myEphemeralKeyPair.secretKey);
    let rk = base64ToU8(staged.rootKey);

    staged.prevSendCount = staged.sendCount;
    staged.sendCount = 0;
    staged.recvCount = 0;
    staged.theirEphemeralPubKey = newTheirPubBase64;

    const dhRecv = safeDH(myOldSec, theirPub);
    zeroize(myOldSec);

    const recvKdf = KDF_RK(rk, dhRecv);
    zeroize(rk);
    zeroize(dhRecv);

    rk = recvKdf.rootKey;
    staged.receivingChainKey = u8ToBase64(recvKdf.chainKey);
    zeroize(recvKdf.chainKey);

    const nextKp = nacl.box.keyPair();
    staged.myEphemeralKeyPair = {
      publicKey: u8ToBase64(nextKp.publicKey),
      secretKey: u8ToBase64(nextKp.secretKey),
    };

    const dhSend = safeDH(nextKp.secretKey, theirPub);
    zeroize(nextKp.secretKey);

    const sendKdf = KDF_RK(rk, dhSend);
    zeroize(rk);
    zeroize(dhSend);

    staged.rootKey = u8ToBase64(sendKdf.rootKey);
    staged.sendingChainKey = u8ToBase64(sendKdf.chainKey);
    zeroize(sendKdf.rootKey);
    zeroize(sendKdf.chainKey);
  }

  private _decryptAndVerify(
    ciphertextStr: string,
    messageKey: Uint8Array,
    header: RatchetHeader,
    associatedDataBase64?: string
  ): string {
    const parts = ciphertextStr.split(":");
    if (parts.length !== 2) throw new Error("Invalid Double Ratchet ciphertext format");
    const nonce = base64ToU8(parts[0]);
    const enc = base64ToU8(parts[1]);
    if (nonce.length !== nacl.secretbox.nonceLength) {
      throw new Error("Invalid nonce length");
    }

    const cipherKey = deriveHeaderBoundCipherKey(messageKey, nonce, header, associatedDataBase64);
    try {
      const decrypted = nacl.secretbox.open(enc, nonce, cipherKey);
      if (!decrypted) {
        throw new Error("Double Ratchet Poly1305 MAC authentication failed");
      }
      return util.encodeUTF8(decrypted);
    } finally {
      zeroize(cipherKey);
    }
  }
}
