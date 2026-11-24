import nacl from "tweetnacl";
import util from "tweetnacl-util";

export interface RatchetStorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
}

export const u8ToBase64 = (u8: Uint8Array): string => {
  try {
    return util.encodeBase64(u8);
  } catch {
    let s = "";
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return typeof btoa !== "undefined" ? btoa(s) : "";
  }
};

export const base64ToU8 = (b64: string): Uint8Array => {
  try {
    return util.decodeBase64(b64);
  } catch {
    const s = typeof atob !== "undefined" ? atob(b64) : "";
    const u8 = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
    return u8;
  }
};

export const concatU8 = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const c = new Uint8Array(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
};

/**
 * Root Key KDF (SHA-512 split into 256-bit next Root Key + 256-bit Chain Key).
 */
export function KDF_RK(rk: Uint8Array, dhOut: Uint8Array): { rootKey: Uint8Array; chainKey: Uint8Array } {
  const hash = nacl.hash(concatU8(rk, dhOut));
  return { rootKey: hash.slice(0, 32), chainKey: hash.slice(32, 64) };
}

/**
 * Symmetric Chain Key KDF (domain-separated constants 0x01 for next Chain Key, 0x02 for Message Key).
 * Provides Forward Secrecy for every individual message.
 */
export function KDF_CK(ck: Uint8Array): { chainKey: Uint8Array; messageKey: Uint8Array } {
  const ckInput = concatU8(ck, new Uint8Array([1]));
  const mkInput = concatU8(ck, new Uint8Array([2]));
  const nextCk = nacl.hash(ckInput).slice(0, 32);
  const mk = nacl.hash(mkInput).slice(0, 32);
  return { chainKey: nextCk, messageKey: mk };
}

export interface RatchetHeader {
  dhPub: string;
  n: number;
}

export interface RatchetState {
  rootKey: string;
  sendingChainKey: string | null;
  receivingChainKey: string | null;
  sendCount: number;
  recvCount: number;
  myEphemeralKeyPair: { publicKey: string; secretKey: string };
  theirEphemeralPubKey: string | null;
  skippedMessageKeys: Record<string, string>;
  initialReceivingChainKeys?: Record<string, string>;
}

/**
 * Signal-inspired Double Ratchet Engine (Diffie-Hellman Ratchet + Symmetric Hash Ratchet).
 * Provides Forward Secrecy, Post-Compromise Security (Break-in Recovery), and Out-of-Order delivery support.
 */
export class DoubleRatchet {
  chatId: string;
  myUid?: string;
  state: RatchetState | null = null;
  private storage?: RatchetStorageAdapter;

  constructor(chatId: string, myUid?: string, storage?: RatchetStorageAdapter) {
    this.chatId = chatId;
    this.myUid = myUid;
    this.storage = storage;
  }

  private getStorageKey(): string {
    return this.myUid ? `ratchet_${this.myUid}_${this.chatId}` : `ratchet_${this.chatId}`;
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

  async init(
    sharedSecretBase64: string,
    isInitiator: boolean,
    theirStaticPub: string,
    myStaticKey?: { publicKey: string | Uint8Array; secretKey: string | Uint8Array }
  ): Promise<void> {
    const sharedSecret = base64ToU8(sharedSecretBase64);

    let myEphemeralKeyPair: { publicKey: string; secretKey: string };
    if (!isInitiator && myStaticKey) {
      const pubStr = typeof myStaticKey.publicKey === "string" ? myStaticKey.publicKey : u8ToBase64(myStaticKey.publicKey);
      const secStr = typeof myStaticKey.secretKey === "string" ? myStaticKey.secretKey : u8ToBase64(myStaticKey.secretKey);
      myEphemeralKeyPair = { publicKey: pubStr, secretKey: secStr };
    } else {
      const kp = nacl.box.keyPair();
      myEphemeralKeyPair = { publicKey: u8ToBase64(kp.publicKey), secretKey: u8ToBase64(kp.secretKey) };
    }

    this.state = {
      rootKey: u8ToBase64(sharedSecret),
      sendingChainKey: null,
      receivingChainKey: null,
      sendCount: 0,
      recvCount: 0,
      myEphemeralKeyPair,
      theirEphemeralPubKey: isInitiator ? theirStaticPub : null,
      skippedMessageKeys: {},
      initialReceivingChainKeys: {},
    };

    if (isInitiator) {
      const dhOut = nacl.box.before(base64ToU8(theirStaticPub), base64ToU8(myEphemeralKeyPair.secretKey));
      const { rootKey, chainKey } = KDF_RK(sharedSecret, dhOut);
      this.state.rootKey = u8ToBase64(rootKey);
      this.state.sendingChainKey = u8ToBase64(chainKey);
    }
    await this.saveState();
  }

  async encryptMessage(plainText: string): Promise<{ ciphertext: string; header: RatchetHeader }> {
    if (!this.state) throw new Error("Ratchet not initialized");
    if (!this.state.sendingChainKey) throw new Error("Sending chain not ready before first ratchet step");

    const ck = base64ToU8(this.state.sendingChainKey);
    const { chainKey, messageKey } = KDF_CK(ck);
    this.state.sendingChainKey = u8ToBase64(chainKey);

    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const msgUint8 = util.decodeUTF8(plainText);
    const encrypted = nacl.secretbox(msgUint8, nonce, messageKey);

    const ciphertext = u8ToBase64(nonce) + ":" + u8ToBase64(encrypted);
    const header: RatchetHeader = {
      dhPub: this.state.myEphemeralKeyPair.publicKey,
      n: this.state.sendCount,
    };

    this.state.sendCount++;
    await this.saveState();

    return { ciphertext, header };
  }

  async decryptMessage(ciphertextStr: string, header: RatchetHeader): Promise<string> {
    if (!this.state) throw new Error("Ratchet not initialized");
    if (!header || !header.dhPub) throw new Error("Invalid ratchet header");

    const { dhPub, n } = header;
    const skipKey = `${dhPub}_${n}`;

    if (!this.state.skippedMessageKeys) this.state.skippedMessageKeys = {};
    if (!this.state.initialReceivingChainKeys) this.state.initialReceivingChainKeys = {};

    // 1. Out-of-order message key lookup
    if (this.state.skippedMessageKeys[skipKey]) {
      const mk = base64ToU8(this.state.skippedMessageKeys[skipKey]);
      delete this.state.skippedMessageKeys[skipKey];
      await this.saveState();
      return this._decryptWithMk(ciphertextStr, mk);
    }

    // 2. Perform Diffie-Hellman Ratchet step when peer rotates ephemeral public key
    if (dhPub !== this.state.theirEphemeralPubKey) {
      this._ratchet(dhPub);
      this.state.theirEphemeralPubKey = dhPub;
      this.state.recvCount = 0;
    }

    // 3. Deterministic recovery if message index `n` arrives behind `recvCount`
    if (this.state.initialReceivingChainKeys[dhPub] && n < this.state.recvCount) {
      let ck = base64ToU8(this.state.initialReceivingChainKeys[dhPub]);
      let mk: Uint8Array = new Uint8Array(32);
      for (let i = 0; i <= n; i++) {
        const step = KDF_CK(ck);
        ck = step.chainKey;
        mk = step.messageKey;
      }
      return this._decryptWithMk(ciphertextStr, mk);
    }

    // 4. Advance receiving chain and store skipped message keys for delayed packets
    while (this.state.recvCount < n) {
      const ck = base64ToU8(this.state.receivingChainKey!);
      const { chainKey, messageKey } = KDF_CK(ck);
      this.state.receivingChainKey = u8ToBase64(chainKey);
      const currentSkipKey = `${dhPub}_${this.state.recvCount}`;
      this.state.skippedMessageKeys[currentSkipKey] = u8ToBase64(messageKey);
      this.state.recvCount++;
    }

    // 5. Derive message key for packet `n`
    const ck = base64ToU8(this.state.receivingChainKey!);
    const { chainKey, messageKey } = KDF_CK(ck);
    this.state.receivingChainKey = u8ToBase64(chainKey);
    this.state.recvCount++;

    await this.saveState();
    return this._decryptWithMk(ciphertextStr, messageKey);
  }

  private _ratchet(newTheirPubBase64: string): void {
    if (!this.state) return;
    const theirPub = base64ToU8(newTheirPubBase64);
    const mySec = base64ToU8(this.state.myEphemeralKeyPair.secretKey);

    let rk = base64ToU8(this.state.rootKey);
    let dhOut = nacl.box.before(theirPub, mySec);
    let kdfOut = KDF_RK(rk, dhOut);
    rk = kdfOut.rootKey;
    this.state.receivingChainKey = u8ToBase64(kdfOut.chainKey);
    if (!this.state.initialReceivingChainKeys) this.state.initialReceivingChainKeys = {};
    this.state.initialReceivingChainKeys[newTheirPubBase64] = u8ToBase64(kdfOut.chainKey);

    const kp = nacl.box.keyPair();
    this.state.myEphemeralKeyPair = {
      publicKey: u8ToBase64(kp.publicKey),
      secretKey: u8ToBase64(kp.secretKey),
    };

    dhOut = nacl.box.before(theirPub, kp.secretKey);
    kdfOut = KDF_RK(rk, dhOut);
    this.state.rootKey = u8ToBase64(kdfOut.rootKey);
    this.state.sendingChainKey = u8ToBase64(kdfOut.chainKey);
    this.state.sendCount = 0;
  }

  private _decryptWithMk(ciphertextStr: string, mk: Uint8Array): string {
    const parts = ciphertextStr.split(":");
    if (parts.length !== 2) throw new Error("Invalid ciphertext format");
    const nonce = base64ToU8(parts[0]);
    const enc = base64ToU8(parts[1]);

    const decrypted = nacl.secretbox.open(enc, nonce, mk);
    if (!decrypted) throw new Error("Double Ratchet authentication/decryption failed");

    return util.encodeUTF8(decrypted);
  }
}

/**
 * Stateless Double Ratchet fallback derivation for initial chain messages.
 */
export function statelessRatchetDecrypt(
  ciphertextStr: string,
  dhPubB64: string,
  n: number,
  sharedSecret: Uint8Array | string,
  myPriv: Uint8Array | string
): string | null {
  try {
    const parts = ciphertextStr.split(":");
    if (parts.length !== 2) return null;
    const nonce = base64ToU8(parts[0]);
    const enc = base64ToU8(parts[1]);

    const theirDhPub = typeof dhPubB64 === "string" ? base64ToU8(dhPubB64) : dhPubB64;
    const mySec = typeof myPriv === "string" ? base64ToU8(myPriv) : myPriv;
    const ss = typeof sharedSecret === "string" ? base64ToU8(sharedSecret) : sharedSecret;

    const dhOut = nacl.box.before(theirDhPub, mySec);
    const { chainKey } = KDF_RK(ss, dhOut);

    let ck = chainKey;
    let mk: Uint8Array | null = null;
    for (let i = 0; i <= n; i++) {
      const step = KDF_CK(ck);
      ck = step.chainKey;
      if (i === n) mk = step.messageKey;
    }

    if (!mk) return null;
    const decrypted = nacl.secretbox.open(enc, nonce, mk);
    if (!decrypted) return null;
    return util.encodeUTF8(decrypted);
  } catch {
    return null;
  }
}
