import nacl from "tweetnacl";
import {
  encryptMessage,
  decryptMessage,
  getPrivateKey,
  storePrivateKey,
  generateKeyPair,
  getPublicKeyFromPrivateKey,
} from "./crypto";
import {
  DoubleRatchet,
  RatchetHeader,
  RatchetStorageAdapter,
  base64ToU8,
  u8ToBase64,
} from "./ratchet";
import { isAllZero, zeroize } from "./hkdf";

export class ProtocolDowngradeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtocolDowngradeError";
  }
}

export class IdentityKeyChangedError extends Error {
  readonly peerUid: string;
  readonly previousPublicKey: string;
  readonly newPublicKey: string;

  constructor(peerUid: string, previousPublicKey: string, newPublicKey: string) {
    super(
      `Security alert: Public key for peer ${peerUid} changed since first contact. ` +
        `Verify the 20-character safety code out-of-band before approving the new key.`
    );
    this.name = "IdentityKeyChangedError";
    this.peerUid = peerUid;
    this.previousPublicKey = previousPublicKey;
    this.newPublicKey = newPublicKey;
  }
}

export interface ChatKeys {
  myPublicKey: string;
  myPrivateKey: string;
  theirPublicKey: string;
  useDoubleRatchet: boolean;
}

export interface E2EEPolicyOptions {
  /**
   * When false (default), static `e2e:` envelopes are disabled for both sending and receiving,
   * enforcing forward-secret Double Ratchet (`dr:`) exclusively.
   * Even when set to `true` for legacy migration, once a peer establishes a `dr:` session,
   * subsequent `e2e:` envelopes from that peer are strictly rejected (`ProtocolDowngradeError`).
   */
  allowLegacyStaticFallback?: boolean;
}

/**
 * Pluggable Public-Key Directory Adapter.
 * Notice: Only PUBLIC keys are ever published or fetched from the directory!
 * Private keys never leave the local hardware keystore.
 */
export interface PublicKeyDirectory {
  getUserPublicKey(uid: string): Promise<{ publicKey: string | null; doubleRatchetEnabled?: boolean }>;
  publishMyPublicKey(uid: string, publicKey: string): Promise<void>;
}

/**
 * Bounded LRU cache prevents unbounded memory growth on low-RAM mobile devices.
 */
export class BoundedLRUCache<K, V> extends Map<K, V> {
  private readonly maxSize: number;
  constructor(maxSize: number) {
    super();
    this.maxSize = maxSize;
  }
  get(key: K): V | undefined {
    if (!super.has(key)) return undefined;
    const val = super.get(key)!;
    super.delete(key);
    super.set(key, val);
    return val;
  }
  set(key: K, value: V): this {
    if (super.has(key)) {
      super.delete(key);
    } else if (this.size >= this.maxSize) {
      const oldestKey = this.keys().next().value;
      if (oldestKey !== undefined) {
        super.delete(oldestKey);
      }
    }
    super.set(key, value);
    return this;
  }
}

const keysCache = new Map<string, ChatKeys>();
const decryptedLocalCache = new BoundedLRUCache<string, string>(500);
const ratchetInstances = new Map<string, DoubleRatchet>();
const pinnedPeerKeysMemory = new Map<string, string>();
const ratchetPinnedPeersMemory = new Set<string>();

export function clearE2ECache(): void {
  keysCache.clear();
  decryptedLocalCache.clear();
  ratchetInstances.clear();
  pinnedPeerKeysMemory.clear();
  ratchetPinnedPeersMemory.clear();
}

function getPeerPinStorageKey(myUid: string, peerUid: string): string {
  return `tofu_pubkey_${myUid}_${peerUid}`;
}

function getRatchetPinStorageKey(myUid: string, peerUid: string): string {
  return `ratchet_pinned_${myUid}_${peerUid}`;
}

/**
 * Explicitly approves a contact's new public key after out-of-band safety code verification.
 */
export async function approvePeerKeyChange(
  myUid: string,
  peerUid: string,
  newPublicKey: string,
  storage?: RatchetStorageAdapter
): Promise<void> {
  const pinKey = getPeerPinStorageKey(myUid, peerUid);
  pinnedPeerKeysMemory.set(pinKey, newPublicKey);
  if (storage) {
    await storage.setItem(pinKey, newPublicKey);
  }
  keysCache.delete(`${myUid}_${peerUid}`);
}

async function verifyAndPinPeerKey(
  myUid: string,
  peerUid: string,
  fetchedPublicKey: string,
  storage?: RatchetStorageAdapter
): Promise<void> {
  const pinKey = getPeerPinStorageKey(myUid, peerUid);
  let existingPin: string | null = pinnedPeerKeysMemory.get(pinKey) ?? null;
  if (!existingPin && storage) {
    existingPin = await storage.getItem(pinKey);
  }
  if (existingPin && existingPin !== fetchedPublicKey) {
    throw new IdentityKeyChangedError(peerUid, existingPin, fetchedPublicKey);
  }
  if (!existingPin) {
    pinnedPeerKeysMemory.set(pinKey, fetchedPublicKey);
    if (storage) {
      await storage.setItem(pinKey, fetchedPublicKey);
    }
  }
}

async function markPeerRatchetPinned(
  myUid: string,
  peerUid: string,
  storage?: RatchetStorageAdapter
): Promise<void> {
  const key = getRatchetPinStorageKey(myUid, peerUid);
  ratchetPinnedPeersMemory.add(key);
  if (storage) {
    await storage.setItem(key, "1");
  }
}

async function isPeerRatchetPinned(
  myUid: string,
  peerUid: string,
  storage?: RatchetStorageAdapter
): Promise<boolean> {
  const key = getRatchetPinStorageKey(myUid, peerUid);
  if (ratchetPinnedPeersMemory.has(key)) return true;
  if (storage) {
    const persisted = await storage.getItem(key);
    if (persisted === "1") {
      ratchetPinnedPeersMemory.add(key);
      return true;
    }
  }
  return false;
}

/**
 * Resolves canonical E2EE keys between `myUid` and `theirUid` with Trust-On-First-Use (TOFU) key pinning.
 * Throws `IdentityKeyChangedError` if the directory serves a substituted public key for a previously pinned peer.
 */
export async function resolveChatKeys(
  myUid: string,
  theirUid: string,
  directory: PublicKeyDirectory,
  storage?: RatchetStorageAdapter
): Promise<ChatKeys | null> {
  if (!myUid || !theirUid) return null;
  const cid = `${myUid}_${theirUid}`;
  if (keysCache.has(cid)) return keysCache.get(cid)!;

  let myPrivateKey = await getPrivateKey(myUid);
  let myPublicKey: string;

  if (myPrivateKey) {
    myPublicKey = getPublicKeyFromPrivateKey(myPrivateKey);
  } else {
    const kp = generateKeyPair();
    myPrivateKey = kp.secretKey;
    myPublicKey = kp.publicKey;
    await storePrivateKey(myPrivateKey, myUid);
    await directory.publishMyPublicKey(myUid, myPublicKey);
  }

  const [meRemote, peerRemote] = await Promise.all([
    directory.getUserPublicKey(myUid),
    directory.getUserPublicKey(theirUid),
  ]);

  if (meRemote.publicKey !== myPublicKey) {
    await directory.publishMyPublicKey(myUid, myPublicKey);
  }

  if (!peerRemote.publicKey) return null;

  await verifyAndPinPeerKey(myUid, theirUid, peerRemote.publicKey, storage);

  const keys: ChatKeys = {
    myPublicKey,
    myPrivateKey,
    theirPublicKey: peerRemote.publicKey,
    useDoubleRatchet: meRemote.doubleRatchetEnabled !== false && peerRemote.doubleRatchetEnabled !== false,
  };
  keysCache.set(cid, keys);
  return keys;
}

export async function getRatchet(
  chatId: string,
  keys: ChatKeys,
  isInitiator: boolean,
  myUid?: string,
  storage?: RatchetStorageAdapter,
  associatedDataBase64?: string
): Promise<DoubleRatchet> {
  const instanceKey = `${myUid || ""}_${chatId}`;
  if (ratchetInstances.has(instanceKey)) return ratchetInstances.get(instanceKey)!;

  const r = new DoubleRatchet(chatId, myUid, storage);
  const state = await r.loadState();
  const needsReinit =
    !state ||
    (!isInitiator &&
      state.recvCount === 0 &&
      !state.theirEphemeralPubKey &&
      state.myEphemeralKeyPair?.publicKey !== keys.myPublicKey);

  if (needsReinit) {
    const mySec = base64ToU8(keys.myPrivateKey);
    const theirPub = base64ToU8(keys.theirPublicKey);
    const rawShared = nacl.scalarMult(mySec, theirPub);
    zeroize(mySec);
    if (isAllZero(rawShared)) {
      zeroize(rawShared);
      throw new Error("Rejected low-order peer public key");
    }
    const sharedSecret = u8ToBase64(rawShared);
    zeroize(rawShared);

    const canonicalAd =
      associatedDataBase64 ??
      u8ToBase64(
        new Uint8Array([
          ...base64ToU8([keys.myPublicKey, keys.theirPublicKey].sort()[0]),
          ...base64ToU8([keys.myPublicKey, keys.theirPublicKey].sort()[1]),
        ])
      );

    await r.init(
      sharedSecret,
      isInitiator,
      keys.theirPublicKey,
      {
        publicKey: keys.myPublicKey,
        secretKey: keys.myPrivateKey,
      },
      canonicalAd
    );
  }

  ratchetInstances.set(instanceKey, r);
  return r;
}

/**
 * Encrypts outgoing plaintext into a Double Ratchet envelope (`dr:<nonce>:<cipher>`).
 * Refuses static `e2e:` fallback unless `policy.allowLegacyStaticFallback` is explicitly enabled AND peer is not ratchet-pinned.
 */
export async function encryptMsg(
  text: string,
  keys: ChatKeys,
  chatId?: string,
  isInitiator?: boolean,
  myUid?: string,
  peerUid?: string,
  storage?: RatchetStorageAdapter,
  policy: E2EEPolicyOptions = {}
): Promise<{ enc: string; ratchetHeader?: RatchetHeader }> {
  if (!text) return { enc: "" };

  if (keys.useDoubleRatchet && chatId && isInitiator !== undefined) {
    const ratchet = await getRatchet(chatId, keys, isInitiator, myUid, storage);
    const { ciphertext, header } = await ratchet.encryptMessage(text);
    if (myUid && peerUid) {
      await markPeerRatchetPinned(myUid, peerUid, storage);
    }
    const enc = "dr:" + ciphertext;
    decryptedLocalCache.set(enc, text);
    return { enc, ratchetHeader: header };
  }

  if (!policy.allowLegacyStaticFallback) {
    throw new ProtocolDowngradeError(
      "Refusing to encrypt without Double Ratchet: static e2e: envelopes are disabled by default policy."
    );
  }

  if (myUid && peerUid && (await isPeerRatchetPinned(myUid, peerUid, storage))) {
    throw new ProtocolDowngradeError(
      `Refusing to downgrade session with ${peerUid} from Double Ratchet (dr:) to static encryption (e2e:).`
    );
  }

  const enc = "e2e:" + encryptMessage(text, keys.theirPublicKey, keys.myPrivateKey);
  decryptedLocalCache.set(enc, text);
  return { enc };
}

/**
 * Decrypts an incoming E2EE envelope (`dr:...`) strictly on-device.
 * Enforces anti-downgrade pinning: rejects `e2e:` static packets when strict mode is active (default)
 * or once any `dr:` session has been established with `chatPartnerUid`.
 */
export async function decryptMsg(
  ciphertext: string,
  keys: ChatKeys,
  msgSenderId: string,
  myUid: string,
  chatPartnerUid: string,
  chatId?: string,
  ratchetHeader?: RatchetHeader,
  storage?: RatchetStorageAdapter,
  policy: E2EEPolicyOptions = {}
): Promise<string> {
  if (!ciphertext) return "";

  if (!ciphertext.startsWith("dr:") && !ciphertext.startsWith("e2e:")) {
    throw new ProtocolDowngradeError("Rejected unencrypted plaintext payload on an E2EE channel");
  }

  if (ciphertext.startsWith("dr:")) {
    if (decryptedLocalCache.has(ciphertext)) {
      await markPeerRatchetPinned(myUid, chatPartnerUid, storage);
      return decryptedLocalCache.get(ciphertext)!;
    }
    if (!chatId || !ratchetHeader) {
      throw new Error("Missing Double Ratchet header or chatId for dr: envelope");
    }

    const rawCipher = ciphertext.slice(3);
    const isInitiator = myUid < chatPartnerUid;
    const ratchet = await getRatchet(chatId, keys, isInitiator, myUid, storage);
    const dec = await ratchet.decryptMessage(rawCipher, ratchetHeader);

    // Permanently pin this peer to Double Ratchet so no future attacker can downgrade to `e2e:`
    await markPeerRatchetPinned(myUid, chatPartnerUid, storage);
    decryptedLocalCache.set(ciphertext, dec);
    return dec;
  }

  // Incoming `e2e:` envelope: check strict anti-downgrade policy BEFORE attempting decryption
  if (!policy.allowLegacyStaticFallback) {
    throw new ProtocolDowngradeError(
      "Rejected static e2e: envelope: strict Double Ratchet mode requires forward-secret dr: envelopes."
    );
  }

  if (await isPeerRatchetPinned(myUid, chatPartnerUid, storage)) {
    throw new ProtocolDowngradeError(
      `Blocked protocol downgrade attack: peer ${chatPartnerUid} is pinned to Double Ratchet (dr:), rejected e2e: packet.`
    );
  }

  if (decryptedLocalCache.has(ciphertext)) {
    return decryptedLocalCache.get(ciphertext)!;
  }

  const encData = ciphertext.slice(4);
  const senderPub = msgSenderId === myUid ? keys.myPublicKey : keys.theirPublicKey;
  const decrypted = decryptMessage(encData, senderPub, keys.myPrivateKey);

  if (!decrypted) {
    throw new Error("Static E2EE MAC verification failed");
  }

  decryptedLocalCache.set(ciphertext, decrypted);
  return decrypted;
}
