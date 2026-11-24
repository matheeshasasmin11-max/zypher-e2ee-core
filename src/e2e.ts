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
  statelessRatchetDecrypt,
  base64ToU8,
  u8ToBase64,
} from "./ratchet";

export interface ChatKeys {
  myPublicKey: string;
  myPrivateKey: string;
  theirPublicKey: string;
  useDoubleRatchet: boolean;
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

export function clearE2ECache(): void {
  keysCache.clear();
  decryptedLocalCache.clear();
  ratchetInstances.clear();
}

/**
 * Resolves canonical E2EE keys between `myUid` and `theirUid`.
 * Generates and stores the user's Curve25519 private key locally in hardware storage if absent,
 * and publishes ONLY the corresponding public key to the directory.
 */
export async function resolveChatKeys(
  myUid: string,
  theirUid: string,
  directory: PublicKeyDirectory
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

  const keys: ChatKeys = {
    myPublicKey,
    myPrivateKey,
    theirPublicKey: peerRemote.publicKey,
    useDoubleRatchet: Boolean(meRemote.doubleRatchetEnabled && peerRemote.doubleRatchetEnabled),
  };
  keysCache.set(cid, keys);
  return keys;
}

export async function getRatchet(
  chatId: string,
  keys: ChatKeys,
  isInitiator: boolean,
  myUid?: string,
  storage?: RatchetStorageAdapter
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
    const sharedSecret = u8ToBase64(
      nacl.box.before(base64ToU8(keys.theirPublicKey), base64ToU8(keys.myPrivateKey))
    );
    await r.init(sharedSecret, isInitiator, keys.theirPublicKey, {
      publicKey: keys.myPublicKey,
      secretKey: keys.myPrivateKey,
    });
  }

  ratchetInstances.set(instanceKey, r);
  return r;
}

/**
 * Encrypts outgoing plaintext into a ZypherChats E2EE envelope (`dr:<nonce>:<cipher>` or `e2e:<box>`).
 * Cloud databases receive ONLY this ciphertext envelope; plaintext never leaves the client.
 */
export async function encryptMsg(
  text: string,
  keys: ChatKeys,
  chatId?: string,
  isInitiator?: boolean,
  myUid?: string,
  storage?: RatchetStorageAdapter
): Promise<{ enc: string; ratchetHeader?: RatchetHeader }> {
  if (!text) return { enc: "" };

  if (keys.useDoubleRatchet && chatId && isInitiator !== undefined) {
    const ratchet = await getRatchet(chatId, keys, isInitiator, myUid, storage);
    const { ciphertext, header } = await ratchet.encryptMessage(text);
    const enc = "dr:" + ciphertext;
    decryptedLocalCache.set(enc, text);
    return { enc, ratchetHeader: header };
  }

  const enc = "e2e:" + encryptMessage(text, keys.theirPublicKey, keys.myPrivateKey);
  decryptedLocalCache.set(enc, text);
  return { enc };
}

/**
 * Decrypts an incoming ZypherChats E2EE envelope (`dr:...` or `e2e:...`) strictly on-device.
 */
export async function decryptMsg(
  ciphertext: string,
  keys: ChatKeys,
  msgSenderId: string,
  myUid: string,
  chatPartnerUid: string,
  chatId?: string,
  ratchetHeader?: RatchetHeader,
  storage?: RatchetStorageAdapter
): Promise<string> {
  if (!ciphertext) return "";
  if (!ciphertext.startsWith("e2e:") && !ciphertext.startsWith("dr:")) {
    return ciphertext;
  }

  if (decryptedLocalCache.has(ciphertext)) {
    return decryptedLocalCache.get(ciphertext)!;
  }

  if (ciphertext.startsWith("dr:")) {
    const rawCipher = ciphertext.slice(3);

    if (msgSenderId !== myUid && chatId && ratchetHeader) {
      try {
        const isInitiator = myUid < chatPartnerUid;
        const ratchet = await getRatchet(chatId, keys, isInitiator, myUid, storage);
        const dec = await ratchet.decryptMessage(rawCipher, ratchetHeader);
        if (dec) {
          decryptedLocalCache.set(ciphertext, dec);
          return dec;
        }
      } catch {}
    }

    if (ratchetHeader?.dhPub) {
      const ss = nacl.box.before(base64ToU8(keys.theirPublicKey), base64ToU8(keys.myPrivateKey));
      const dec = statelessRatchetDecrypt(
        rawCipher,
        ratchetHeader.dhPub,
        ratchetHeader.n ?? 0,
        ss,
        keys.myPrivateKey
      );
      if (dec) {
        decryptedLocalCache.set(ciphertext, dec);
        return dec;
      }
    }

    return "🔒 [Encrypted Message]";
  }

  const encData = ciphertext.slice(4);
  const decrypted =
    decryptMessage(encData, keys.theirPublicKey, keys.myPrivateKey) ||
    decryptMessage(encData, keys.myPublicKey, keys.myPrivateKey);

  if (decrypted) {
    decryptedLocalCache.set(ciphertext, decrypted);
    return decrypted;
  }

  return "🔒 [Encrypted Message]";
}
