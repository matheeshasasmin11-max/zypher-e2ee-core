import nacl from "tweetnacl";
import util from "tweetnacl-util";
import { concatBytes, hkdfSha512, isAllZero, zeroize } from "./hkdf";
import { ensureCSPRNG } from "./crypto";

const X3DH_INFO = "ZypherChats_X3DH_Curve25519_SHA512_v1";
const SPK_SIG_DOMAIN = "ZypherX3DH-SPK-v1:";
const X25519_DOMAIN_F = new Uint8Array(32).fill(0xff);

export class X3DHError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "X3DHError";
  }
}

export interface IdentityKeyBundle {
  /** Ed25519 keypair used exclusively to sign & authenticate prekeys */
  signingKeyPair: { publicKey: string; secretKey: string };
  /** Long-term X25519 Identity Diffie-Hellman keypair (IK) */
  dhKeyPair: { publicKey: string; secretKey: string };
}

export interface SignedPreKeyPrivate {
  keyId: number;
  publicKey: string;
  secretKey: string;
  signature: string;
  createdAt: number;
}

export interface OneTimePreKeyPrivate {
  keyId: number;
  publicKey: string;
  secretKey: string;
}

/**
 * Public PreKey Bundle published to the directory so peers can initiate
 * asynchronous sessions with full forward secrecy even while the recipient is offline.
 */
export interface PublicPreKeyBundle {
  identitySigningPublicKey: string;
  identityDHPublicKey: string;
  signedPreKeyId: number;
  signedPreKeyPublic: string;
  /** Ed25519 detached signature over ("ZypherX3DH-SPK-v1:" || IK_DH_pub || SPK_pub) */
  signedPreKeySignature: string;
  oneTimePreKeyId?: number;
  oneTimePreKeyPublic?: string;
}

/**
 * Initial X3DH handshake header attached to Alice's first Double Ratchet message.
 */
export interface X3DHInitialHeader {
  senderIdentitySigningKey: string;
  senderIdentityDHKey: string;
  ephemeralPublicKey: string;
  signedPreKeyId: number;
  oneTimePreKeyId?: number;
}

export interface X3DHInitiatorResult {
  /** 32-byte root shared secret (SK) fed into DoubleRatchet.init() */
  sharedSecretBase64: string;
  /** Canonical 64-byte Associated Data (IK_A || IK_B) bound to Double Ratchet AEAD headers */
  associatedDataBase64: string;
  /** Handshake header sent alongside initial message */
  initialHeader: X3DHInitialHeader;
}

/**
 * Generates a long-term Identity Key Bundle (Ed25519 signing + X25519 DH).
 */
export function generateIdentityKeyBundle(): IdentityKeyBundle {
  ensureCSPRNG();
  const signKp = nacl.sign.keyPair();
  const dhKp = nacl.box.keyPair();
  return {
    signingKeyPair: {
      publicKey: util.encodeBase64(signKp.publicKey),
      secretKey: util.encodeBase64(signKp.secretKey),
    },
    dhKeyPair: {
      publicKey: util.encodeBase64(dhKp.publicKey),
      secretKey: util.encodeBase64(dhKp.secretKey),
    },
  };
}

function buildSignedPreKeyTranscript(identityDHPublicKey: Uint8Array, signedPreKeyPublic: Uint8Array): Uint8Array {
  return concatBytes(util.decodeUTF8(SPK_SIG_DOMAIN), identityDHPublicKey, signedPreKeyPublic);
}

/**
 * Generates a medium-term X25519 Signed PreKey signed by the user's Ed25519 Identity Key.
 * Binds `identityDHPublicKey` inside the signed transcript to prevent cross-identity key substitution.
 */
export function generateSignedPreKey(identity: IdentityKeyBundle, keyId: number): SignedPreKeyPrivate {
  ensureCSPRNG();
  const spk = nacl.box.keyPair();
  const ikDhPub = util.decodeBase64(identity.dhKeyPair.publicKey);
  const signSec = util.decodeBase64(identity.signingKeyPair.secretKey);

  const transcript = buildSignedPreKeyTranscript(ikDhPub, spk.publicKey);
  const sig = nacl.sign.detached(transcript, signSec);

  return {
    keyId,
    publicKey: util.encodeBase64(spk.publicKey),
    secretKey: util.encodeBase64(spk.secretKey),
    signature: util.encodeBase64(sig),
    createdAt: Date.now(),
  };
}

/**
 * Generates a batch of single-use X25519 One-Time PreKeys (OPKs).
 */
export function generateOneTimePreKeys(startKeyId: number, count: number): OneTimePreKeyPrivate[] {
  ensureCSPRNG();
  const keys: OneTimePreKeyPrivate[] = [];
  for (let i = 0; i < count; i++) {
    const kp = nacl.box.keyPair();
    keys.push({
      keyId: startKeyId + i,
      publicKey: util.encodeBase64(kp.publicKey),
      secretKey: util.encodeBase64(kp.secretKey),
    });
  }
  return keys;
}

/**
 * Verifies the Ed25519 signature on a peer's PublicPreKeyBundle.
 */
export function verifyPreKeyBundleSignature(bundle: PublicPreKeyBundle): boolean {
  try {
    const signPub = util.decodeBase64(bundle.identitySigningPublicKey);
    const ikDhPub = util.decodeBase64(bundle.identityDHPublicKey);
    const spkPub = util.decodeBase64(bundle.signedPreKeyPublic);
    const sig = util.decodeBase64(bundle.signedPreKeySignature);

    if (
      signPub.length !== nacl.sign.publicKeyLength ||
      ikDhPub.length !== nacl.box.publicKeyLength ||
      spkPub.length !== nacl.box.publicKeyLength ||
      sig.length !== nacl.sign.signatureLength
    ) {
      return false;
    }

    const transcript = buildSignedPreKeyTranscript(ikDhPub, spkPub);
    return nacl.sign.detached.verify(transcript, sig, signPub);
  } catch {
    return false;
  }
}

function safeX25519(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (secretKey.length !== 32 || publicKey.length !== 32) {
    throw new X3DHError("Invalid X25519 key length");
  }
  const shared = nacl.scalarMult(secretKey, publicKey);
  if (isAllZero(shared)) {
    zeroize(shared);
    throw new X3DHError("Rejected low-order X25519 public key (RFC 7748 Section 6.1)");
  }
  return shared;
}

/**
 * Signal X3DH Initiator (Alice -> Bob's PreKeyBundle).
 * Computes SK = HKDF(F || DH1 || DH2 || DH3 [|| DH4]) and AD = IK_A || IK_B.
 */
export function x3dhInitiate(
  aliceIdentity: IdentityKeyBundle,
  bobBundle: PublicPreKeyBundle
): X3DHInitiatorResult {
  ensureCSPRNG();
  if (!verifyPreKeyBundleSignature(bobBundle)) {
    throw new X3DHError("SignedPreKey Ed25519 signature verification failed — possible MITM key tampering");
  }

  const ikASec = util.decodeBase64(aliceIdentity.dhKeyPair.secretKey);
  const ikAPub = util.decodeBase64(aliceIdentity.dhKeyPair.publicKey);
  const ikBPub = util.decodeBase64(bobBundle.identityDHPublicKey);
  const spkBPub = util.decodeBase64(bobBundle.signedPreKeyPublic);

  const ekA = nacl.box.keyPair();

  let dh1: Uint8Array | null = null;
  let dh2: Uint8Array | null = null;
  let dh3: Uint8Array | null = null;
  let dh4: Uint8Array | null = null;
  let ikm: Uint8Array | null = null;

  try {
    dh1 = safeX25519(ikASec, spkBPub);
    dh2 = safeX25519(ekA.secretKey, ikBPub);
    dh3 = safeX25519(ekA.secretKey, spkBPub);

    if (bobBundle.oneTimePreKeyPublic) {
      const opkBPub = util.decodeBase64(bobBundle.oneTimePreKeyPublic);
      dh4 = safeX25519(ekA.secretKey, opkBPub);
      ikm = concatBytes(X25519_DOMAIN_F, dh1, dh2, dh3, dh4);
    } else {
      ikm = concatBytes(X25519_DOMAIN_F, dh1, dh2, dh3);
    }

    const sk = hkdfSha512(ikm, new Uint8Array(64), X3DH_INFO, 32);
    const ad = concatBytes(ikAPub, ikBPub);

    const result: X3DHInitiatorResult = {
      sharedSecretBase64: util.encodeBase64(sk),
      associatedDataBase64: util.encodeBase64(ad),
      initialHeader: {
        senderIdentitySigningKey: aliceIdentity.signingKeyPair.publicKey,
        senderIdentityDHKey: aliceIdentity.dhKeyPair.publicKey,
        ephemeralPublicKey: util.encodeBase64(ekA.publicKey),
        signedPreKeyId: bobBundle.signedPreKeyId,
        ...(bobBundle.oneTimePreKeyId !== undefined ? { oneTimePreKeyId: bobBundle.oneTimePreKeyId } : {}),
      },
    };
    zeroize(sk);
    return result;
  } finally {
    zeroize(ikASec);
    zeroize(ekA.secretKey);
    zeroize(dh1);
    zeroize(dh2);
    zeroize(dh3);
    zeroize(dh4);
    zeroize(ikm);
  }
}

/**
 * Signal X3DH Responder (Bob processes Alice's X3DHInitialHeader).
 * Note: Caller MUST permanently delete `bobOneTimePreKey` from storage immediately after `x3dhRespond` succeeds.
 */
export function x3dhRespond(
  bobIdentity: IdentityKeyBundle,
  bobSignedPreKey: SignedPreKeyPrivate,
  bobOneTimePreKey: OneTimePreKeyPrivate | null | undefined,
  header: X3DHInitialHeader
): { sharedSecretBase64: string; associatedDataBase64: string } {
  if (header.signedPreKeyId !== bobSignedPreKey.keyId) {
    throw new X3DHError(`SignedPreKey ID mismatch: expected ${bobSignedPreKey.keyId}, got ${header.signedPreKeyId}`);
  }
  if (header.oneTimePreKeyId !== undefined && (!bobOneTimePreKey || bobOneTimePreKey.keyId !== header.oneTimePreKeyId)) {
    throw new X3DHError(`Missing or mismatched OneTimePreKey ID: ${header.oneTimePreKeyId}`);
  }

  const ikBSec = util.decodeBase64(bobIdentity.dhKeyPair.secretKey);
  const ikBPub = util.decodeBase64(bobIdentity.dhKeyPair.publicKey);
  const spkBSec = util.decodeBase64(bobSignedPreKey.secretKey);
  const ikAPub = util.decodeBase64(header.senderIdentityDHKey);
  const ekAPub = util.decodeBase64(header.ephemeralPublicKey);

  let opkBSec: Uint8Array | null = null;
  let dh1: Uint8Array | null = null;
  let dh2: Uint8Array | null = null;
  let dh3: Uint8Array | null = null;
  let dh4: Uint8Array | null = null;
  let ikm: Uint8Array | null = null;

  try {
    dh1 = safeX25519(spkBSec, ikAPub);
    dh2 = safeX25519(ikBSec, ekAPub);
    dh3 = safeX25519(spkBSec, ekAPub);

    if (header.oneTimePreKeyId !== undefined && bobOneTimePreKey) {
      opkBSec = util.decodeBase64(bobOneTimePreKey.secretKey);
      dh4 = safeX25519(opkBSec, ekAPub);
      ikm = concatBytes(X25519_DOMAIN_F, dh1, dh2, dh3, dh4);
    } else {
      ikm = concatBytes(X25519_DOMAIN_F, dh1, dh2, dh3);
    }

    const sk = hkdfSha512(ikm, new Uint8Array(64), X3DH_INFO, 32);
    const ad = concatBytes(ikAPub, ikBPub);

    const sharedSecretBase64 = util.encodeBase64(sk);
    const associatedDataBase64 = util.encodeBase64(ad);
    zeroize(sk);

    return { sharedSecretBase64, associatedDataBase64 };
  } finally {
    zeroize(ikBSec);
    zeroize(spkBSec);
    zeroize(opkBSec);
    zeroize(dh1);
    zeroize(dh2);
    zeroize(dh3);
    zeroize(dh4);
    zeroize(ikm);
  }
}
