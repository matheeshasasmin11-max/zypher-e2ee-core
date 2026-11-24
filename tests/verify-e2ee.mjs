/**
 * ZypherChats E2EE Core — Comprehensive Cryptographic & Adversarial Test Suite
 *
 * Compiles and imports the actual TypeScript modules from `../dist/index.js`
 * and verifies RFC 4231 / RFC 5869 test vectors, X3DH, Double Ratchet v2,
 * Header-Authenticated AEAD, DoS bounds, Downgrade rejection, and TOFU pinning.
 */
import assert from "node:assert/strict";
import nodeCrypto from "node:crypto";
import util from "tweetnacl-util";

import {
  hmacSha512,
  hkdfSha512,
  configureSecureVault,
  generateIdentityKeyBundle,
  generateSignedPreKey,
  generateOneTimePreKeys,
  x3dhInitiate,
  x3dhRespond,
  DoubleRatchet,
  MAX_SKIP,
  resolveChatKeys,
  approvePeerKeyChange,
  encryptMsg,
  decryptMsg,
  clearE2ECache,
  ProtocolDowngradeError,
  IdentityKeyChangedError,
  encryptBinaryMediaPayload,
  decryptBinaryMediaPayload,
  computeKeyVerificationFingerprint,
} from "../dist/index.js";

const toHex = (u8) => Buffer.from(u8).toString("hex");
const fromHex = (hex) => new Uint8Array(Buffer.from(hex, "hex"));

console.log("🔒 Running ZypherChats E2EE Core v1.1 Verification Suite (against compiled src/)...\n");

// ============================================================================
// 1. IETF RFC 4231 Official HMAC-SHA512 Test Vectors
// ============================================================================
{
  // RFC 4231 Test Case 1
  const key1 = new Uint8Array(20).fill(0x0b);
  const data1 = util.decodeUTF8("Hi There");
  const expected1 =
    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" +
    "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";
  assert.equal(toHex(hmacSha512(key1, data1)), expected1, "RFC 4231 Case 1 mismatch");

  // RFC 4231 Test Case 2
  const key2 = util.decodeUTF8("Jefe");
  const data2 = util.decodeUTF8("what do ya want for nothing?");
  const expected2 =
    "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554" +
    "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
  assert.equal(toHex(hmacSha512(key2, data2)), expected2, "RFC 4231 Case 2 mismatch");

  // RFC 4231 Test Case 6 (Key = 131 bytes > 128-byte SHA-512 block size)
  const key6 = new Uint8Array(131).fill(0xaa);
  const data6 = util.decodeUTF8("Test Using Larger Than Block-Size Key - Hash Key First");
  const expected6 =
    "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352" +
    "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598";
  assert.equal(toHex(hmacSha512(key6, data6)), expected6, "RFC 4231 Case 6 (key > block size) mismatch");

  console.log("✅ [1/7] IETF RFC 4231 HMAC-SHA512 official test vectors (Cases 1, 2, 6) verified.");
}

// ============================================================================
// 2. RFC 5869 HKDF-SHA512 Differential Verification against OpenSSL
// ============================================================================
{
  const ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  const salt = fromHex("000102030405060708090a0b0c");
  const info = fromHex("f0f1f2f3f4f5f6f7f8f9");

  for (const length of [32, 64, 140, 256]) {
    const ours = hkdfSha512(ikm, salt, info, length);
    const openssl = new Uint8Array(nodeCrypto.hkdfSync("sha512", ikm, salt, info, length));
    assert.equal(toHex(ours), toHex(openssl), `HKDF-SHA512 mismatch against OpenSSL at length=${length}`);
  }

  // Empty salt (must default to HashLen zeros per RFC 5869 Section 2.2)
  const oursEmptySalt = hkdfSha512(ikm, null, "ZypherTestInfo", 64);
  const opensslEmptySalt = new Uint8Array(
    nodeCrypto.hkdfSync("sha512", ikm, new Uint8Array(0), Buffer.from("ZypherTestInfo", "utf8"), 64)
  );
  assert.equal(toHex(oursEmptySalt), toHex(opensslEmptySalt), "HKDF-SHA512 empty-salt mismatch");

  console.log("✅ [2/7] RFC 5869 HKDF-SHA512 verified byte-for-byte against OpenSSL across multi-block outputs.");
}

// ============================================================================
// 3. X3DH Asynchronous Handshake & Ed25519 SignedPreKey Authentication
// ============================================================================
{
  const aliceId = generateIdentityKeyBundle();
  const bobId = generateIdentityKeyBundle();
  const bobSpk = generateSignedPreKey(bobId, 1);
  const [bobOpk] = generateOneTimePreKeys(100, 2);

  const bobPublicBundle = {
    identitySigningPublicKey: bobId.signingKeyPair.publicKey,
    identityDHPublicKey: bobId.dhKeyPair.publicKey,
    signedPreKeyId: bobSpk.keyId,
    signedPreKeyPublic: bobSpk.publicKey,
    signedPreKeySignature: bobSpk.signature,
    oneTimePreKeyId: bobOpk.keyId,
    oneTimePreKeyPublic: bobOpk.publicKey,
  };

  // 4-DH X3DH agreement (with One-Time PreKey)
  const aliceInit = x3dhInitiate(aliceId, bobPublicBundle);
  const bobResp = x3dhRespond(bobId, bobSpk, bobOpk, aliceInit.initialHeader);
  assert.equal(aliceInit.sharedSecretBase64, bobResp.sharedSecretBase64, "X3DH 4-DH shared secret mismatch");
  assert.equal(aliceInit.associatedDataBase64, bobResp.associatedDataBase64, "X3DH AD mismatch");

  // 3-DH X3DH agreement (when OPKs are exhausted)
  const bundleNoOpk = { ...bobPublicBundle, oneTimePreKeyId: undefined, oneTimePreKeyPublic: undefined };
  const aliceInit3 = x3dhInitiate(aliceId, bundleNoOpk);
  const bobResp3 = x3dhRespond(bobId, bobSpk, null, aliceInit3.initialHeader);
  assert.equal(aliceInit3.sharedSecretBase64, bobResp3.sharedSecretBase64, "X3DH 3-DH shared secret mismatch");

  // MITM tampering: attacker swaps Bob's SignedPreKey without Bob's Ed25519 signing secret
  const malloryId = generateIdentityKeyBundle();
  const mallorySpk = generateSignedPreKey(malloryId, 1);
  const tamperedBundle = { ...bobPublicBundle, signedPreKeyPublic: mallorySpk.publicKey };
  assert.throws(
    () => x3dhInitiate(aliceId, tamperedBundle),
    /signature verification failed/,
    "Must reject tampered SignedPreKey"
  );

  // Cross-identity transplant attack: Mallory attaches Bob's valid signature to Mallory's IK_DH
  const transplantedBundle = {
    ...bobPublicBundle,
    identitySigningPublicKey: malloryId.signingKeyPair.publicKey,
    signedPreKeySignature: mallorySpk.signature,
    identityDHPublicKey: bobId.dhKeyPair.publicKey, // mismatched IK_DH inside transcript
  };
  assert.throws(
    () => x3dhInitiate(aliceId, transplantedBundle),
    /signature verification failed/,
    "Must reject cross-identity SignedPreKey transplant"
  );

  console.log("✅ [3/7] X3DH 4-DH/3-DH handshake & Ed25519 SignedPreKey MITM rejection verified.");
}

// ============================================================================
// 4. Double Ratchet v2 (X3DH -> Multi-Turn DH Ratchet + Out-of-Order + Replay Rejection)
// ============================================================================
{
  const aliceId = generateIdentityKeyBundle();
  const bobId = generateIdentityKeyBundle();
  const bobSpk = generateSignedPreKey(bobId, 7);
  const [bobOpk] = generateOneTimePreKeys(500, 1);

  const initOut = x3dhInitiate(aliceId, {
    identitySigningPublicKey: bobId.signingKeyPair.publicKey,
    identityDHPublicKey: bobId.dhKeyPair.publicKey,
    signedPreKeyId: bobSpk.keyId,
    signedPreKeyPublic: bobSpk.publicKey,
    signedPreKeySignature: bobSpk.signature,
    oneTimePreKeyId: bobOpk.keyId,
    oneTimePreKeyPublic: bobOpk.publicKey,
  });
  const respOut = x3dhRespond(bobId, bobSpk, bobOpk, initOut.initialHeader);

  const aliceRatchet = new DoubleRatchet("chat_x3dh", "alice");
  const bobRatchet = new DoubleRatchet("chat_x3dh", "bob");

  await aliceRatchet.init(
    initOut.sharedSecretBase64,
    true,
    bobSpk.publicKey,
    undefined,
    initOut.associatedDataBase64
  );
  await bobRatchet.init(
    respOut.sharedSecretBase64,
    false,
    "",
    { publicKey: bobSpk.publicKey, secretKey: bobSpk.secretKey },
    respOut.associatedDataBase64
  );

  // Alice sends 3 messages; packets arrive out of order (msg 2 before msg 0 & 1)
  const m0 = await aliceRatchet.encryptMessage("Msg 0");
  const m1 = await aliceRatchet.encryptMessage("Msg 1");
  const m2 = await aliceRatchet.encryptMessage("Msg 2");

  assert.equal(await bobRatchet.decryptMessage(m2.ciphertext, m2.header), "Msg 2");
  // Bob replies BEFORE receiving delayed m0 & m1 (triggers DH ratchet turn)
  const b0 = await bobRatchet.encryptMessage("Bob Reply 0");
  assert.equal(await aliceRatchet.decryptMessage(b0.ciphertext, b0.header), "Bob Reply 0");

  // Alice sends on her NEW DH chain BEFORE Bob even receives old-chain m1!
  const m3NewChain = await aliceRatchet.encryptMessage("Msg 3 after DH turn");
  assert.equal(await bobRatchet.decryptMessage(m3NewChain.ciphertext, m3NewChain.header), "Msg 3 after DH turn");

  // Delayed m0 and m1 from Alice's PREVIOUS chain arrive late — must decrypt via skipped keys & then be deleted!
  assert.equal(await bobRatchet.decryptMessage(m1.ciphertext, m1.header), "Msg 1");
  assert.equal(await bobRatchet.decryptMessage(m0.ciphertext, m0.header), "Msg 0");

  // Replaying m0 a second time MUST fail because the skipped one-time key was deleted for Forward Secrecy
  await assert.rejects(
    () => bobRatchet.decryptMessage(m0.ciphertext, m0.header),
    /MAC authentication failed|MAX_SKIP/,
    "Replayed packet must be rejected after one-time messageKey deletion"
  );

  console.log("✅ [4/7] Double Ratchet v2 multi-turn DH ratcheting, cross-chain out-of-order delivery & replay rejection verified.");
}

// ============================================================================
// 5. Header-Authenticated AEAD, Atomic State Preservation & MAX_SKIP DoS Bound
// ============================================================================
{
  const aliceId = generateIdentityKeyBundle();
  const bobId = generateIdentityKeyBundle();
  const bobSpk = generateSignedPreKey(bobId, 1);
  const initOut = x3dhInitiate(aliceId, {
    identitySigningPublicKey: bobId.signingKeyPair.publicKey,
    identityDHPublicKey: bobId.dhKeyPair.publicKey,
    signedPreKeyId: bobSpk.keyId,
    signedPreKeyPublic: bobSpk.publicKey,
    signedPreKeySignature: bobSpk.signature,
  });
  const respOut = x3dhRespond(bobId, bobSpk, null, initOut.initialHeader);

  const alice = new DoubleRatchet("chat_sec", "alice");
  const bob = new DoubleRatchet("chat_sec", "bob");
  await alice.init(initOut.sharedSecretBase64, true, bobSpk.publicKey, undefined, initOut.associatedDataBase64);
  await bob.init(
    respOut.sharedSecretBase64,
    false,
    "",
    { publicKey: bobSpk.publicKey, secretKey: bobSpk.secretKey },
    respOut.associatedDataBase64
  );

  const validPkt = await alice.encryptMessage("Authentic payload");

  // Attacker tampers with header `pn`
  await assert.rejects(
    () => bob.decryptMessage(validPkt.ciphertext, { ...validPkt.header, pn: 99 }),
    /MAC authentication failed/,
    "Header tampering (pn) must fail AEAD authentication"
  );

  // Attacker injects forged ciphertext with n=5 to try desyncing Bob's receivingChainKey
  const fakeParts = validPkt.ciphertext.split(":");
  const corruptedBytes = util.decodeBase64(fakeParts[1]);
  corruptedBytes[0] ^= 0xff;
  const forgedCipher = `${fakeParts[0]}:${util.encodeBase64(corruptedBytes)}`;
  await assert.rejects(
    () => bob.decryptMessage(forgedCipher, { ...validPkt.header, n: 5 }),
    /MAC authentication failed/
  );

  // Attacker sends DoS packet with n = MAX_SKIP + 500
  await assert.rejects(
    () => bob.decryptMessage(validPkt.ciphertext, { ...validPkt.header, n: MAX_SKIP + 500 }),
    /MAX_SKIP/,
    "Must reject unbounded n DoS attempt"
  );

  // Because state transitions are atomic (committed only post-MAC), Bob's state is UNHARMED and decrypts validPkt!
  assert.equal(await bob.decryptMessage(validPkt.ciphertext, validPkt.header), "Authentic payload");

  console.log("✅ [5/7] Header-Authenticated AEAD, atomic state preservation under forgery & MAX_SKIP DoS bound verified.");
}

// ============================================================================
// 6. Anti-Downgrade Pinning (`dr:` -> `e2e:`) & TOFU Key-Substitution Detection
// ============================================================================
{
  clearE2ECache();
  const vaultMem = new Map();
  configureSecureVault({
    async setItem(k, v) {
      vaultMem.set(k, v);
    },
    async getItem(k) {
      return vaultMem.get(k) ?? null;
    },
    async deleteItem(k) {
      vaultMem.delete(k);
    },
  });

  const storageMem = new Map();
  const storage = {
    async getItem(k) {
      return storageMem.get(k) ?? null;
    },
    async setItem(k, v) {
      storageMem.set(k, v);
    },
  };

  const directoryData = new Map();
  const directory = {
    async getUserPublicKey(uid) {
      return { publicKey: directoryData.get(uid) ?? null, doubleRatchetEnabled: true };
    },
    async publishMyPublicKey(uid, pub) {
      directoryData.set(uid, pub);
    },
  };

  // Initialize both users in directory
  await resolveChatKeys("alice", "bob", directory, storage); // publishes Alice's key
  await resolveChatKeys("bob", "alice", directory, storage); // publishes Bob's key
  clearE2ECache();

  const aliceKeys = await resolveChatKeys("alice", "bob", directory, storage);
  const bobKeys = await resolveChatKeys("bob", "alice", directory, storage);

  // Safety codes on both devices must match identically
  const aliceCode = computeKeyVerificationFingerprint(aliceKeys.myPublicKey, aliceKeys.theirPublicKey);
  const bobCode = computeKeyVerificationFingerprint(bobKeys.myPublicKey, bobKeys.theirPublicKey);
  assert.equal(aliceCode, bobCode);

  // Alice sends a Double Ratchet `dr:` message to Bob
  const drOut = await encryptMsg("Top secret via DR", aliceKeys, "alice_bob", true, "alice", "bob", storage);
  assert.ok(drOut.enc.startsWith("dr:"));
  const decByBob = await decryptMsg(drOut.enc, bobKeys, "alice", "bob", "alice", "alice_bob", drOut.ratchetHeader, storage);
  assert.equal(decByBob, "Top secret via DR");

  // Attacker attempts to downgrade session to static `e2e:` (even if legacy flag were passed!)
  const fakeStaticKeys = { ...aliceKeys, useDoubleRatchet: false };
  await assert.rejects(
    () =>
      encryptMsg("Downgraded", fakeStaticKeys, "alice_bob", true, "alice", "bob", storage, {
        allowLegacyStaticFallback: true,
      }),
    ProtocolDowngradeError,
    "Sender must refuse to downgrade pinned DR peer to e2e:"
  );

  await assert.rejects(
    () =>
      decryptMsg("e2e:AAAA", bobKeys, "alice", "bob", "alice", "alice_bob", undefined, storage, {
        allowLegacyStaticFallback: true,
      }),
    ProtocolDowngradeError,
    "Receiver must reject e2e: downgrade packet from a DR-pinned peer"
  );

  // Compromised server silently swaps Bob's public key in the directory (MITM attempt)
  directoryData.set("bob", util.encodeBase64(nodeCrypto.randomBytes(32)));
  clearE2ECache();
  await assert.rejects(
    () => resolveChatKeys("alice", "bob", directory, storage),
    IdentityKeyChangedError,
    "TOFU pinning must raise IdentityKeyChangedError when directory swaps peer public key"
  );

  // After out-of-band verification, Alice explicitly approves Bob's rotated key
  await approvePeerKeyChange("alice", "bob", directoryData.get("bob"), storage);
  const updatedKeys = await resolveChatKeys("alice", "bob", directory, storage);
  assert.equal(updatedKeys.theirPublicKey, directoryData.get("bob"));

  console.log("✅ [6/7] Strict dr: anti-downgrade pinning & TOFU key-substitution detection verified.");
}

// ============================================================================
// 7. Zero-Knowledge Binary Media AEAD (`ZYPHER_E2EE_V1:`)
// ============================================================================
{
  const rawMedia = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 10, 20, 30, 40]);
  const { encryptedBytes, keyBase64 } = encryptBinaryMediaPayload(rawMedia);
  const decrypted = decryptBinaryMediaPayload(encryptedBytes, keyBase64);
  assert.deepEqual(decrypted, rawMedia);

  const tampered = new Uint8Array(encryptedBytes);
  tampered[tampered.length - 1] ^= 0x01;
  assert.equal(decryptBinaryMediaPayload(tampered, keyBase64), null, "Tampered media blob must return null");

  console.log("✅ [7/7] Zero-Knowledge Binary Media Encryption (ZYPHER_E2EE_V1) verified.\n");
}

console.log("🎉 All 7 cryptographic & adversarial test suites passed!");
