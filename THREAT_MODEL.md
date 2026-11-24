# 🛡️ ZypherChats Cryptographic Threat Model & Security Boundaries

This document defines the explicit security guarantees, adversary assumptions, architectural boundaries, and known limitations of `@zypherchats/e2ee-core` (v1.1+).

We intentionally avoid exaggerated "silver-bullet" security claims. Security researchers and users deserve an accurate engineering specification of what is cryptographically enforced and what remains outside the scope of End-to-End Encryption (E2EE).

---

## 1. Adversary Model

We consider the following adversaries:

1. **Passive & Active Network Attackers (ISP, Wi-Fi attacker, BGP hijacker, TLS proxy)**
   - Can observe, replay, drop, reorder, delay, or modify packets in transit.
2. **Compromised or Coerced Backend Infrastructure (Database, Relay Server, Cloud Object Storage)**
   - Has full read/write access to stored message documents, binary media blobs, and the public-key directory.
3. **Post-Compromise / Transient Key Exposure**
   - An adversary who obtains a snapshot of a session's current ephemeral state at time $t$, attempting to read past messages ($< t$) or future messages after subsequent Diffie-Hellman ratchet turns ($> t + 1$).

### Out-of-Scope Adversaries
* **Compromised Endpoint OS / Malware / Physical Coercion**: If an attacker has root/jailbreak execution on an unlocked user device, they can read plaintext directly from screen memory or UI buffers before encryption.
* **Global Traffic-Analysis Adversary**: Timing correlation, packet sizes, IP addresses, and push-notification wakeups are not obfuscated by E2EE alone (no mixnet/onion routing).

---

## 2. Cryptographic Guarantees

| Security Property | Mechanism in `@zypherchats/e2ee-core` |
| :--- | :--- |
| **Message Confidentiality** | 256-bit `XSalsa20` stream cipher (`tweetnacl` `secretbox`) under unique per-message keys. |
| **Ciphertext & Header Integrity** | 128-bit `Poly1305` MAC with header-bound AEAD key derivation (`v`, `dhPub`, `pn`, `n`, and X3DH `associatedData = IK_A \|\| IK_B` bound via `HKDF-SHA512`). Modifying any header field or ciphertext byte causes immediate MAC rejection without mutating ratchet state. |
| **Asynchronous Forward Secrecy (Handshake)** | **X3DH (`src/x3dh.ts`)** combining long-term Identity DH keys (`IK`), Ed25519-authenticated Signed PreKeys (`SPK`), and single-use One-Time PreKeys (`OPK`) with RFC 7748 low-order point rejection. |
| **Per-Message Forward Secrecy** | **Symmetric HMAC-SHA512 Chain Ratchet (`KDF_CK`)**: `chainKey` advances via one-way `HMAC-SHA512(ck, 0x01)` while `messageKey` is derived via `HMAC-SHA512(ck, 0x02)` and erased immediately after decryption. |
| **Post-Compromise Security (Break-in Recovery)** | **X25519 Ephemeral Diffie-Hellman Ratchet (`KDF_RK`)**: Every reply turn generates a fresh CSPRNG X25519 keypair and mixes `scalarMult` output into the Root Key via **RFC 5869 `HKDF-SHA512`**. |
| **Downgrade Resistance** | **Strict Ratchet Pinning (`src/e2e.ts`)**: Static `e2e:` envelopes are disabled by default (`allowLegacyStaticFallback: false`). Even during legacy migration, once any `dr:` session is established with a peer, `e2e:` envelopes from that peer throw `ProtocolDowngradeError`. |
| **State-Desync & CPU DoS Resistance** | `DoubleRatchet.decryptMessage` stages state transitions on an isolated clone and commits **only** after Poly1305 MAC verification succeeds. Skipped message key derivation is bounded by `MAX_SKIP = 1000` and `MAX_TOTAL_SKIPPED_KEYS = 2000`. |
| **Zero-Knowledge Media Storage** | Attachments (`src/mediaCrypto.ts`) are encrypted client-side with a fresh 256-bit CSPRNG key and 192-bit nonce (`ZYPHER_E2EE_V1:`). Cloud object storage receives only ciphertext; the file key travels strictly inside the `dr:` E2EE message payload. |

---

## 3. Public-Key Directory, TOFU, and Active MITM Risks

Like Signal and WhatsApp, ZypherChats uses a server-hosted directory to distribute public Identity Keys and PreKey Bundles:

1. **First-Contact MITM Risk**: On initial contact, if users do not verify keys out-of-band, a malicious server could theoretically substitute public keys (Man-in-the-Middle).
2. **Signed PreKey Binding**: In X3DH (`src/x3dh.ts`), `SignedPreKey` is signed by the peer's Ed25519 Identity Signing Key over `"ZypherX3DH-SPK-v1:" || IK_DH_pub || SPK_pub`, preventing an attacker from attaching their own prekey to an already-known identity key.
3. **Trust-On-First-Use (TOFU) Key Pinning**: `resolveChatKeys` pins each contact's public key locally (`tofu_pubkey_<myUid>_<peerUid>`). If the server later serves a different key for that contact, `IdentityKeyChangedError` is raised until explicitly verified and approved via `approvePeerKeyChange()`.
4. **Out-of-Band Verification**: High-risk users should verify the deterministic 20-character safety code (`src/fingerprint.ts`) or scan the peer's QR code in person or over a secondary authenticated channel.

---

## 4. Transport Metadata vs. Content Confidentiality

**What ZypherChats servers CANNOT access:**
* Plaintext message text, captions, replies, or link previews generated client-side
* Photos, videos, voice notes, documents, or their symmetric decryption keys
* Private Identity Keys, Signed PreKey secrets, One-Time PreKey secrets, or Double Ratchet chain/root keys

**What ZypherChats transport servers DO process (Metadata):**
* Sender UID and Recipient UID (required to route messages and deliver FCM/APNs push wakeups)
* Delivery timestamps and ciphertext payload byte lengths
* Connection IP addresses at the transport/CDN edge

---

## 5. Known Limitations & Audit Status

1. **No Formal Third-Party Audit Yet**: While the underlying cryptographic primitives (`tweetnacl` Curve25519, Ed25519, XSalsa20-Poly1305, SHA-512) are widely audited, the protocol composition in `@zypherchats/e2ee-core` has **not yet undergone an independent paid cryptographic audit**. Journalists, activists, and high-risk users facing nation-state adversaries should weigh this accordingly.
2. **Client Application Distribution**: `@zypherchats/e2ee-core` open-sources the complete cryptographic layer, but the full ZypherChats mobile UI application is not yet built via deterministic reproducible store builds. Verifying that a binary store release runs unmodified `@zypherchats/e2ee-core` requires binary inspection until reproducible client builds are introduced.
3. **JavaScript Memory Model**: Although `@zypherchats/e2ee-core` explicitly zeroizes (`Uint8Array.fill(0)`) intermediate DH outputs, PRKs, and message keys, JavaScript runtimes (Hermes/V8) garbage-collect immutable UTF-8 plaintext `string` values non-deterministically.
