import nacl from "tweetnacl";
import util from "tweetnacl-util";

/**
 * Generates a deterministic 20-character Base36 Safety Verification Fingerprint
 * (formatted as 4 groups of 5 characters: `XXXXX   XXXXX   XXXXX   XXXXX`)
 * from both participants' Curve25519 public keys via SHA-512.
 *
 * Both participants independently compute the exact same 20-character string on their devices.
 * If a Man-in-the-Middle (MITM) substitutes either public key, the 20-character codes will not match.
 */
export function computeKeyVerificationFingerprint(
  publicKeyA: string,
  publicKeyB: string
): string {
  const canonicalPair = [publicKeyA.trim(), publicKeyB.trim()].sort().join(":");
  const digest = nacl.hash(util.decodeUTF8(canonicalPair)); // 64-byte SHA-512 digest

  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 20; i++) {
    // Combine two digest bytes per character to avoid modulo bias
    const v = ((digest[i * 2] << 8) | digest[i * 2 + 1]) % alphabet.length;
    out += alphabet.charAt(v);
  }
  return out.match(/.{1,5}/g)?.join("   ") || out;
}
