/**
 * @module x3dh
 * Extended Triple Diffie-Hellman (X3DH) key agreement protocol.
 *
 * Matches the Rust implementation in core/src/double_ratchet.rs byte-for-byte:
 * - Same DH concatenation order: DH1 || DH2 || DH3 [|| DH4]
 * - Same HKDF: salt=None, info="accord-x3dh-v1"
 * - Same key types: X25519
 *
 * Protocol (Alice initiates to Bob):
 *   DH1 = DH(IK_A, SPK_B)   — Alice's identity × Bob's signed prekey
 *   DH2 = DH(EK_A, IK_B)    — Alice's ephemeral × Bob's identity
 *   DH3 = DH(EK_A, SPK_B)   — Alice's ephemeral × Bob's signed prekey
 *   DH4 = DH(EK_A, OPK_B)   — Alice's ephemeral × Bob's one-time prekey (optional)
 *   SK  = HKDF(salt=None, ikm=DH1||DH2||DH3[||DH4], info="accord-x3dh-v1")
 *
 * Reference: https://signal.org/docs/specifications/x3dh/
 */

// @ts-ignore
import { hkdf } from '@noble/hashes/hkdf.js';
// @ts-ignore
import { sha256 } from '@noble/hashes/sha2.js';

import type { IdentityKeyPair, PreKeyBundle, SignedPreKeyPair, OneTimePreKeyPair, RawKey } from './keys';
import { x25519DH, generateOneTimePreKey } from './keys';

/** HKDF info string — must match Rust's `b"accord-x3dh-v1"` */
const X3DH_INFO = new TextEncoder().encode('accord-x3dh-v1');

/** Output of X3DH initiation (Alice's side) */
export interface X3DHInitiatorOutput {
  /** 32-byte shared secret for Double Ratchet initialization */
  sharedSecret: Uint8Array;
  /** Alice's ephemeral public key (sent to Bob in the initial message) */
  ephemeralPublicKey: Uint8Array;
}

/**
 * Perform X3DH as the initiator (Alice).
 *
 * Alice generates an ephemeral keypair and computes the shared secret
 * using Bob's published prekey bundle.
 *
 * @param ourIdentity - Alice's long-term identity keypair
 * @param theirBundle - Bob's published prekey bundle
 * @returns Shared secret + ephemeral public key to send to Bob
 */
export function x3dhInitiate(
  ourIdentity: IdentityKeyPair,
  theirBundle: PreKeyBundle,
): X3DHInitiatorOutput {
  // Generate ephemeral keypair (EK_A) — reuse key generation helper
  const ek = generateOneTimePreKey();
  const ekPrivate = ek.privateKey;
  const ekPublic = ek.publicKey;

  // Compute the four DH exchanges (matching Rust order exactly)
  const dh1 = x25519DH(ourIdentity.privateKey, theirBundle.signedPrekey);  // DH(IK_A, SPK_B)
  const dh2 = x25519DH(ekPrivate, theirBundle.identityKey);                // DH(EK_A, IK_B)
  const dh3 = x25519DH(ekPrivate, theirBundle.signedPrekey);               // DH(EK_A, SPK_B)

  // Concatenate: DH1 || DH2 || DH3 [|| DH4]
  const parts = [dh1, dh2, dh3];
  if (theirBundle.oneTimePrekey) {
    const dh4 = x25519DH(ekPrivate, theirBundle.oneTimePrekey);             // DH(EK_A, OPK_B)
    parts.push(dh4);
  }

  const ikmLength = parts.reduce((sum, p) => sum + p.length, 0);
  const ikm = new Uint8Array(ikmLength);
  let offset = 0;
  for (const part of parts) {
    ikm.set(part, offset);
    offset += part.length;
  }

  // HKDF: salt=undefined (no salt, matches Rust's `Hkdf::new(None, &ikm)`)
  // Rust uses hkdf crate which treats None salt as zeroed salt of hash length
  const sharedSecret = hkdf(sha256, ikm, undefined, X3DH_INFO, 32);

  // Zeroize intermediate material
  ikm.fill(0);
  ekPrivate.fill(0);

  return { sharedSecret, ephemeralPublicKey: ekPublic };
}

/**
 * Perform X3DH as the responder (Bob).
 *
 * Bob uses the ephemeral public key from Alice's initial message
 * along with his own key material to derive the same shared secret.
 *
 * @param ourIdentity - Bob's long-term identity keypair
 * @param ourSignedPrekey - Bob's signed prekey pair
 * @param ourOneTimePrekey - Bob's one-time prekey (if Alice used one)
 * @param theirIdentityKey - Alice's identity public key
 * @param theirEphemeralKey - Alice's ephemeral public key (from initial message)
 * @returns 32-byte shared secret (same as Alice computed)
 */
export function x3dhRespond(
  ourIdentity: IdentityKeyPair,
  ourSignedPrekey: SignedPreKeyPair,
  ourOneTimePrekey: OneTimePreKeyPair | undefined,
  theirIdentityKey: RawKey,
  theirEphemeralKey: RawKey,
): Uint8Array {
  // Compute DH exchanges (Bob's perspective, same order as Alice)
  const dh1 = x25519DH(ourSignedPrekey.privateKey, theirIdentityKey);    // DH(SPK_B, IK_A)
  const dh2 = x25519DH(ourIdentity.privateKey, theirEphemeralKey);       // DH(IK_B, EK_A)
  const dh3 = x25519DH(ourSignedPrekey.privateKey, theirEphemeralKey);   // DH(SPK_B, EK_A)

  const parts = [dh1, dh2, dh3];
  if (ourOneTimePrekey) {
    const dh4 = x25519DH(ourOneTimePrekey.privateKey, theirEphemeralKey); // DH(OPK_B, EK_A)
    parts.push(dh4);
  }

  const ikmLength = parts.reduce((sum, p) => sum + p.length, 0);
  const ikm = new Uint8Array(ikmLength);
  let offset = 0;
  for (const part of parts) {
    ikm.set(part, offset);
    offset += part.length;
  }

  const sharedSecret = hkdf(sha256, ikm, undefined, X3DH_INFO, 32);

  ikm.fill(0);

  return sharedSecret;
}
