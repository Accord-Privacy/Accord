/**
 * @module duress
 * Duress ("panic") password.
 *
 * A user may configure a second password. When it is entered at login, the app
 * **destroys the real account on this device** and opens a fresh, empty decoy
 * identity instead. Because the real data is wiped the moment the duress
 * password is used — including this duress *configuration* itself — nothing
 * remains for a forensic examiner to find: only an ordinary-looking empty
 * account. That is what makes it safer than a classic hidden-volume decoy,
 * which leaves a second ciphertext blob that betrays the hidden account's
 * existence.
 *
 * We never store the duress password, only a salted verifier so login can
 * recognize it. The verifier is a normal `accord_*` key, so the wipe removes it
 * too — after the duress password fires once, there is no trace it ever existed.
 */

// @ts-ignore - noble v2 uses .js exports
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
// @ts-ignore
import { sha256 } from '@noble/hashes/sha2.js';

const DURESS_VERIFIER_KEY = 'accord_duress_v';
const PBKDF2_ITERS = 200_000;

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function derive(password: string, salt: Uint8Array): Uint8Array {
  return pbkdf2(sha256, new TextEncoder().encode(password), salt, { c: PBKDF2_ITERS, dkLen: 32 });
}

/** Whether a duress password is currently configured on this device. */
export function isDuressConfigured(): boolean {
  return localStorage.getItem(DURESS_VERIFIER_KEY) !== null;
}

/**
 * Set (or, with null, clear) the duress password. Stores only a salted verifier.
 * Throws if the duress password equals the account's real password — otherwise a
 * normal login would trigger the wipe.
 */
export function setDuressPassword(duressPassword: string | null, realPassword: string): void {
  if (duressPassword === null) {
    localStorage.removeItem(DURESS_VERIFIER_KEY);
    return;
  }
  if (duressPassword.length < 8) {
    throw new Error('Duress password must be at least 8 characters');
  }
  if (duressPassword === realPassword) {
    throw new Error('Duress password must differ from your real password');
  }
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const verifier = derive(duressPassword, salt);
  // Stored blob: [salt(16)][verifier(32)]
  const combined = new Uint8Array(48);
  combined.set(salt, 0);
  combined.set(verifier, 16);
  localStorage.setItem(DURESS_VERIFIER_KEY, toBase64(combined));
}

/** Constant-time-ish comparison of two byte arrays. */
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Whether `password` is the configured duress password. */
export function isDuressPassword(password: string): boolean {
  const stored = localStorage.getItem(DURESS_VERIFIER_KEY);
  if (!stored) return false;
  try {
    const combined = fromBase64(stored);
    const salt = combined.slice(0, 16);
    const expected = combined.slice(16);
    return equalBytes(derive(password, salt), expected);
  } catch {
    return false;
  }
}
