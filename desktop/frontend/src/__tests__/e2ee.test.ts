import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  buildPreKeyBundle,
  keyToHex,
  hexToKey,
} from '../e2ee/keys';
import { x3dhInitiate, x3dhRespond } from '../e2ee/x3dh';
import { DoubleRatchetSession } from '../e2ee/ratchet';
import {
  saveIdentityKeys,
  loadIdentityKeys,
  saveSenderKeyStore,
  loadSenderKeyStore,
} from '../e2ee/persistence';
import { hasStoredKeyPair } from '../crypto';

// ─── Key Generation ─────────────────────────────────────────────────────────

describe('X25519 Key Generation', () => {
  it('generates a 32-byte keypair', () => {
    const kp = generateIdentityKeyPair();
    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.privateKey.length).toBe(32);
    expect(kp.publicKey.length).toBe(32);
  });

  it('generates unique keypairs each time', () => {
    const a = generateIdentityKeyPair();
    const b = generateIdentityKeyPair();
    expect(keyToHex(a.publicKey)).not.toBe(keyToHex(b.publicKey));
    expect(keyToHex(a.privateKey)).not.toBe(keyToHex(b.privateKey));
  });

  it('keyToHex / hexToKey roundtrip', () => {
    const kp = generateIdentityKeyPair();
    const hex = keyToHex(kp.publicKey);
    expect(hex).toMatch(/^[0-9a-f]{64}$/);
    const restored = hexToKey(hex);
    expect(restored).toEqual(kp.publicKey);
  });

  it('buildPreKeyBundle returns correct public keys', () => {
    const identity = generateIdentityKeyPair();
    const signed = generateSignedPreKey();
    const otpks = generateOneTimePreKeys(3);
    const bundle = buildPreKeyBundle(identity, signed, otpks[0]);
    expect(bundle.identityKey).toEqual(identity.publicKey);
    expect(bundle.signedPrekey).toEqual(signed.publicKey);
    expect(bundle.oneTimePrekey).toEqual(otpks[0].publicKey);
  });
});

// ─── Key Persistence ────────────────────────────────────────────────────────

describe('Key Persistence', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('saves and loads identity keys', () => {
    const identity = generateIdentityKeyPair();
    const signed = generateSignedPreKey();
    const otpks = generateOneTimePreKeys(2);
    const keys = { identityKeyPair: identity, signedPreKey: signed, oneTimePreKeys: otpks };

    saveIdentityKeys('user-1', keys, 'test-password');

    const loaded = loadIdentityKeys('user-1', 'test-password');
    expect(loaded).not.toBeNull();
    expect(keyToHex(loaded!.identityKeyPair.publicKey)).toBe(keyToHex(identity.publicKey));
    expect(keyToHex(loaded!.identityKeyPair.privateKey)).toBe(keyToHex(identity.privateKey));
    expect(loaded!.oneTimePreKeys.length).toBe(2);
  });

  it('returns null for wrong password', () => {
    const keys = {
      identityKeyPair: generateIdentityKeyPair(),
      signedPreKey: generateSignedPreKey(),
      oneTimePreKeys: [],
    };
    saveIdentityKeys('user-1', keys, 'correct');
    const loaded = loadIdentityKeys('user-1', 'wrong');
    expect(loaded).toBeNull();
  });

  it('returns null for missing key', () => {
    const loaded = loadIdentityKeys('nonexistent', 'pass');
    expect(loaded).toBeNull();
  });
});

// ─── Message Encrypt/Decrypt Roundtrip (X3DH + Double Ratchet) ──────────────

describe('Message encrypt/decrypt roundtrip', () => {
  it('X3DH produces matching shared secrets', () => {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const bobSigned = generateSignedPreKey();
    const bobOtpk = generateOneTimePreKeys(1)[0];

    const bundle = buildPreKeyBundle(bob, bobSigned, bobOtpk);
    const { sharedSecret: aliceSecret, ephemeralPublicKey } = x3dhInitiate(alice, bundle);

    const bobSecret = x3dhRespond(bob, bobSigned, bobOtpk, alice.publicKey, ephemeralPublicKey);

    expect(keyToHex(aliceSecret)).toBe(keyToHex(bobSecret));
  });

  it('encrypt and decrypt a message via Double Ratchet', () => {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const bobSigned = generateSignedPreKey();

    const bundle = buildPreKeyBundle(bob, bobSigned);
    const { sharedSecret, ephemeralPublicKey } = x3dhInitiate(alice, bundle);
    const bobSecret = x3dhRespond(bob, bobSigned, undefined, alice.publicKey, ephemeralPublicKey);

    const aliceSession = DoubleRatchetSession.initAlice(sharedSecret, bobSigned.publicKey);
    const bobSession = DoubleRatchetSession.initBob(bobSecret, bobSigned.privateKey);

    const plaintext = 'Hello, Bob!';
    const encrypted = aliceSession.encrypt(new TextEncoder().encode(plaintext));
    const decrypted = bobSession.decrypt(encrypted);

    expect(new TextDecoder().decode(decrypted)).toBe(plaintext);
  });
});

// ─── Double Ratchet Session ─────────────────────────────────────────────────

describe('Double Ratchet Session', () => {
  function createSessionPair() {
    const sharedSecret = new Uint8Array(32);
    crypto.getRandomValues(sharedSecret);
    const bobSigned = generateSignedPreKey();

    const alice = DoubleRatchetSession.initAlice(new Uint8Array(sharedSecret), bobSigned.publicKey);
    const bob = DoubleRatchetSession.initBob(new Uint8Array(sharedSecret), bobSigned.privateKey);
    return { alice, bob };
  }

  it('encrypts 3 messages and decrypts in order', () => {
    const { alice, bob } = createSessionPair();
    const messages = ['msg-0', 'msg-1', 'msg-2'];
    const encrypted = messages.map(m => alice.encrypt(new TextEncoder().encode(m)));

    for (let i = 0; i < 3; i++) {
      const decrypted = bob.decrypt(encrypted[i]);
      expect(new TextDecoder().decode(decrypted)).toBe(messages[i]);
    }
  });

  it('handles out-of-order message decryption', () => {
    const { alice, bob } = createSessionPair();
    const encrypted = [
      alice.encrypt(new TextEncoder().encode('first')),
      alice.encrypt(new TextEncoder().encode('second')),
      alice.encrypt(new TextEncoder().encode('third')),
    ];

    // Decrypt out of order: third, first, second
    expect(new TextDecoder().decode(bob.decrypt(encrypted[2]))).toBe('third');
    expect(new TextDecoder().decode(bob.decrypt(encrypted[0]))).toBe('first');
    expect(new TextDecoder().decode(bob.decrypt(encrypted[1]))).toBe('second');
  });

  it('supports bidirectional messaging', () => {
    const { alice, bob } = createSessionPair();

    // Alice → Bob
    const e1 = alice.encrypt(new TextEncoder().encode('hello bob'));
    expect(new TextDecoder().decode(bob.decrypt(e1))).toBe('hello bob');

    // Bob → Alice
    const e2 = bob.encrypt(new TextEncoder().encode('hello alice'));
    expect(new TextDecoder().decode(alice.decrypt(e2))).toBe('hello alice');

    // Alice → Bob again
    const e3 = alice.encrypt(new TextEncoder().encode('still here'));
    expect(new TextDecoder().decode(bob.decrypt(e3))).toBe('still here');
  });

  it('serializes and deserializes session state', () => {
    const { alice, bob } = createSessionPair();

    const e1 = alice.encrypt(new TextEncoder().encode('before save'));
    bob.decrypt(e1);

    const serialized = alice.serialize();
    const restored = DoubleRatchetSession.deserialize(serialized);

    const e2 = restored.encrypt(new TextEncoder().encode('after restore'));
    const decrypted = bob.decrypt(e2);
    expect(new TextDecoder().decode(decrypted)).toBe('after restore');
  });
});

// ─── hasStoredKeyPair ───────────────────────────────────────────────────────

describe('hasStoredKeyPair', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns false when nothing stored', () => {
    expect(hasStoredKeyPair()).toBe(false);
  });

  it('returns true when regular public key is stored', () => {
    localStorage.setItem('accord_public_key', 'some-base64-key');
    expect(hasStoredKeyPair()).toBe(true);
  });

  it('returns true when _pwd slot is stored', () => {
    localStorage.setItem('accord_public_key_pwd', 'encrypted-key');
    expect(hasStoredKeyPair()).toBe(true);
  });

  it('returns true when namespaced key with pkHash is stored', () => {
    const hash = 'abcdef0123456789abcdef0123456789';
    localStorage.setItem(`accord_public_key_${hash.slice(0, 16)}`, 'key-data');
    expect(hasStoredKeyPair(hash)).toBe(true);
  });

  it('returns true when _pwd slot with hash suffix is stored', () => {
    const hash = 'abcdef0123456789abcdef0123456789';
    localStorage.setItem(`accord_public_key_pwd_${hash.slice(0, 16)}`, 'encrypted-key');
    expect(hasStoredKeyPair(hash)).toBe(true);
  });
});
