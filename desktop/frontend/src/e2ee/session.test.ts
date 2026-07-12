import { describe, it, expect, beforeEach } from 'vitest';
import { generateIdentityKeyPair, generateSignedPreKey, generateOneTimePreKeys, buildPreKeyBundle, keyToHex } from './keys';
import { x3dhInitiate, x3dhRespond } from './x3dh';
import { SessionManager } from './session';

const STORAGE_PREFIX = 'accord_e2ee_session_';

/** Set up Alice and Bob with completed X3DH and live SessionManagers. */
function establishPair() {
  const aliceIdentity = generateIdentityKeyPair();
  const bobIdentity = generateIdentityKeyPair();
  const bobSigned = generateSignedPreKey();
  const bobOtpk = generateOneTimePreKeys(1)[0];
  const bundle = buildPreKeyBundle(bobIdentity, bobSigned, bobOtpk);

  const { sharedSecret: aliceSecret, ephemeralPublicKey } = x3dhInitiate(aliceIdentity, bundle);
  const bobSecret = x3dhRespond(bobIdentity, bobSigned, bobOtpk, aliceIdentity.publicKey, ephemeralPublicKey);

  const alice = new SessionManager(aliceIdentity);
  const bob = new SessionManager(bobIdentity);
  alice.createSessionAsAlice('bob', aliceSecret, bobSigned.publicKey);
  bob.createSessionAsBob('alice', bobSecret, bobSigned.privateKey);

  return { alice, bob, aliceIdentity, bobIdentity, bobSigned, aliceSecret };
}

function storageKeyFor(identityPublicKey: Uint8Array, peerId: string): string {
  return `${STORAGE_PREFIX}${keyToHex(identityPublicKey).slice(0, 16)}_${peerId}`;
}

describe('SessionManager', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('encrypts and decrypts both directions', () => {
    const { alice, bob } = establishPair();

    const toBob = alice.encrypt('bob', 'hello bob');
    expect(bob.decrypt('alice', toBob)).toBe('hello bob');

    const toAlice = bob.encrypt('alice', 'hello alice');
    expect(alice.decrypt('bob', toAlice)).toBe('hello alice');
  });

  it('throws when encrypting without a session (missing bundle case)', () => {
    const mgr = new SessionManager(generateIdentityKeyPair());
    expect(() => mgr.encrypt('stranger', 'hi')).toThrow(/No E2EE session/);
    expect(mgr.hasSession('stranger')).toBe(false);
  });

  it('recovers a persisted session in a fresh SessionManager instance', () => {
    const { alice, bob, aliceIdentity } = establishPair();
    // Advance the ratchet before "restarting"
    bob.decrypt('alice', alice.encrypt('bob', 'first'));

    // Simulate app restart: new manager, same identity, same localStorage
    const aliceRestarted = new SessionManager(aliceIdentity);
    expect(aliceRestarted.hasSession('bob')).toBe(true);

    const toBob = aliceRestarted.encrypt('bob', 'after restart');
    expect(bob.decrypt('alice', toBob)).toBe('after restart');

    const toAlice = bob.encrypt('alice', 'reply');
    expect(aliceRestarted.decrypt('bob', toAlice)).toBe('reply');
  });

  it('does not load a session persisted under a different identity key', () => {
    const { aliceIdentity } = establishPair();
    // Same localStorage, different identity: storage key and decryption key both differ
    const other = new SessionManager(generateIdentityKeyPair());
    expect(other.hasSession('bob')).toBe(false);

    // Even if the ciphertext is copied under the other identity's storage key,
    // decryption with the wrong identity key must fail
    const stored = localStorage.getItem(storageKeyFor(aliceIdentity.publicKey, 'bob'));
    expect(stored).not.toBeNull();
    const otherIdentity = generateIdentityKeyPair();
    localStorage.setItem(storageKeyFor(otherIdentity.publicKey, 'bob'), stored!);
    const impostor = new SessionManager(otherIdentity);
    expect(impostor.hasSession('bob')).toBe(false);
  });

  it('treats corrupted persisted state as no session (stale session case)', () => {
    const { aliceIdentity } = establishPair();
    const key = storageKeyFor(aliceIdentity.publicKey, 'bob');
    localStorage.setItem(key, 'not-valid-base64-ciphertext!!!');

    const restarted = new SessionManager(aliceIdentity);
    expect(restarted.hasSession('bob')).toBe(false);
    expect(() => restarted.encrypt('bob', 'hi')).toThrow(/No E2EE session/);
  });

  it('removeSession deletes in-memory and persisted state', () => {
    const { alice, aliceIdentity } = establishPair();
    const key = storageKeyFor(aliceIdentity.publicKey, 'bob');
    expect(localStorage.getItem(key)).not.toBeNull();

    alice.removeSession('bob');
    expect(localStorage.getItem(key)).toBeNull();
    expect(alice.hasSession('bob')).toBe(false);
    expect(() => alice.encrypt('bob', 'hi')).toThrow(/No E2EE session/);
  });

  it('persists ratchet state after every encrypt/decrypt (no replay after restart)', () => {
    const { alice, bob, bobIdentity } = establishPair();

    const m1 = alice.encrypt('bob', 'one');
    expect(bob.decrypt('alice', m1)).toBe('one');

    // Restarted Bob must not decrypt m1 again (state already advanced past it)
    const bobRestarted = new SessionManager(bobIdentity);
    expect(bobRestarted.hasSession('alice')).toBe(true);
    expect(() => bobRestarted.decrypt('alice', m1)).toThrow();

    // But the session still works for new messages
    const m2 = alice.encrypt('bob', 'two');
    expect(bobRestarted.decrypt('alice', m2)).toBe('two');
  });

  it('handles out-of-order delivery across a restart (skipped message keys persisted)', () => {
    const { alice, bob, bobIdentity } = establishPair();
    // Prime the session so both sides have ratchet state
    bob.decrypt('alice', alice.encrypt('bob', 'prime'));

    const m1 = alice.encrypt('bob', 'first');
    const m2 = alice.encrypt('bob', 'second');

    // Bob receives the later message first, then restarts
    expect(bob.decrypt('alice', m2)).toBe('second');
    const bobRestarted = new SessionManager(bobIdentity);
    expect(bobRestarted.decrypt('alice', m1)).toBe('first');
  });

  it('tampered message neither desyncs the chain nor consumes a skipped key', () => {
    const { alice, bob } = establishPair();
    bob.decrypt('alice', alice.encrypt('bob', 'prime'));

    const m1 = alice.encrypt('bob', 'first');
    const m2 = alice.encrypt('bob', 'second');

    // Out-of-order: m2 first, so m1's key is stored as a skipped key
    expect(bob.decrypt('alice', m2)).toBe('second');

    // Tamper with m1's ciphertext
    const parsed = JSON.parse(m1);
    const bytes = Uint8Array.from(atob(parsed.ciphertext), c => c.charCodeAt(0));
    bytes[0] ^= 0xff;
    parsed.ciphertext = btoa(String.fromCharCode(...bytes));
    expect(() => bob.decrypt('alice', JSON.stringify(parsed))).toThrow();

    // The untampered original must still decrypt
    expect(bob.decrypt('alice', m1)).toBe('first');
  });
});
