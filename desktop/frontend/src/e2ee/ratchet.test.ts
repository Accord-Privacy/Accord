/**
 * SPEC-03 §6.10 E2EE manager additions: the Double Ratchet reports whether a
 * stored skipped message key produced a plaintext (REQ-32), and exposes the
 * length of the current sending chain, `sendN` (REQ-21). T-21 and T-32 build
 * on these facts; their call-level parts live with `CallKeyManager`.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { generateIdentityKeyPair, generateOneTimePreKeys, generateSignedPreKey, buildPreKeyBundle } from './keys';
import { x3dhInitiate, x3dhRespond } from './x3dh';
import { DoubleRatchetSession } from './ratchet';
import { SessionManager } from './session';
import { E2EEManager } from './index';

const enc = new TextEncoder();
const dec = new TextDecoder();

function pair(): { alice: DoubleRatchetSession; bob: DoubleRatchetSession } {
  const aliceId = generateIdentityKeyPair();
  const bobId = generateIdentityKeyPair();
  const bobSpk = generateSignedPreKey();
  const bobOtpk = generateOneTimePreKeys(1)[0];
  const bundle = buildPreKeyBundle(bobId, bobSpk, bobOtpk);
  const { sharedSecret: sa, ephemeralPublicKey } = x3dhInitiate(aliceId, bundle);
  const sb = x3dhRespond(bobId, bobSpk, bobOtpk, aliceId.publicKey, ephemeralPublicKey);
  return {
    alice: DoubleRatchetSession.initAlice(sa, bobSpk.publicKey),
    bob: DoubleRatchetSession.initBob(sb, bobSpk.privateKey),
  };
}

describe('DoubleRatchetSession: skipped-key reporting (SPEC-03 REQ-32)', () => {
  it('reports in-order messages as not using a skipped key', () => {
    const { alice, bob } = pair();
    for (let i = 0; i < 3; i++) {
      const r = bob.decryptDetailed(alice.encrypt(enc.encode(`m${i}`)));
      expect(dec.decode(r.plaintext)).toBe(`m${i}`);
      expect(r.usedSkippedKey).toBe(false);
    }
  });

  it('withheld message n, then n+1, then n: n decrypts only through a stored skipped key, once', () => {
    const { alice, bob } = pair();
    const n = alice.encrypt(enc.encode('withheld'));
    const n1 = alice.encrypt(enc.encode('retransmission'));
    const later = bob.decryptDetailed(n1);
    expect(later.usedSkippedKey).toBe(false);
    const old = bob.decryptDetailed(n);
    expect(dec.decode(old.plaintext)).toBe('withheld');
    expect(old.usedSkippedKey).toBe(true);
    // The decryption consumed the stored key: a second delivery fails.
    expect(() => bob.decryptDetailed(n)).toThrow();
  });

  it('a message left behind in an earlier chain is reported as a skipped-key decryption', () => {
    const { alice, bob } = pair();
    const lost = alice.encrypt(enc.encode('old chain'));
    bob.decrypt(alice.encrypt(enc.encode('a1')));
    alice.decrypt(bob.encrypt(enc.encode('b1')));
    const fresh = bob.decryptDetailed(alice.encrypt(enc.encode('new chain')));
    expect(fresh.usedSkippedKey).toBe(false);
    const r = bob.decryptDetailed(lost);
    expect(dec.decode(r.plaintext)).toBe('old chain');
    expect(r.usedSkippedKey).toBe(true);
  });

  it('decrypt() keeps returning the plaintext bytes', () => {
    const { alice, bob } = pair();
    expect(dec.decode(bob.decrypt(alice.encrypt(enc.encode('plain'))))).toBe('plain');
  });
});

describe('DoubleRatchetSession: sending chain length (SPEC-03 REQ-21)', () => {
  it('counts every message encrypted since the last DH ratchet step', () => {
    const { alice, bob } = pair();
    expect(alice.sendingChainLength).toBe(0);
    for (let i = 1; i <= 5; i++) {
      bob.decrypt(alice.encrypt(enc.encode(`x${i}`)));
      expect(alice.sendingChainLength).toBe(i);
    }
  });

  it('returns to 0 only when a message carrying a new ratchet key from the peer is decrypted', () => {
    const { alice, bob } = pair();
    for (let i = 0; i < 4; i++) bob.decrypt(alice.encrypt(enc.encode('a')));
    expect(alice.sendingChainLength).toBe(4);
    // Bob's first reply carries a new ratchet key.
    const reply1 = bob.encrypt(enc.encode('b1'));
    const reply2 = bob.encrypt(enc.encode('b2'));
    expect(bob.sendingChainLength).toBe(2);
    alice.decrypt(reply1);
    expect(alice.sendingChainLength).toBe(0);
    alice.encrypt(enc.encode('a after'));
    expect(alice.sendingChainLength).toBe(1);
    // A second message on the same peer chain does not reset it again.
    alice.decrypt(reply2);
    expect(alice.sendingChainLength).toBe(1);
  });

  it('a failed decryption changes neither the chain length nor later decryption', () => {
    const { alice, bob } = pair();
    bob.decrypt(alice.encrypt(enc.encode('a')));
    const good = bob.encrypt(enc.encode('b'));
    const forged = { ...good, ciphertext: btoa('x'.repeat(40)) };
    expect(() => alice.decrypt(forged)).toThrow();
    expect(alice.sendingChainLength).toBe(1);
    expect(dec.decode(alice.decrypt(good))).toBe('b');
    expect(alice.sendingChainLength).toBe(0);
  });

  it('survives serialization', () => {
    const { alice, bob } = pair();
    for (let i = 0; i < 3; i++) bob.decrypt(alice.encrypt(enc.encode('a')));
    expect(DoubleRatchetSession.deserialize(alice.serialize()).sendingChainLength).toBe(3);
  });
});

describe('E2EEManager: decryptEnvelopeDetailed and sendingChainLength (SPEC-03 §6.10)', () => {
  const A = '11111111-2222-4333-8444-555555555555';
  const B = '66666666-7777-4888-8999-aaaaaaaaaaaa';
  let alice: E2EEManager;
  let bob: E2EEManager;
  let bobBundle: ReturnType<E2EEManager['initialize']>;

  beforeEach(() => {
    localStorage.clear();
    alice = new E2EEManager();
    bob = new E2EEManager();
    alice.initialize();
    bobBundle = bob.initialize();
  });

  it('returns null without a session or before initialization', () => {
    expect(alice.sendingChainLength(B)).toBeNull();
    expect(new E2EEManager().sendingChainLength(B)).toBeNull();
  });

  it('counts messages of any kind and resets when the peer answers with a new ratchet key', () => {
    const envs = [alice.encryptEnvelope(B, 'dm', bobBundle), alice.encryptEnvelope(B, 'skdm'), alice.encryptEnvelope(B, 'call')];
    expect(alice.sendingChainLength(B)).toBe(3);
    for (const e of envs) {
      const r = bob.decryptEnvelopeDetailed(A, e);
      expect(r.usedSkippedKey).toBe(false);
    }
    expect(bob.sendingChainLength(A)).toBe(0);
    const reply = bob.encryptEnvelope(A, 'reply');
    expect(bob.sendingChainLength(A)).toBe(1);
    expect(alice.decryptEnvelopeDetailed(B, reply)).toEqual({ plaintext: 'reply', usedSkippedKey: false });
    expect(alice.sendingChainLength(B)).toBe(0);
  });

  it('reports a withheld envelope decrypted after a later one as a skipped-key decryption', () => {
    const first = alice.encryptEnvelope(B, 'first', bobBundle);
    const withheld = alice.encryptEnvelope(B, 'withheld');
    const later = alice.encryptEnvelope(B, 'later');
    expect(bob.decryptEnvelopeDetailed(A, first).usedSkippedKey).toBe(false);
    expect(bob.decryptEnvelopeDetailed(A, later)).toEqual({ plaintext: 'later', usedSkippedKey: false });
    expect(bob.decryptEnvelopeDetailed(A, withheld)).toEqual({ plaintext: 'withheld', usedSkippedKey: true });
    // decryptEnvelope stays a plain string API.
    expect(bob.decryptEnvelope(A, alice.encryptEnvelope(B, 'plain'))).toBe('plain');
  });

  it('keeps skipped keys and the chain length across a reload from storage', () => {
    const first = alice.encryptEnvelope(B, 'first', bobBundle);
    const withheld = alice.encryptEnvelope(B, 'withheld');
    const later = alice.encryptEnvelope(B, 'later');
    bob.decryptEnvelope(A, first);
    bob.decryptEnvelope(A, later);
    // A fresh session manager over the same identity reads the stored session.
    const reloaded = new SessionManager((bob as unknown as { identityKeyPair: ConstructorParameters<typeof SessionManager>[0] }).identityKeyPair);
    expect(reloaded.sendingChainLength(A)).toBe(0);
    const env = JSON.parse(withheld) as { ct: string };
    expect(reloaded.decryptDetailed(A, env.ct)).toEqual({ plaintext: 'withheld', usedSkippedKey: true });
  });
});
