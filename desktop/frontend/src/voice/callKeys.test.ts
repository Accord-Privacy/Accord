// @vitest-environment node
/**
 * SPEC-03 `CallKeyManager` (§11.2 step 5) with fake transports and the fake
 * bridge of `callKeys.testkit.ts`: T-5, T-7, T-9 (manager side), T-11 (as a
 * U property), T-12, T-16, T-17, T-19, T-20, T-21, T-33 and T-36, plus the
 * state machines of §8.1 and §8.2. The media-key tests (T-6, T-14, T-15,
 * T-18, T-34, T-35 and A1's video parts) are in `callKeys.media.test.ts`; the
 * bridge implementation's tests, with real Double Ratchet sessions, are in
 * `callKeyBridge.test.ts`.
 *
 * The clock is manual; every timer of the managers runs only inside
 * `net.advance`. Times below are offsets from the start of each test.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { decodeWireBase64 } from '../attachments/base64';
import {
  A,
  B,
  C,
  CH,
  CH2,
  D,
  E,
  Net,
  b64,
  callPlaintext,
  readCall,
  testInst,
  wrapFake,
  type CallRecord,
  type ClientOptions,
} from './callKeys.testkit';
import { CALL_ENVELOPE_PREFIX, INDICATOR_TEXT, PARTICIPANT_LABEL_TEXT, type CallKeyManager } from './callKeys';

const TAG = '\u001eaccord-call\u001e';
const raw = (body: object) => TAG + JSON.stringify(body);

function instBytes(m: CallKeyManager): Uint8Array {
  return decodeWireBase64(m.instanceId)!;
}

const hello = (from: string, inst: Uint8Array, toInst: string | null) =>
  callPlaintext({ type: 'call_hello', v: 1, from, ch: CH, inst: b64(inst), to_inst: toInst });
const ckm = (from: string, inst: Uint8Array, toInst: string | null, epoch: number, key: Uint8Array) =>
  callPlaintext({ type: 'call_key', v: 1, suite: 5, from, ch: CH, inst: b64(inst), to_inst: toInst, epoch, key: b64(key) });
const ackMsg = (from: string, inst: Uint8Array, toInst: string, epoch: number) =>
  callPlaintext({ type: 'call_key_ack', v: 1, from, ch: CH, inst: b64(inst), to_inst: toInst, epoch });

const keyOf = (seed: number) => new Uint8Array(32).fill(seed);

/** Collect the 32-byte secrets a client draws, in order (its epochs 0, 1, …). */
function capturingRandom(): { random: (n: number) => Uint8Array; secrets: Uint8Array[] } {
  const secrets: Uint8Array[] = [];
  return {
    secrets,
    random: n => {
      const b = crypto.getRandomValues(new Uint8Array(n));
      if (n === 32) secrets.push(Uint8Array.from(b));
      return b;
    },
  };
}

function label(m: CallKeyManager, user: string) {
  return m.snapshot().participants.find(p => p.userId === user)!;
}

async function twoParty(opts: Partial<Record<string, ClientOptions>> = {}) {
  const net = new Net();
  const a = net.client(A, opts[A]);
  const b = net.client(B, opts[B]);
  await net.join(A, B);
  return { net, a, b };
}

/** A client A alone in a call whose V is `others` (no other managers): messages are injected. */
async function lone(others: string[], opts: ClientOptions = {}) {
  const net = new Net();
  const a = net.client(A, opts);
  a.mgr.start();
  a.mgr.onJoined(others);
  await net.settle();
  return { net, a };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// T-5
// ---------------------------------------------------------------------------

describe('T-5 (REQ-5) instances', () => {
  it('two calls use different instances and secrets from getRandomValues (16 and 32 bytes), and nothing is stored', async () => {
    const spy = vi.spyOn(crypto, 'getRandomValues');
    const writes: string[] = [];
    const storage = {
      getItem: () => null,
      setItem: (k: string) => void writes.push(k),
      removeItem: (k: string) => void writes.push(k),
      clear: () => void writes.push('clear'),
      key: () => null,
      length: 0,
    };
    vi.stubGlobal('localStorage', storage);
    vi.stubGlobal('sessionStorage', storage);
    const { net, a, b } = await twoParty();
    const inst1 = a.mgr.instanceId;
    const keys1 = net.callsBetween(A, B, 'call_key').map(m => m.body.key);
    const count1 = net.calls.length;
    net.newCall(a);
    net.newCall(b);
    await net.join(A, B);
    const second = net.calls.slice(count1).filter(m => m.from === A && m.to === B).map(m => readCall(m.wrappedKey));
    expect(a.mgr.instanceId).not.toBe(inst1);
    expect(second.every(m => m.inst === a.mgr.instanceId)).toBe(true);
    const keys2 = second.filter(m => m.type === 'call_key').map(m => m.key);
    expect(keys1.length).toBeGreaterThan(0);
    expect(keys2.length).toBeGreaterThan(0);
    for (const k of keys2) expect(keys1).not.toContain(k);
    const sizes = spy.mock.calls.map(c => (c[0] as Uint8Array).length);
    expect(sizes).toContain(16);
    expect(sizes).toContain(32);
    expect(writes).toEqual([]);
  });

  it('a later voice_channel_joined only reconciles V: epochs continue, and the extra participant causes one rotation', async () => {
    const net = new Net();
    const a = net.client(A);
    net.client(B);
    await net.join(A, B);
    expect(a.mgr.snapshot().newestEpoch).toBe(0);
    a.mgr.onJoined([B, C]);
    expect(a.mgr.participants().sort()).toEqual([B, C].sort());
    await net.advance(20_000);
    expect(a.mgr.snapshot().newestEpoch).toBe(1);
    expect(new Set(net.callsBetween(A, B, 'call_key').map(m => m.body.epoch))).toEqual(new Set([0, 1]));
  });
});

// ---------------------------------------------------------------------------
// T-7
// ---------------------------------------------------------------------------

describe('T-7 (REQ-7) R_g never gains members', () => {
  it('a newcomer never receives an older epoch, and a member who becomes eligible later only the new one', async () => {
    const net = new Net();
    const a = net.client(A);
    net.client(B);
    net.client(C);
    net.client(D);
    await net.join(A, B);
    let dropped = 0;
    net.callFilter = m => (m.from === A && m.to === C && readCall(m.wrappedKey).type === 'call_key' && dropped++ < 3 ? 'drop' : 'deliver');
    await net.joinLate(C, [A, B]);
    await net.advance(20_000);
    const toC = net.callsBetween(A, C, 'call_key');
    expect(toC.length).toBeGreaterThan(3); // retransmissions happened
    expect(toC.every(m => (m.body.epoch as number) >= 1)).toBe(true);

    a.fake.membershipOf.set(D, 'not_member');
    await net.joinLate(D, [A, B, C]);
    await net.advance(5000);
    const before = a.mgr.snapshot().newestEpoch!;
    expect(net.callsBetween(A, D)).toEqual([]);
    a.fake.setMembership(D, 'member');
    await net.advance(5000);
    const after = a.mgr.snapshot().newestEpoch!;
    expect(after).toBe(before + 1);
    const toD = net.callsBetween(A, D, 'call_key');
    expect(toD.length).toBeGreaterThan(0);
    expect(toD.every(m => m.body.epoch === after)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// T-9, manager side
// ---------------------------------------------------------------------------

describe('T-9 (REQ-9) interim eligibility, manager side', () => {
  it('a participant whose membership is unknown, then absent, gets no hello or CKM, and none of its envelopes is decrypted', async () => {
    const net = new Net();
    const a = net.client(A);
    net.client(B);
    a.fake.membershipOf.set(B, 'unknown');
    await net.join(A, B);
    expect(label(a.mgr, B).label).toBe('checking_membership');
    await net.advance(9000);
    a.fake.setMembership(B, 'not_member');
    await net.advance(120_000);
    expect(a.fake.decryptCalls.filter(c => c.peer === B)).toEqual([]);
    expect(net.callsBetween(A, B)).toEqual([]);
    expect(a.mgr.currentRecipients()).toEqual([]);
    expect(label(a.mgr, B).label).toBe('not_verified_member');
    expect(label(a.mgr, B).outbound).toBe('blocked');
  });

  it('refreshes the member list every 60 s, and the indicator says "not verified" under the interim rule', async () => {
    const { net, a } = await twoParty();
    const times: number[] = [];
    const orig = a.fake.refreshMembership.bind(a.fake);
    a.fake.refreshMembership = (node, cause) => {
      if (cause === 'timer') times.push(net.clock.now());
      return orig(node, cause);
    };
    const t0 = net.clock.now();
    await net.advance(185_000);
    expect(times.map(t => Math.round((t - t0) / 1000))).toEqual([60, 120, 180]);
    expect(a.mgr.snapshot().indicator).toBe('e2ee_not_verified');
    expect(INDICATOR_TEXT.e2ee_not_verified).toBe('End-to-end encrypted · not verified');
  });

  it('shows "Checking membership…" until the first fetch, and "Can\'t verify members" when it failed, retrying on the backoff', async () => {
    const net = new Net();
    const a = net.client(A);
    a.fake.refreshFails = true;
    a.mgr.start();
    a.mgr.onJoined([B]);
    expect(a.mgr.snapshot().indicator).toBe('checking_membership');
    await net.settle();
    expect(a.mgr.snapshot().indicator).toBe('cant_verify_members');
    a.fake.refreshFails = false;
    await net.advance(2000); // the first retry of the 2, 4, 6, 8, 10 s backoff
    expect(a.mgr.snapshot().indicator).toBe('connecting');
    expect(a.fake.refreshCalls.filter(c => c.cause === 'call_start').length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// T-11 (U form)
// ---------------------------------------------------------------------------

describe('T-11 (REQ-11), as a U property', () => {
  it('after random joins, leaves and eligibility changes, every call message went to a member of V that was eligible, and every CKM to a member of its R', async () => {
    let seed = 12345;
    const rnd = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    const net = new Net();
    const a = net.client(A);
    const others = [B, C, D, E];
    for (const o of others) net.client(o);
    const violations: string[] = [];
    net.callFilter = (m: CallRecord) => {
      if (m.from !== A) return 'deliver';
      if (!a.mgr.participants().includes(m.to)) violations.push(`not in V: ${m.to}`);
      if (a.fake.membership('', '', m.to) !== 'member') violations.push(`not eligible: ${m.to}`);
      const body = readCall(m.wrappedKey);
      if (body.type === 'call_key') {
        // REQ-19: a CKM carries the current epoch and goes to members of its R only.
        if (body.epoch !== a.mgr.snapshot().newestEpoch) violations.push(`stale epoch ${String(body.epoch)}`);
        if (!a.mgr.currentRecipients().includes(m.to)) violations.push(`not in R_${String(body.epoch)}: ${m.to}`);
      }
      return 'deliver';
    };
    a.mgr.start();
    a.mgr.onJoined([]);
    const inCall = new Set<string>();
    for (let step = 0; step < 60; step++) {
      const who = others[Math.floor(rnd() * others.length)];
      const op = rnd();
      if (op < 0.35) {
        if (!inCall.has(who)) {
          inCall.add(who);
          const c = net.clients.get(who)!;
          if (c.mgr.isEnded) net.newCall(c);
          a.mgr.onPeerJoined(who);
          for (const o of inCall) if (o !== who) net.clients.get(o)!.mgr.onPeerJoined(who);
          c.mgr.start();
          c.mgr.onJoined([A, ...[...inCall].filter(o => o !== who)]);
        }
      } else if (op < 0.6) {
        if (inCall.has(who)) {
          inCall.delete(who);
          a.mgr.onPeerLeft(who);
          for (const o of inCall) net.clients.get(o)!.mgr.onPeerLeft(who);
          net.clients.get(who)!.mgr.end();
        }
      } else if (op < 0.8) {
        a.fake.setMembership(who, rnd() < 0.5 ? 'member' : 'not_member');
      }
      await net.advance(Math.floor(rnd() * 3000));
      for (const p of a.mgr.snapshot().participants) {
        expect(p.shortId).toMatch(/^[0-9a-f]{8}$/);
        if (p.recipient) expect(a.mgr.participants()).toContain(p.userId);
      }
    }
    expect(net.calls.filter(m => m.from === A).length).toBeGreaterThan(10);
    expect(violations).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// REQ-1, REQ-19 at transmission time (an encryption that yields)
// ---------------------------------------------------------------------------

describe('REQ-1 and REQ-19 when the encryption yields (SPEC-05 queues every message)', () => {
  /**
   * A alone with V = [B]; every encryption for a peer waits for `release()`.
   * B's hello naming A's instance makes A build epoch 0's CKM for B, whose
   * encryption is then waiting.
   */
  async function ckmWaitingInEncryption() {
    const { net, a } = await lone([B]);
    let release!: () => void;
    const gate = new Promise<void>(r => {
      release = r;
    });
    const enc = a.fake.encryptFor.bind(a.fake);
    const waiting: string[] = [];
    a.fake.encryptFor = async (peer, plaintext, useCredit) => {
      waiting.push(peer);
      await gate;
      return enc(peer, plaintext, useCredit);
    };
    const since = net.calls.length;
    a.mgr.handleKeyExchange({ from: B, channel_id: CH, wrapped_key: wrapFake(B, A, hello(B, testInst(2), a.mgr.instanceId)) });
    for (let i = 0; i < 50 && waiting.length === 0; i++) await new Promise(r => setImmediate(r));
    expect(waiting).toEqual([B]);
    expect(a.mgr.currentRecipients()).toEqual([B]);
    return { net, a, release, since };
  }

  it('a CKM whose peer was excluded while it was being encrypted is not handed off', async () => {
    const { net, a, release, since } = await ckmWaitingInEncryption();
    a.fake.setMembership(B, 'not_member'); // sender_key_rotation_required, or a refreshed list
    release();
    await a.mgr.whenIdle();
    expect(net.calls.slice(since).filter(m => m.to === B)).toEqual([]);
  });

  it('a CKM whose epoch was superseded while it was being encrypted is not handed off; the new epoch\'s CKM goes instead', async () => {
    const { net, a, release, since } = await ckmWaitingInEncryption();
    a.mgr.onPeerJoined(C);
    await net.clock.advance(600); // the coalesced rotation: epoch 1, R_1 = {B, C}
    expect(a.mgr.snapshot().newestEpoch).toBe(1);
    release();
    await a.mgr.whenIdle();
    const ckms = net.calls.slice(since).filter(m => m.to === B).map(m => readCall(m.wrappedKey)).filter(b => b.type === 'call_key');
    expect(ckms.map(b => b.epoch)).toEqual([1]);
  });
});

// ---------------------------------------------------------------------------
// T-12
// ---------------------------------------------------------------------------

describe('T-12 (REQ-12) accepting call messages', () => {
  const instB = testInst(0x11);

  async function setup(opts: ClientOptions = {}) {
    const { net, a } = await lone([B, C], opts);
    return { net, a, toA: a.mgr.instanceId };
  }

  function validKey(toA: string, over: Record<string, unknown> = {}) {
    return { type: 'call_key', v: 1, suite: 5, from: B, ch: CH, inst: b64(instB), to_inst: toA, epoch: 0, key: b64(keyOf(7)), ...over };
  }

  it('a valid call_key is installed and acknowledged (positive control)', async () => {
    const { net, a, toA } = await setup();
    net.inject(A, B, wrapFake(B, A, callPlaintext(validKey(toA))));
    await net.settle();
    expect(a.mgr.retainedRecord(B)!.keys.length).toBe(2);
    expect(net.callsBetween(A, B, 'call_key_ack').map(m => m.body.epoch)).toEqual([0]);
  });

  it.each([
    ['wrong ch', (toA: string) => callPlaintext(validKey(toA, { ch: CH2 }))],
    ['from differing from the stamped sender', (toA: string) => callPlaintext(validKey(toA, { from: C }))],
    ['v = 2', (toA: string) => raw(validKey(toA, { v: 2 }))],
    ['unknown type', (toA: string) => raw(validKey(toA, { type: 'call_bye' }))],
    ['missing tag', (toA: string) => JSON.stringify(validKey(toA))],
    ['a 15-byte inst', (toA: string) => callPlaintext(validKey(toA, { inst: b64(new Uint8Array(15)) }))],
    ['a call_key with a null to_inst', (toA: string) => callPlaintext(validKey(toA, { to_inst: null }))],
    ['suite 4', (toA: string) => callPlaintext(validKey(toA, { suite: 4 }))],
    ['suite 6', (toA: string) => callPlaintext(validKey(toA, { suite: 6 }))],
    ['a 31-byte key', (toA: string) => callPlaintext(validKey(toA, { key: b64(new Uint8Array(31).fill(7)) }))],
    ['an epoch of 2^32', (toA: string) => callPlaintext(validKey(toA, { epoch: 2 ** 32 }))],
  ])('%s: discarded, nothing installed or acknowledged', async (_name, make) => {
    const { net, a, toA } = await setup();
    net.inject(A, B, wrapFake(B, A, make(toA)));
    await net.settle();
    expect(a.mgr.retainedRecord(B)!.keys).toEqual([]);
    expect(net.callsBetween(A, B, 'call_key_ack')).toEqual([]);
  });

  it('wrong channel_id, a sender not in V, a known non-member, the local user and prefixes other than acv1: are never decrypted', async () => {
    const { net, a, toA } = await setup();
    a.fake.membershipOf.set(C, 'not_member');
    const wk = (from: string) => wrapFake(from, A, callPlaintext(validKey(toA, { from })));
    net.inject(A, B, wk(B), CH2);
    net.inject(A, E, wk(E));
    net.inject(A, C, wk(C));
    net.inject(A, A, wk(A));
    for (const prefix of ['acv2:', 'acv1', '']) net.inject(A, B, prefix + wk(B).slice(CALL_ENVELOPE_PREFIX.length));
    await net.settle();
    expect(a.fake.decryptCalls).toEqual([]);
    expect(a.mgr.retainedRecord(B)!.keys).toEqual([]);
  });

  it('with SPEC-05 (pinned sessions only): a legacy session or a v2 session bound to another ISK is discarded; the pinned v2 session is accepted', async () => {
    const { net, a, toA } = await setup();
    a.fake.pinned = true;
    a.fake.pins.set(B, new Uint8Array(32).fill(1));
    a.fake.sessionVersion = 'legacy';
    a.fake.peerIsk = null;
    net.inject(A, B, wrapFake(B, A, callPlaintext(validKey(toA))));
    await net.settle();
    expect(a.mgr.retainedRecord(B)!.keys).toEqual([]);
    a.fake.sessionVersion = 'v2';
    a.fake.peerIsk = new Uint8Array(32).fill(2);
    net.inject(A, B, wrapFake(B, A, callPlaintext(validKey(toA))));
    await net.settle();
    expect(a.mgr.retainedRecord(B)!.keys).toEqual([]);
    expect(net.callsBetween(A, B, 'call_key_ack')).toEqual([]);
    a.fake.peerIsk = new Uint8Array(32).fill(1);
    net.inject(A, B, wrapFake(B, A, callPlaintext(validKey(toA))));
    await net.settle();
    expect(a.mgr.retainedRecord(B)!.keys.length).toBe(2);
  });

  describe('holding while a membership fetch is in flight', () => {
    async function held(count: number) {
      const s = await setup();
      s.a.fake.membershipOf.set(B, 'unknown');
      for (let i = 0; i < count; i++) {
        const body = i === 0 ? hello(B, instB, s.toA) : ckm(B, instB, s.toA, i - 1, keyOf(i));
        s.net.inject(A, B, wrapFake(B, A, body));
      }
      await s.net.settle();
      expect(s.a.fake.decryptCalls).toEqual([]);
      return s;
    }

    it('three envelopes are held undecrypted, then processed in order once the fetch lists S', async () => {
      const { net, a } = await held(3);
      expect(label(a.mgr, B).label).toBe('checking_membership');
      a.fake.setMembership(B, 'member');
      await net.settle();
      const ns = a.fake.decryptCalls.map(c => c.n);
      expect(ns.length).toBe(3);
      expect([...ns].sort((x, y) => x - y)).toEqual(ns);
      expect(a.mgr.retainedRecord(B)!.maxEpoch).toBe(1);
      expect(net.callsBetween(A, B, 'call_key_ack').map(m => m.body.epoch)).toEqual([0, 1]);
    });

    it('a fetch that omits S discards them all undecrypted', async () => {
      const { net, a } = await held(3);
      a.fake.setMembership(B, 'not_member');
      await net.settle();
      a.fake.setMembership(B, 'member');
      await net.settle();
      expect(a.fake.decryptCalls).toEqual([]);
    });

    it('a 17th envelope is discarded', async () => {
      const { net, a } = await held(17);
      a.fake.setMembership(B, 'member');
      await net.settle();
      expect(a.fake.decryptCalls.length).toBe(16);
    });

    it('after 10 s all are discarded', async () => {
      const { net, a } = await held(3);
      await net.advance(10_000);
      a.fake.setMembership(B, 'member');
      await net.settle();
      expect(a.fake.decryptCalls).toEqual([]);
    });
  });
});

// ---------------------------------------------------------------------------
// T-16
// ---------------------------------------------------------------------------

describe('T-16 (REQ-16) rotation triggers', () => {
  async function three() {
    const net = new Net();
    const a = net.client(A);
    net.client(B);
    net.client(C);
    await net.join(A, B, C);
    await net.advance(3000);
    return { net, a, newest: () => a.mgr.snapshot().newestEpoch! };
  }

  it('(a) a user entering V: exactly one new epoch, after coalescing', async () => {
    const { net, a, newest } = await three();
    const g = newest();
    a.mgr.onPeerJoined(D);
    expect(newest()).toBe(g);
    await net.advance(499);
    expect(newest()).toBe(g);
    await net.advance(5000);
    expect(newest()).toBe(g + 1);
  });

  it('(b) a member of R leaving V: exactly one new epoch, begun without yielding', async () => {
    const { net, a, newest } = await three();
    const g = newest();
    a.mgr.onPeerLeft(C);
    expect(newest()).toBe(g + 1); // in the same turn
    expect(a.mgr.currentRecipients()).toEqual([B]);
    await net.advance(5000);
    expect(newest()).toBe(g + 1);
  });

  it('(c) a member of R becoming ineligible: exactly one new epoch, in the same turn', async () => {
    const { net, a, newest } = await three();
    const g = newest();
    a.fake.setMembership(C, 'not_member');
    expect(newest()).toBe(g + 1);
    expect(a.mgr.currentRecipients()).toEqual([B]);
    await net.advance(5000);
    expect(newest()).toBe(g + 1);
  });

  it('(d) a member of V becoming eligible: exactly one new epoch', async () => {
    const net = new Net();
    const a = net.client(A);
    net.client(B);
    net.client(C);
    a.fake.membershipOf.set(C, 'not_member');
    await net.join(A, B, C);
    await net.advance(3000);
    const g = a.mgr.snapshot().newestEpoch!;
    a.fake.setMembership(C, 'member');
    await net.advance(5000);
    expect(a.mgr.snapshot().newestEpoch).toBe(g + 1);
    expect(a.mgr.currentRecipients().sort()).toEqual([B, C].sort());
  });

  it('(e) 10 minutes after the epoch was created, whether or not anything was sent', async () => {
    const { net, a, newest } = await three();
    const g = newest();
    await net.advance(9 * 60_000);
    expect(newest()).toBe(g);
    await net.advance(60_000);
    expect(newest()).toBe(g + 1);
    for (let i = 0; i < 20; i++) a.mgr.sendAudio(Uint8Array.of(0, 1, 2, 3));
    await net.advance(10 * 60_000);
    expect(newest()).toBe(g + 2);
  });

  it('(e) no rotation while R_g is empty', async () => {
    const net = new Net();
    const a = net.client(A);
    a.fake.membershipOf.set(B, 'not_member');
    a.mgr.start();
    a.mgr.onJoined([B]);
    await net.advance(35 * 60_000);
    expect(a.mgr.snapshot().newestEpoch).toBe(0);
  });

  it('(f) a member of R recorded with a new instance: exactly one new epoch', async () => {
    const { net, a, newest } = await three();
    const g = newest();
    net.inject(A, B, wrapFake(B, A, hello(B, testInst(0x42), a.mgr.instanceId)));
    await net.settle();
    expect(newest()).toBe(g);
    await net.advance(5000);
    expect(newest()).toBe(g + 1);
  });

  it('two joins 100 ms apart, and a join plus a new instance 100 ms apart: one or two epochs', async () => {
    const { net, a, newest } = await three();
    let g = newest();
    a.mgr.onPeerJoined(D);
    await net.advance(100);
    a.mgr.onPeerJoined(E);
    await net.advance(5000);
    expect([g + 1, g + 2]).toContain(newest());
    g = newest();
    a.mgr.onPeerLeft(D); // so D can join again
    g = newest();
    a.mgr.onPeerJoined(D);
    await net.advance(100);
    net.inject(A, B, wrapFake(B, A, hello(B, testInst(0x43), a.mgr.instanceId)));
    await net.advance(5000);
    expect([g + 1, g + 2]).toContain(newest());
  });
});

// ---------------------------------------------------------------------------
// T-17
// ---------------------------------------------------------------------------

describe('T-17 (REQ-17) switching epochs', () => {
  it('after a departure trigger no frame leaves under the old epoch, including frames sealed before it; frames resume under the new one', async () => {
    const net = new Net();
    let release: (() => void) | null = null;
    const gate = new Promise<void>(r => (release = r));
    let gated = false;
    const a = net.client(A, {
      seal: async (...args) => {
        if (gated) await gate;
        const { sealFrame } = await import('./mediaFrame');
        return sealFrame(...args);
      },
    });
    net.client(B);
    net.client(C);
    await net.join(A, B, C);
    await net.advance(3000);
    const g = a.mgr.sendingEpoch()!;
    expect(a.mgr.sendAudio(Uint8Array.of(0, 1, 2, 3))).toBe(true);
    await net.settle();
    gated = true;
    expect(a.mgr.sendAudio(Uint8Array.of(0, 1, 2, 3))).toBe(true); // sealed under g, not handed off yet
    const sentBefore = net.media.length;
    a.mgr.onPeerLeft(C);
    expect(a.mgr.sendAudio(Uint8Array.of(0, 1, 2, 3))).toBe(false); // suspended
    gated = false;
    release!();
    await net.settle();
    expect(a.mgr.sendingEpoch()).toBe(g + 1);
    expect(a.mgr.sendAudio(Uint8Array.of(0, 1, 2, 3))).toBe(true);
    await net.settle();
    const kids = net.media.slice(sentBefore).map(m => m.frame[2] >> 4); // KID < 8: in the config byte
    expect(kids).toEqual([g + 1]);
  });

  it('a join rotation switches without waiting for a member with no session or no known instance, within 2 s, and that member receives g+1 later', async () => {
    const net = new Net();
    const a = net.client(A);
    net.client(B);
    await net.join(A, B);
    // D is in V but silent (no instance known); E has an instance but no session, and its bundle cannot be fetched yet.
    a.fake.noSession.add(E);
    a.fake.noBundle.add(E);
    net.client(E).fake.noSession.add(A); // E, the higher id, waits for A's first message (REQ-10)
    a.mgr.onPeerJoined(D);
    a.mgr.onPeerJoined(E);
    net.clients.get(E)!.mgr.start();
    net.clients.get(E)!.mgr.onJoined([A, B]);
    const t0 = net.clock.now();
    await net.advance(2000);
    expect(a.mgr.sendingEpoch()).toBe(1);
    expect(a.switches).toEqual([0, 1]);
    expect(net.clock.now() - t0).toBeLessThanOrEqual(2000);
    expect(net.callsBetween(A, E, 'call_key')).toEqual([]);
    // E's bundle becomes available: the retry on the backoff initiates, and E receives epoch 1.
    a.fake.noBundle.delete(E);
    await net.advance(10_000);
    expect(a.fake.initiations).toBe(1);
    expect(net.callsBetween(A, E, 'call_key').map(m => m.body.epoch)).toContain(1);
  });

  it('switches at the 2 s deadline when a reachable member\'s CKM is not handed off, and never to an older epoch than the newest', async () => {
    const net = new Net();
    const a = net.client(A);
    net.client(B);
    net.client(C);
    await net.join(A, B, C);
    await net.advance(3000);
    // C is reachable, but no call message to it is handed off (REQ-37).
    let refuseC = true;
    net.handOff = m => !(refuseC && m.to === C);
    a.mgr.onPeerJoined(D); // epoch 1 after 500 ms
    await net.advance(500);
    expect(a.mgr.snapshot().newestEpoch).toBe(1);
    expect(a.mgr.sendingEpoch()).toBe(0);
    await net.advance(1999);
    expect(a.mgr.sendingEpoch()).toBe(0);
    await net.advance(1);
    expect(a.mgr.sendingEpoch()).toBe(1); // the deadline, 2 s after the epoch was created
    // Overlapping rotations: epoch 2 is created while epoch 3 follows before 2 switches.
    a.mgr.onPeerLeft(D); // epoch 2, suspended
    a.mgr.onPeerLeft(B); // epoch 3 (B was in R_2), epoch 2 abandoned
    expect(a.mgr.snapshot().newestEpoch).toBe(3);
    refuseC = false;
    await net.advance(5000);
    expect(a.switches).toEqual([0, 1, 3]);
    expect(a.mgr.sendingEpoch()).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// T-19, T-20
// ---------------------------------------------------------------------------

describe('T-19 (REQ-19) and T-20 (REQ-20) retransmission', () => {
  it('T-19: a rotation or a new recipient instance during the backoff changes the next transmission; nothing goes outside R', async () => {
    const net = new Net();
    const a = net.client(A);
    net.client(B);
    net.callFilter = m => (m.from === A && m.to === B && readCall(m.wrappedKey).type === 'call_key' ? 'drop' : 'deliver');
    await net.join(A, B);
    const first = net.callsBetween(A, B, 'call_key');
    expect(first.map(m => m.body.epoch)).toEqual([0]);
    const t0 = first[0].at;
    await net.advance(300);
    a.mgr.onPeerJoined(C); // epoch 1 at +800 ms, inside the 2 s backoff
    await net.advance(1700);
    const second = net.callsBetween(A, B, 'call_key');
    expect(second.length).toBe(2);
    expect(second[1].at - t0).toBe(2000);
    expect(second[1].body.epoch).toBe(1);
    // B's instance changes during the next backoff.
    const newInst = testInst(0x55);
    net.inject(A, B, wrapFake(B, A, hello(B, newInst, a.mgr.instanceId)));
    await net.advance(4000);
    const after = net.callsBetween(A, B, 'call_key').slice(2);
    expect(after.length).toBeGreaterThan(0);
    expect(after.every(m => m.body.epoch === 2 && m.body.to_inst === b64(newInst))).toBe(true);
    // Only B and C were ever in R; C never received epoch 0.
    expect(net.calls.filter(m => m.from === A).every(m => [B, C].includes(m.to))).toBe(true);
    expect(net.callsBetween(A, C, 'call_key').every(m => (m.body.epoch as number) >= 1)).toBe(true);
  });

  it('T-20: retransmits at 2 s up to 6 transmissions, then recovers every 15 s and at once after an accepted message, never twice in 2 s, and stops when B leaves R', async () => {
    const net = new Net();
    const a = net.client(A);
    const b = net.client(B);
    net.callFilter = m => (m.from === A && m.to === B && readCall(m.wrappedKey).type === 'call_key' ? 'drop' : 'deliver');
    await net.join(A, B);
    const t0 = net.callsBetween(A, B, 'call_key')[0].at;
    const offsets = () => net.callsBetween(A, B, 'call_key').map(m => (m.at - t0) / 1000);
    await net.advance(12_000);
    expect(offsets()).toEqual([0, 2, 4, 6, 8, 10]);
    await net.advance(15_000);
    expect(offsets()).toEqual([0, 2, 4, 6, 8, 10, 25]);
    // An accepted hello from B's current instance: one immediate retransmission.
    await net.advance(t0 + 30_000 - net.clock.now());
    net.inject(A, B, wrapFake(B, A, hello(B, instBytes(b.mgr), a.mgr.instanceId)));
    await net.settle();
    expect(offsets()).toEqual([0, 2, 4, 6, 8, 10, 25, 30]);
    await net.advance(15_000);
    expect(offsets()).toEqual([0, 2, 4, 6, 8, 10, 25, 30, 45]);
    const all = offsets();
    for (let i = 1; i < all.length; i++) expect(all[i] - all[i - 1]).toBeGreaterThanOrEqual(2);
    a.mgr.onPeerLeft(B);
    await net.advance(60_000);
    expect(offsets().length).toBe(9);
  });
});

// ---------------------------------------------------------------------------
// T-21
// ---------------------------------------------------------------------------

describe('T-21 (REQ-21) the chain cap and credits', () => {
  it('stops at 32 messages in the chain, allows exactly one per accepted message, and resumes when the chain resets', async () => {
    const net = new Net();
    const a = net.client(A);
    a.fake.chain.set(B, 30);
    a.mgr.start();
    a.mgr.onJoined([B]);
    await net.advance(60_000);
    const sent = () => net.calls.filter(m => m.from === A && m.to === B);
    expect(sent().length).toBe(2); // hellos at 0 and 2 s, then capped
    expect(a.fake.chain.get(B)).toBe(32);
    expect(label(a.mgr, B).outbound).toBe('capped');
    // An accepted message from B grants one credit: exactly one more message (the CKM it asks for).
    net.inject(A, B, wrapFake(B, A, hello(B, testInst(0x21), null)));
    await net.advance(60_000);
    expect(sent().length).toBe(3);
    expect(readCall(sent()[2].wrappedKey).type).toBe('call_key');
    expect(a.fake.encryptCalls.filter(c => c.useCredit).length).toBe(1);
    // A message carrying a new ratchet key resets the chain.
    a.fake.chain.set(B, 0);
    await net.advance(3000);
    expect(sent().length).toBeGreaterThan(3);
  });
});

// ---------------------------------------------------------------------------
// T-33
// ---------------------------------------------------------------------------

describe('T-33 (REQ-33) instances and message rules', () => {
  const inst1 = testInst(0x31);
  const inst2 = testInst(0x32);

  it('the first instance of a member of R receives the current CKM without a new epoch', async () => {
    const { net, a } = await lone([B]);
    net.inject(A, B, wrapFake(B, A, hello(B, inst1, null)));
    await net.advance(3000);
    expect(a.mgr.snapshot().newestEpoch).toBe(0);
    const keys = net.callsBetween(A, B, 'call_key');
    expect(keys.length).toBeGreaterThan(0); // the first one, then retransmissions (no ACK)
    expect(keys.every(m => m.body.epoch === 0 && m.body.to_inst === b64(inst1))).toBe(true);
  });

  it('epoch rules: >, = (same key, different key), <, = after erasure, and = after KEY_MAX_AGE', async () => {
    const { net, a } = await lone([B]);
    const toA = a.mgr.instanceId;
    const send = async (epoch: number, key: Uint8Array) => {
      net.inject(A, B, wrapFake(B, A, ckm(B, inst1, toA, epoch, key)));
      await net.settle();
    };
    const acks = () => net.callsBetween(A, B, 'call_key_ack').map(m => m.body.epoch);
    await send(5, keyOf(5));
    expect(a.installed.map(i => i.epoch)).toEqual([5]);
    expect(acks()).toEqual([5]);
    const firstAt = a.mgr.retainedRecord(B)!.maxEpochFirstInstalledAt!;
    await send(5, keyOf(5)); // a duplicate: acknowledged, not reinstalled
    expect(a.installed.length).toBe(1);
    expect(acks()).toEqual([5, 5]);
    await send(5, keyOf(6)); // a different key for the same epoch: discarded
    expect(acks()).toEqual([5, 5]);
    await send(4, keyOf(4)); // older: discarded
    expect(acks()).toEqual([5, 5]);
    expect(a.mgr.retainedRecord(B)!.maxEpoch).toBe(5);
    // Erased by a departure: reinstalled with the first installation time.
    await net.advance(60_000);
    a.mgr.onPeerLeft(B);
    a.mgr.onPeerJoined(B);
    expect(a.mgr.retainedRecord(B)!.keys).toEqual([]);
    await send(5, keyOf(5));
    expect(a.installed.length).toBe(2);
    expect(acks()).toEqual([5, 5, 5]);
    expect(a.mgr.retainedRecord(B)!.maxEpochFirstInstalledAt).toBe(firstAt);
    // KEY_MAX_AGE after the first installation the key is erased, and a re-delivery is refused.
    await net.advance(firstAt + 11 * 60_000 - net.clock.now());
    expect(a.mgr.retainedRecord(B)!.keys).toEqual([]);
    a.mgr.onPeerLeft(B);
    a.mgr.onPeerJoined(B);
    await send(5, keyOf(5));
    expect(a.installed.length).toBe(2);
    expect(acks()).toEqual([5, 5, 5]);
  });

  it('a to_inst mismatch is discarded and answered with a hello; a new instance replaces the old one; the replaced one is refused', async () => {
    const { net, a } = await lone([B]);
    const toA = a.mgr.instanceId;
    net.inject(A, B, wrapFake(B, A, ckm(B, inst1, toA, 0, keyOf(1))));
    await net.advance(3000);
    expect(a.mgr.retainedRecord(B)!.keys.length).toBe(2);
    const hellosBefore = net.callsBetween(A, B, 'call_hello').length;
    net.inject(A, B, wrapFake(B, A, ckm(B, inst1, b64(testInst(0x99)), 1, keyOf(2))));
    await net.advance(3000);
    expect(a.mgr.retainedRecord(B)!.maxEpoch).toBe(0);
    expect(net.callsBetween(A, B, 'call_hello').length).toBe(hellosBefore + 1);
    // A new instance: old keys erased, pipeline reset.
    net.inject(A, B, wrapFake(B, A, hello(B, inst2, toA)));
    await net.settle();
    expect(a.resets).toContainEqual({ from: B, cause: 'new_instance' });
    expect(a.mgr.retainedRecord(B)!.currentInst).toBe(b64(inst2));
    expect(a.mgr.retainedRecord(B)!.replaced).toEqual([b64(inst1)]);
    expect(a.mgr.retainedRecord(B)!.keys).toEqual([]);
    net.inject(A, B, wrapFake(B, A, ckm(B, inst1, toA, 3, keyOf(3))));
    await net.settle();
    expect(a.mgr.retainedRecord(B)!.keys).toEqual([]);
    expect(a.mgr.retainedRecord(B)!.currentInst).toBe(b64(inst2));
  });

  it('a new instance of a member of R never receives the current epoch: a new epoch within 500 ms, without any peer event', async () => {
    const { net, a } = await lone([B]);
    const toA = a.mgr.instanceId;
    net.inject(A, B, wrapFake(B, A, hello(B, inst1, toA)));
    await net.advance(3000);
    expect(net.callsBetween(A, B, 'call_key').every(m => m.body.epoch === 0 && m.body.to_inst === b64(inst1))).toBe(true);
    const tReplace = net.clock.now();
    net.inject(A, B, wrapFake(B, A, hello(B, inst2, toA)));
    await net.advance(10_000);
    const toNew = net.callsBetween(A, B, 'call_key').filter(m => m.body.to_inst === b64(inst2));
    expect(toNew.length).toBeGreaterThan(0);
    expect(toNew.every(m => m.body.epoch === 1)).toBe(true);
    expect(net.callsBetween(A, B, 'call_key').filter(m => m.at >= tReplace).every(m => m.body.to_inst === b64(inst2))).toBe(true);
    expect(toNew[0].at - tReplace).toBeLessThanOrEqual(2500); // 500 ms coalescing, then the 2 s gap per recipient
    expect(a.mgr.snapshot().newestEpoch).toBe(1);
  });

  it('A2 (e), third case: a hello from the current instance after it acknowledged the current epoch gets the current CKM once more, once per (instance, epoch), within the rate limit and without a new epoch', async () => {
    const { net, a } = await lone([B]);
    const toA = a.mgr.instanceId;
    const keys = (epoch: number) => net.callsBetween(A, B, 'call_key').filter(m => m.body.epoch === epoch);
    net.inject(A, B, wrapFake(B, A, hello(B, inst1, toA)));
    await net.settle();
    net.inject(A, B, wrapFake(B, A, ackMsg(B, inst1, toA, 0)));
    await net.advance(10_000);
    expect(label(a.mgr, B).outbound).toBe('secure');
    const n = keys(0).length;
    expect(n).toBe(1);
    // B erased its keys (a forged leave and its own rejoin, same instance) and says hello again.
    const t = net.clock.now();
    net.inject(A, B, wrapFake(B, A, hello(B, inst1, toA)));
    await net.advance(3000);
    expect(keys(0).length).toBe(n + 1);
    const resent = keys(0)[n];
    expect(resent.body.to_inst).toBe(b64(inst1));
    expect(resent.at - t).toBeLessThanOrEqual(10);
    expect(a.mgr.snapshot().newestEpoch).toBe(0);
    // Once per (instance, epoch): further hellos, and B acknowledging the re-send, add nothing.
    net.inject(A, B, wrapFake(B, A, ackMsg(B, inst1, toA, 0)));
    for (let i = 0; i < 3; i++) {
      net.inject(A, B, wrapFake(B, A, hello(B, inst1, toA)));
      await net.advance(5000);
    }
    expect(keys(0).length).toBe(n + 1);
    expect(a.mgr.snapshot().newestEpoch).toBe(0);
    // The next epoch earns its own re-send, also when the hello comes within 2 s of a CKM (REQ-20's rate limit).
    await net.advance(10 * 60_000 - (net.clock.now() - t) + 5000);
    expect(a.mgr.snapshot().newestEpoch).toBe(1);
    net.inject(A, B, wrapFake(B, A, ackMsg(B, inst1, toA, 1)));
    await net.settle();
    const m1 = keys(1).length;
    const lastCkmAt = keys(1)[m1 - 1].at;
    net.inject(A, B, wrapFake(B, A, hello(B, inst1, toA)));
    await net.advance(5000);
    expect(keys(1).length).toBe(m1 + 1);
    expect(keys(1)[m1].at - lastCkmAt).toBeGreaterThanOrEqual(2000);
    net.inject(A, B, wrapFake(B, A, hello(B, inst1, toA)));
    await net.advance(5000);
    expect(keys(1).length).toBe(m1 + 1);
    // A replaced instance is unchanged: it gets a new epoch, never a re-send of the current one.
    net.inject(A, B, wrapFake(B, A, hello(B, inst2, toA)));
    await net.advance(3000);
    expect(net.callsBetween(A, B, 'call_key').filter(m => m.body.to_inst === b64(inst2)).every(m => m.body.epoch === 2)).toBe(true);
    expect(keys(1).length).toBe(m1 + 1);
  });

  it('ACK rules: only from a member of the current R, for an epoch not above the current one', async () => {
    const { net, a } = await lone([B, C]);
    const toA = a.mgr.instanceId;
    net.inject(A, B, wrapFake(B, A, hello(B, inst1, toA)));
    await net.advance(3000);
    net.inject(A, B, wrapFake(B, A, ackMsg(B, inst1, toA, 7)));
    await net.settle();
    expect(label(a.mgr, B).outbound).toBe('keying');
    net.inject(A, B, wrapFake(B, A, ackMsg(B, inst1, toA, 0)));
    await net.settle();
    expect(label(a.mgr, B).outbound).toBe('secure');
    // D enters V; before the coalesced rotation it is not in R: its ACK is ignored.
    a.mgr.onPeerJoined(D);
    net.inject(A, D, wrapFake(D, A, hello(D, testInst(0x44), toA)));
    net.inject(A, D, wrapFake(D, A, ackMsg(D, testInst(0x44), toA, 0)));
    await net.settle();
    expect(label(a.mgr, D).outbound).toBe('keying');
  });
});

// ---------------------------------------------------------------------------
// T-36
// ---------------------------------------------------------------------------

describe('T-36 (REQ-36) hellos', () => {
  it('go at instance start only to eligible members of V, are retransmitted at 2, 4 and 8 s and then every 60 s, and stop on confirmation', async () => {
    const net = new Net();
    const a = net.client(A);
    a.fake.membershipOf.set(C, 'not_member');
    a.mgr.start();
    a.mgr.onJoined([B, C]);
    const t0 = net.clock.now();
    await net.advance(130_000);
    expect(net.callsBetween(A, C)).toEqual([]);
    const times = () => net.callsBetween(A, B, 'call_hello').map(m => (m.at - t0) / 1000);
    expect(times()).toEqual([0, 2, 4, 8, 68, 128]);
    for (const m of net.callsBetween(A, B, 'call_hello')) expect(m.body.to_inst).toBeNull();
    net.inject(A, B, wrapFake(B, A, hello(B, testInst(0x36), a.mgr.instanceId)));
    await net.advance(400_000);
    expect(times()).toEqual([0, 2, 4, 8, 68, 128]);
  });

  it('a message from an unconfirmed peer gets a reply: a CKM for a member of R, a hello after a stale ACK; at most one hello per 2 s; no key material', async () => {
    const { random, secrets } = capturingRandom();
    const { net, a } = await lone([B], { random });
    const toA = a.mgr.instanceId;
    const instB = testInst(0x37);
    // B's hello names A's instance (B confirms A): A answers with its CKM, and stops retransmitting hellos.
    net.inject(A, B, wrapFake(B, A, hello(B, instB, toA)));
    await net.settle();
    expect(net.callsBetween(A, B, 'call_key').length).toBe(1);
    await net.advance(10_000);
    const helloCount = net.callsBetween(A, B, 'call_hello').length;
    // A stale ACK (to_inst is not A's instance) is answered with one hello.
    net.inject(A, B, wrapFake(B, A, ackMsg(B, instB, b64(testInst(0x01)), 0)));
    await net.advance(10_000);
    const hellos = net.callsBetween(A, B, 'call_hello');
    expect(hellos.length).toBe(helloCount + 1);
    expect(hellos[hellos.length - 1].body.to_inst).toBe(b64(instB));
    for (let i = 1; i < hellos.length; i++) expect(hellos[i].at - hellos[i - 1].at).toBeGreaterThanOrEqual(2000);
    for (const h of hellos) {
      expect(h.body).not.toHaveProperty('key');
      for (const s of secrets) expect(JSON.stringify(h.body)).not.toContain(b64(s));
    }
  });
});

// ---------------------------------------------------------------------------
// §8.1 and §8.2 states
// ---------------------------------------------------------------------------

describe('§8 states (REQ-31)', () => {
  it('a silent participant: Connecting for 12 s, then Can\'t connect securely', async () => {
    const { net, a } = await lone([B]);
    expect(label(a.mgr, B).label).toBe('connecting');
    expect(a.mgr.snapshot().indicator).toBe('connecting');
    await net.advance(11_999);
    expect(label(a.mgr, B).label).toBe('connecting');
    await net.advance(1);
    expect(label(a.mgr, B).label).toBe('cant_connect');
    expect(label(a.mgr, B).inbound).toBe('waiting');
    expect(PARTICIPANT_LABEL_TEXT.cant_connect).toBe("Can't connect securely");
  });

  it('both directions keyed: Secure; ACK without key: Can\'t hear them; key without ACK: They can\'t hear you', async () => {
    const net = new Net();
    const a = net.client(A);
    net.client(B);
    net.client(C);
    // B's CKMs to A are dropped: A never hears B.
    net.callFilter = m => (m.from === B && m.to === A && readCall(m.wrappedKey).type === 'call_key' ? 'drop' : m.from === C && m.to === A && readCall(m.wrappedKey).type === 'call_key_ack' ? 'drop' : 'deliver');
    await net.join(A, B, C);
    await net.advance(13_000);
    expect(label(a.mgr, B).outbound).toBe('secure');
    expect(label(a.mgr, B).label).toBe('cant_hear_them');
    expect(label(a.mgr, C).inbound).toBe('keyed');
    expect(label(a.mgr, C).label).toBe('they_cant_hear_you');
    net.callFilter = () => 'deliver';
    await net.advance(30_000);
    expect(label(a.mgr, B).label).toBe('secure');
    expect(label(a.mgr, C).label).toBe('secure');
    expect(a.mgr.snapshot().indicator).toBe('e2ee_not_verified');
    expect(label(a.mgr, B).recipient).toBe(true);
  });

  it('stays Secure across a rotation while the previous epoch was acknowledged less than 6 s ago', async () => {
    const net = new Net();
    const a = net.client(A);
    net.client(B);
    await net.join(A, B);
    await net.advance(13_000);
    expect(label(a.mgr, B).label).toBe('secure');
    net.callFilter = m => (m.to === A && readCall(m.wrappedKey).type === 'call_key_ack' ? 'drop' : 'deliver');
    a.mgr.onPeerJoined(C); // a rotation whose ACK from B is lost
    await net.advance(1000);
    expect(a.mgr.snapshot().newestEpoch).toBe(1);
    expect(label(a.mgr, B).outbound).toBe('secure');
    await net.advance(6000);
    expect(label(a.mgr, B).outbound).toBe('keying');
  });

  it('notes: session problem (cleared by the next success), outdated app (cleared by an accepted message), older app in P2P mode', async () => {
    const { net, a } = await lone([B]);
    const toA = a.mgr.instanceId;
    const instB = testInst(0x61);
    const bad = wrapFake(B, A, hello(B, instB, toA));
    a.fake.failing.add(JSON.parse(new TextDecoder().decode(decodeWireBase64(bad.slice(5))!)).n);
    net.inject(A, B, bad);
    await net.settle();
    expect(label(a.mgr, B).notes.sessionProblem).toBe(true);
    // A legacy raw key: evidence only.
    net.inject(A, B, b64(keyOf(9)));
    await net.settle();
    expect(label(a.mgr, B).notes.outdatedApp).toBe(true);
    expect(a.mgr.retainedRecord(B)!.keys).toEqual([]);
    expect(a.mgr.currentRecipients()).toEqual([B]); // evidence never changes eligibility or R
    a.mgr.noteRelayMode('p2p');
    expect(label(a.mgr, B).notes.olderAppP2p).toBe(true);
    net.inject(A, B, wrapFake(B, A, hello(B, instB, toA)));
    await net.settle();
    const n = label(a.mgr, B).notes;
    expect(n).toEqual({ sessionProblem: false, outdatedApp: false, olderAppP2p: false, audioUnverifiable: false });
    a.mgr.noteRelayMode('relay');
    a.mgr.noteLegacyVoicePacket(B, CH);
    expect(label(a.mgr, B).notes.outdatedApp).toBe(true);
  });

  it('Secure voice unavailable while the E2EE manager is not ready, and start() refuses (REQ-23)', async () => {
    const net = new Net();
    const a = net.client(A);
    a.fake.ready = false;
    expect(a.mgr.start()).toBe(false);
    a.mgr.onJoined([B]);
    expect(a.mgr.snapshot().indicator).toBe('unavailable');
    await net.settle();
  });

  it('an identity change and a membership fetch in flight have their own labels', async () => {
    const { a } = await lone([B, C]);
    a.fake.ineligible.set(B, { eligible: false, reason: 'identity_changed' });
    a.fake.membershipOf.set(C, 'unknown');
    expect(label(a.mgr, B).label).toBe('identity_changed');
    expect(label(a.mgr, C).label).toBe('checking_membership');
  });
});

// ---------------------------------------------------------------------------
// T-8 (final rule), with fakes of the SPEC-05 and SPEC-06 interfaces
// ---------------------------------------------------------------------------

describe('T-8 (REQ-8) the final rule, manager side', () => {
  const ISK = new Uint8Array(32).fill(0x08);
  const HEAD = { seq: 4, hash: 'aGFzaA==', prev: 'cHJldg==', rcpt: 'cmNwdA==' };

  function finalClient(net: Net, id: string, others: string[]) {
    const c = net.client(id);
    c.fake.ruleValue = 'final';
    c.fake.head = HEAD;
    c.fake.peerIsk = ISK;
    for (const o of others) c.fake.rosterIsks.set(o, ISK);
    return c;
  }

  it('hellos and CKMs carry gh, ACKs do not; a received gh is offered to SPEC-06; all Secure and verified gives "verified"', async () => {
    const net = new Net();
    const a = finalClient(net, A, [B]);
    const b = finalClient(net, B, [A]);
    await net.join(A, B);
    await net.advance(3000);
    for (const type of ['call_hello', 'call_key']) {
      const ms = net.callsBetween(A, B, type);
      expect(ms.length).toBeGreaterThan(0);
      for (const m of ms) expect(m.body.gh).toEqual(HEAD);
    }
    for (const m of net.callsBetween(A, B, 'call_key_ack')) expect(m.body).not.toHaveProperty('gh');
    expect(b.fake.offeredHeads.some(o => o.from === A && o.head.seq === 4)).toBe(true);
    expect(a.mgr.snapshot().indicator).toBe('e2ee_not_verified');
    a.fake.verified.add(B);
    expect(a.mgr.snapshot().indicator).toBe('e2ee_verified');
  });

  it('a call message from a session whose ISK is not roster(S).isk is discarded', async () => {
    const net = new Net();
    const a = finalClient(net, A, [B]);
    a.fake.rosterIsks.set(B, new Uint8Array(32).fill(0x09));
    a.mgr.start();
    a.mgr.onJoined([B]);
    await net.settle();
    net.inject(A, B, wrapFake(B, A, ckm(B, testInst(0x81), a.mgr.instanceId, 0, keyOf(1))));
    await net.settle();
    expect(a.mgr.retainedRecord(B)!.keys).toEqual([]);
    expect(a.mgr.retainedRecord(B)!.currentInst).toBeNull();
  });

  it('while the audience is withheld, a new epoch\'s R contains nobody who was not in the previous R', async () => {
    const net = new Net();
    const a = finalClient(net, A, [B, C]);
    finalClient(net, B, [A, C]);
    finalClient(net, C, [A, B]);
    await net.join(A, B);
    await net.advance(3000);
    a.fake.withheld = true;
    await net.joinLate(C, [A, B]);
    await net.advance(3000);
    expect(a.mgr.snapshot().newestEpoch).toBe(1);
    expect(a.mgr.currentRecipients()).toEqual([B]);
    expect(net.callsBetween(A, C, 'call_key')).toEqual([]);
    a.fake.withheld = false;
    a.fake.emitEligibility();
    a.mgr.onPeerLeft(C);
    a.mgr.onPeerJoined(C);
    await net.advance(3000);
    expect(a.mgr.currentRecipients().sort()).toEqual([B, C].sort());
  });
});
