// @vitest-environment node
/**
 * SPEC-03 §6.10 bridge implementation (`voice/callKeyBridgeImpl.ts`, §11.2
 * step 6) over real `E2EEManager` instances wired to each other through the
 * in-memory relay of `callKeys.testkit.ts`:
 *
 * - the interim membership rule, bridge side (T-9): fetch failures, a
 *   channel not listed under N, the cache per node, immediate exclusion on
 *   `sender_key_rotation_required` (rotation in the same turn, REQ-16 (c)),
 *   coalescing of event and on-demand fetches to one per 5 s per node, one
 *   more fetch for a trigger that arrives during a fetch, and a call-start
 *   fetch that a list cached by an earlier call cannot stand in for;
 * - first contact (T-10, REQ-10): the lower id initiates once and its first
 *   message carries the hello; the higher id holds until the session exists;
 * - in-order acceptance (T-32, REQ-32): a call message decrypted with a
 *   skipped key is discarded;
 * - the bridge contract: chain limit, credits, error mapping, session events.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { decodeWireBase64, encodeBase64 } from '../attachments/base64';
import { classifyFor, strictToPlain } from '../e2ee/plaintext';
import { E2EEManager, type PreKeyBundle } from '../e2ee';
import { CallKeyBridgeImpl } from './callKeyBridgeImpl';
import { CALL_CHAIN_LIMIT } from './callKeyBridge';
import { CALL_ENVELOPE_PREFIX } from './callKeys';
import { A, B, C, CH, CH2, D, NODE, NODE2, Net, ManualClock, b64, callPlaintext, testInst, type Client } from './callKeys.testkit';

function memoryStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: k => m.get(k) ?? null,
    key: i => [...m.keys()][i] ?? null,
    removeItem: k => void m.delete(k),
    setItem: (k, v) => void m.set(k, String(v)),
  };
}

beforeEach(() => {
  vi.stubGlobal('localStorage', memoryStorage());
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

interface World {
  readonly clock: ManualClock;
  readonly managers: Map<string, E2EEManager>;
  readonly bundleFetches: Map<string, string[]>;
  members: Map<string, string[]>;
  channels: Map<string, string[]>;
  failFetch: boolean;
  /** Clients whose fetches fail. */
  readonly failFor: Set<string>;
  fetchCount: number;
}

function world(clock: ManualClock = new ManualClock()): World {
  return {
    clock,
    managers: new Map(),
    bundleFetches: new Map(),
    members: new Map([[NODE, [A, B, C, D]], [NODE2, [A]]]),
    channels: new Map([[NODE, [CH, CH2]], [NODE2, ['00000000-0000-4000-8000-0000000000c9']]]),
    failFetch: false,
    failFor: new Set(),
    fetchCount: 0,
  };
}

function bridgeFor(w: World, id: string, e2ee: E2EEManager | null = null): CallKeyBridgeImpl {
  let mgr = e2ee;
  if (!mgr) {
    mgr = new E2EEManager();
    mgr.initialize();
  }
  w.managers.set(id, mgr);
  w.bundleFetches.set(id, []);
  const m = mgr;
  return new CallKeyBridgeImpl({
    e2ee: () => m,
    selfId: () => id,
    fetchBundle: async peer => {
      w.bundleFetches.get(id)!.push(peer);
      const pm = w.managers.get(peer);
      if (!pm) return undefined;
      const b = pm.getPreKeyBundle();
      return { identityKey: b.identityKey, signedPrekey: b.signedPrekey } satisfies PreKeyBundle;
    },
    fetchMembers: async node => {
      w.fetchCount++;
      if (w.failFetch || w.failFor.has(id)) throw new Error('unavailable');
      return w.members.get(node) ?? [];
    },
    fetchChannels: async node => {
      if (w.failFetch || w.failFor.has(id)) throw new Error('unavailable');
      return w.channels.get(node) ?? [];
    },
    clock: w.clock,
  });
}

/**
 * Real E2EE clients on one in-memory relay. As in the app (§6.6 step 1),
 * each fetches N's lists at call start before `voice_channel_joined`.
 */
async function realCall(ids: string[], prepare?: (net: Net) => void) {
  const net = new Net();
  const w = world(net.clock);
  const clients = new Map<string, Client>();
  for (const id of ids) clients.set(id, net.client(id, { bridge: bridgeFor(w, id) }));
  prepare?.(net);
  for (const c of clients.values()) c.mgr.start();
  await net.settle();
  await net.join(...ids);
  return { net, w, clients };
}

const flush = () => new Promise<void>(r => setImmediate(r));

function envelopeOf(wk: string): { t: string } {
  return JSON.parse(new TextDecoder().decode(decodeWireBase64(wk.slice(CALL_ENVELOPE_PREFIX.length))!)) as { t: string };
}

// ---------------------------------------------------------------------------
// T-9, bridge side
// ---------------------------------------------------------------------------

describe('T-9 (REQ-9) the interim membership rule, bridge side', () => {
  it('nobody is eligible before the lists are fetched, when the fetch fails, or when C is not listed under N', async () => {
    const w = world();
    const br = bridgeFor(w, A);
    expect(br.eligibility(NODE, CH, B)).toEqual({ eligible: false, reason: 'not_member' });
    w.failFetch = true;
    await expect(br.refreshMembership(NODE, 'call_start')).rejects.toThrow();
    expect(br.eligibility(NODE, CH, B).eligible).toBe(false);
    expect(br.membership(NODE, CH, B)).toBe('not_member');
    w.failFetch = false;
    await br.refreshMembership(NODE, 'call_start');
    expect(br.eligibility(NODE, CH, B)).toEqual({ eligible: true });
    const other = '00000000-0000-4000-8000-0000000000c7';
    expect(br.eligibility(NODE, other, B)).toEqual({ eligible: false, reason: 'channel_not_in_node' });
    expect(br.membership(NODE, other, B)).toBe('not_member');
    expect(br.eligibility(NODE, CH, A)).toEqual({ eligible: false, reason: 'not_in_view' });
  });

  it('the member list stays N\'s when another node is fetched (the user selected another node)', async () => {
    const w = world();
    const br = bridgeFor(w, A);
    await br.refreshMembership(NODE, 'call_start');
    await br.refreshMembership(NODE2, 'call_start');
    expect(br.membership(NODE, CH, B)).toBe('member');
    expect(br.membership(NODE2, '00000000-0000-4000-8000-0000000000c9', B)).not.toBe('member');
  });

  it('sender_key_rotation_required for a text channel of N excludes the user at once (the manager rotates in the same turn), until a fetch started after the event lists the user again', async () => {
    const { net, w, clients } = await realCall([A, B, C]);
    await net.advance(5000);
    const a = clients.get(A)!;
    const br = a.bridge as CallKeyBridgeImpl;
    expect(a.mgr.currentRecipients().sort()).toEqual([B, C].sort());
    const g = a.mgr.snapshot().newestEpoch!;
    br.noteRotationRequired(CH2.toUpperCase(), C); // another channel of N; ids compared in lowercase
    expect(br.eligibility(NODE, CH, C)).toEqual({ eligible: false, reason: 'not_member' });
    expect(a.mgr.snapshot().newestEpoch).toBe(g + 1); // without yielding
    expect(a.mgr.currentRecipients()).toEqual([B]);
    // The re-fetch it triggered started after the event and lists C: C is eligible again.
    await net.advance(6000);
    expect(br.eligibility(NODE, CH, C)).toEqual({ eligible: true });
    expect(w.fetchCount).toBeGreaterThan(0);
  });

  it('20 rotation events and 5 member_joined within 1 s cause at most one fetch per 5 s for the node, and each named user is excluded at once', async () => {
    const w = world();
    const br = bridgeFor(w, A);
    await br.refreshMembership(NODE, 'call_start');
    const changes: string[] = [];
    br.onEligibilityChange(n => changes.push(n));
    await w.clock.advance(10_000);
    const start = w.fetchCount;
    const t0 = w.clock.now();
    const fetchTimes: number[] = [];
    const users = [B, C, D];
    for (let i = 0; i < 25; i++) {
      if (i % 5 === 4) br.noteMemberJoined(NODE);
      else {
        const u = users[i % 3];
        br.noteRotationRequired(CH, u);
        expect(br.membership(NODE, CH, u)).toBe('not_member'); // at once
      }
      const before = w.fetchCount;
      await w.clock.advance(40);
      if (w.fetchCount > before) fetchTimes.push(w.clock.now() - t0);
    }
    await w.clock.advance(20_000);
    expect(w.fetchCount - start).toBeLessThanOrEqual(2);
    expect(changes.length).toBeGreaterThanOrEqual(20);
    // Excluded users stay excluded until a fetch that started after their event lists them.
    for (const u of users) expect(br.membership(NODE, CH, u)).toBe('member');
    expect(fetchTimes.length).toBeLessThanOrEqual(1);
  });

  it('a member of V missing from the cached list triggers one re-fetch: unknown while it is pending, then member or not_member', async () => {
    const w = world();
    const br = bridgeFor(w, A);
    await br.refreshMembership(NODE, 'call_start');
    const E = '00000000-0000-4000-8000-0000000000a5';
    await w.clock.advance(10_000);
    const n0 = w.fetchCount;
    expect(br.membership(NODE, CH, E)).toBe('unknown');
    await w.clock.advance(10);
    expect(w.fetchCount).toBe(n0 + 1);
    expect(br.membership(NODE, CH, E)).toBe('not_member');
    expect(br.membership(NODE, CH, E)).toBe('not_member');
    await w.clock.advance(30_000);
    expect(w.fetchCount).toBe(n0 + 1); // not again for a user already checked
    // A member_joined hint: E is listed now.
    w.members.set(NODE, [A, B, C, D, E]);
    br.noteMemberJoined(NODE);
    await w.clock.advance(10);
    expect(br.membership(NODE, CH, E)).toBe('member');
  });

  it('an event or a missing member during a running fetch gets one more fetch, started after it and coalesced to one per 5 s', async () => {
    const w = world();
    const br = bridgeFor(w, A);
    await br.refreshMembership(NODE, 'call_start');
    await w.clock.advance(10_000);
    const n0 = w.fetchCount;
    const running = br.refreshMembership(NODE, 'timer');
    expect(w.fetchCount).toBe(n0 + 1);
    br.noteRotationRequired(CH, B);
    expect(br.membership(NODE, CH, B)).toBe('not_member');
    await running; // it lists B, but it started before the event
    expect(br.membership(NODE, CH, B)).toBe('not_member');
    await w.clock.advance(4900);
    await flush();
    expect(w.fetchCount).toBe(n0 + 1);
    await w.clock.advance(100);
    await flush();
    expect(w.fetchCount).toBe(n0 + 2);
    expect(br.membership(NODE, CH, B)).toBe('member');
    // A member_joined hint during a running fetch, likewise.
    await w.clock.advance(10_000);
    const E = '00000000-0000-4000-8000-0000000000a5';
    const again = br.refreshMembership(NODE, 'timer');
    w.members.set(NODE, [A, B, C, D, E]);
    br.noteMemberJoined(NODE);
    await again;
    await w.clock.advance(5000);
    await flush();
    expect(w.fetchCount).toBe(n0 + 4);
    expect(br.membership(NODE, CH, E)).toBe('member');
    await w.clock.advance(30_000);
    await flush();
    expect(w.fetchCount).toBe(n0 + 4); // and no more
  });

  it('the call-start fetch is authoritative: on a bridge that served an earlier call, nobody is eligible while the next start fetch runs or after it fails, no CKM goes out and no envelope is decrypted', async () => {
    const { net, w, clients } = await realCall([A, B]);
    await net.advance(5000);
    const a = clients.get(A)!;
    const b = clients.get(B)!;
    const br = a.bridge as CallKeyBridgeImpl;
    expect(br.eligibility(NODE, CH, B)).toEqual({ eligible: true });
    expect(a.mgr.snapshot().participants[0].label).toBe('secure');
    // B is removed from N, and A never sees the event. A's fetches fail from now on.
    w.members.set(NODE, [A, C, D]);
    w.failFor.add(A);
    const decrypts: string[] = [];
    const dec = br.decryptFrom.bind(br);
    br.decryptFrom = (peer, envelope) => {
      decrypts.push(peer);
      return dec(peer, envelope);
    };
    // An envelope B sealed for A, over their existing session.
    const sealed = await b.bridge.encryptFor(A, callPlaintext({ type: 'call_hello', v: 1, from: B, ch: CH, inst: b64(testInst(9)), to_inst: null }), true);
    if (!sealed.ok) throw new Error('encrypt');
    const wire = CALL_ENVELOPE_PREFIX + encodeBase64(new TextEncoder().encode(sealed.envelope));
    net.newCall(a);
    net.newCall(b);
    const since = net.calls.length;
    a.mgr.start(); // the start fetch is running: the first call's list answers nothing
    expect(br.membership(NODE, CH, B)).toBe('unknown');
    expect(br.eligibility(NODE, CH, B)).toEqual({ eligible: false, reason: 'membership_unknown' });
    a.mgr.onJoined([B]);
    expect(a.mgr.currentRecipients()).toEqual([]);
    expect(a.mgr.snapshot().participants[0].label).toBe('checking_membership');
    expect(a.mgr.snapshot().indicator).toBe('checking_membership');
    a.mgr.handleKeyExchange({ from: B, channel_id: CH, wrapped_key: wire }); // held, not decrypted
    b.mgr.start();
    b.mgr.onJoined([A]);
    await net.advance(30_000); // the start fetch and every retry on the backoff fail
    expect(br.membership(NODE, CH, B)).toBe('not_member');
    expect(a.mgr.snapshot().indicator).toBe('cant_verify_members');
    expect(net.calls.slice(since).filter(m => m.from === B && m.to === A).length).toBeGreaterThan(0);
    expect(decrypts).toEqual([]);
    expect(net.calls.slice(since).filter(m => m.from === A)).toEqual([]);
    // Once a fetch succeeds, the fresh list decides: B is no member.
    w.failFor.delete(A);
    await net.advance(60_000);
    expect(br.membership(NODE, CH, B)).toBe('not_member');
    expect(a.mgr.currentRecipients()).toEqual([]);
    expect(decrypts).toEqual([]);
    expect(net.calls.slice(since).filter(m => m.from === A)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// T-10
// ---------------------------------------------------------------------------

describe('T-10 (REQ-10) first contact', () => {
  it('self < P without a session: exactly one X3DH initiation, and it carries the hello', async () => {
    const { net, w, clients } = await realCall([A, B]);
    await net.advance(5000);
    expect(w.bundleFetches.get(A)).toEqual([B]);
    expect(w.bundleFetches.get(B)).toEqual([]);
    const fromA = net.calls.filter(m => m.from === A && m.to === B);
    const fromB = net.calls.filter(m => m.from === B && m.to === A);
    expect(envelopeOf(fromA[0].wrappedKey).t).toBe('x3dh');
    expect(fromB.every(m => envelopeOf(m.wrappedKey).t === 'dr')).toBe(true);
    // B recorded A's instance from that first message: the hello.
    expect(clients.get(B)!.mgr.retainedRecord(A)!.currentInst).toBe(clients.get(A)!.mgr.instanceId);
    for (const [x, y] of [[A, B], [B, A]]) {
      expect(clients.get(x)!.mgr.snapshot().participants.find(p => p.userId === y)!.label).toBe('secure');
    }
  });

  it('self > P: the higher id holds its call messages until P\'s first Double Ratchet message establishes the session', async () => {
    const { net, clients } = await realCall([A, B], n => {
      n.callFilter = m => (m.from === A ? 'withhold' : 'deliver');
    });
    await net.advance(10_000);
    expect(net.calls.filter(m => m.from === B)).toEqual([]);
    const b = clients.get(B)!;
    expect(b.mgr.snapshot().participants[0].outbound).toBe('session');
    net.callFilter = () => 'deliver';
    for (const m of net.withheld.splice(0)) net.deliverCall(m);
    await net.advance(5000);
    const fromB = net.calls.filter(m => m.from === B && m.to === A);
    expect(fromB.length).toBeGreaterThan(0);
    expect(fromB.every(m => envelopeOf(m.wrappedKey).t === 'dr')).toBe(true);
    expect(b.mgr.snapshot().participants[0].label).toBe('secure');
    expect(clients.get(A)!.mgr.snapshot().participants[0].label).toBe('secure');
  });
});

// ---------------------------------------------------------------------------
// T-32
// ---------------------------------------------------------------------------

describe('T-32 (REQ-32) fresh, in-order call messages', () => {
  it('a withheld CKM delivered after its retransmission decrypts with a skipped key and is discarded: no install, no ACK, no session-problem note', async () => {
    const types = new Map<string, string>();
    let withheld: string | null = null;
    const { net, clients } = await realCall([A, B], n => {
      const a = n.clients.get(A)!;
      const enc = a.bridge.encryptFor.bind(a.bridge);
      a.bridge.encryptFor = async (peer, plaintext, useCredit) => {
        const r = await enc(peer, plaintext, useCredit);
        const c = classifyFor('voice', plaintext);
        if (r.ok && c && c.class === 'control' && c.valid) types.set(r.envelope, String((strictToPlain(c.body) as { type: string }).type));
        return r;
      };
      n.callFilter = m => {
        if (m.from !== A || withheld !== null) return 'deliver';
        const env = new TextDecoder().decode(decodeWireBase64(m.wrappedKey.slice(CALL_ENVELOPE_PREFIX.length))!);
        if (types.get(env) !== 'call_key') return 'deliver';
        withheld = m.wrappedKey;
        return 'withhold';
      };
    });
    await net.advance(5000);
    const b = clients.get(B)!;
    expect(withheld).not.toBeNull();
    expect(b.installed.filter(i => i.from === A).length).toBe(1); // from the retransmission
    const installs = b.installed.length;
    const sentByB = net.calls.filter(m => m.from === B).length;
    for (const m of net.withheld.splice(0)) net.deliverCall(m);
    await net.settle();
    expect(b.installed.length).toBe(installs);
    expect(net.calls.filter(m => m.from === B).length).toBe(sentByB);
    expect(b.mgr.snapshot().participants[0].notes.sessionProblem).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The bridge contract (§6.10)
// ---------------------------------------------------------------------------

describe('§6.10 bridge contract', () => {
  it('encryptFor: await_peer for the higher id, bundle_unavailable without a bundle, chain_limit at 32 unless a credit is used; one session event per initiation', async () => {
    const w = world();
    const a = bridgeFor(w, A);
    const b = bridgeFor(w, B);
    expect(await b.encryptFor(A, 'x', false)).toEqual({ ok: false, error: 'await_peer' });
    expect(w.bundleFetches.get(B)).toEqual([]);
    const lonely = bridgeFor(world(), A);
    expect(await lonely.encryptFor(D, 'x', false)).toEqual({ ok: false, error: 'bundle_unavailable' });
    const usable: string[] = [];
    a.onSessionUsable(p => usable.push(p));
    const r = await a.encryptFor(B, 'hello', false);
    expect(r.ok).toBe(true);
    await Promise.resolve();
    expect(usable).toEqual([B]);
    for (let i = 1; i < CALL_CHAIN_LIMIT; i++) expect((await a.encryptFor(B, 'm', false)).ok).toBe(true);
    expect(a.sendingChainLength(B)).toBe(CALL_CHAIN_LIMIT);
    expect(await a.encryptFor(B, 'm', false)).toEqual({ ok: false, error: 'chain_limit' });
    expect((await a.encryptFor(B, 'm', true)).ok).toBe(true);
    expect(w.bundleFetches.get(A)).toEqual([B]);
  });

  it('decryptFrom: plaintext with usedSkippedKey and the session facts; no_session, decrypt_failed and store_locked otherwise; a responder session announces itself', async () => {
    const w = world();
    const a = bridgeFor(w, A);
    const b = bridgeFor(w, B);
    const usable: string[] = [];
    b.onSessionUsable(p => usable.push(p));
    const e1 = await a.encryptFor(B, 'one', false);
    const e2 = await a.encryptFor(B, 'two', false);
    if (!e1.ok || !e2.ok) throw new Error('encrypt');
    const r2 = await b.decryptFrom(A, e2.envelope);
    expect(r2).toMatchObject({ ok: true, plaintext: 'two', usedSkippedKey: false, sessionVersion: 'legacy', peer: { isk: null } });
    await Promise.resolve();
    expect(usable).toEqual([A]);
    const r1 = await b.decryptFrom(A, e1.envelope);
    expect(r1).toMatchObject({ ok: true, plaintext: 'one', usedSkippedKey: true });
    expect(await b.decryptFrom(A, '{"t":"dr","ct":"garbage"}')).toEqual({ ok: false, error: 'decrypt_failed' });
    const c = bridgeFor(w, C);
    expect(await c.decryptFrom(A, '{"t":"dr","ct":"{}"}')).toEqual({ ok: false, error: 'no_session' });
    const locked = new CallKeyBridgeImpl({
      e2ee: () => null,
      selfId: () => A,
      fetchBundle: async () => undefined,
      fetchMembers: async () => [],
      fetchChannels: async () => [],
    });
    expect(locked.isReady()).toBe(false);
    expect(await locked.decryptFrom(B, e1.envelope)).toEqual({ ok: false, error: 'store_locked' });
    expect(await locked.encryptFor(B, 'x', false)).toEqual({ ok: false, error: 'store_locked' });
  });

  it('interim rule: not verified, no pins, no roster, no head; the short id is the first 8 hex digits', () => {
    const br = bridgeFor(world(), A);
    expect(br.rule()).toBe('interim');
    expect(br.pinnedSessionsOnly()).toBe(false);
    expect(br.identityLabel('ABCDEF01-2345-4678-89ab-cdef01234567')).toEqual({ shortId: 'abcdef01', verified: false });
    expect(br.governanceHead()).toBeNull();
    expect(br.pinnedIsk()).toBeNull();
    expect(br.rosterIsk()).toBeNull();
    expect(br.audienceWithheld()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// T-1 (REQ-1) and T-27 (REQ-27) over real sessions
// ---------------------------------------------------------------------------

describe('T-1 (REQ-1) and T-27 (REQ-27) with real Double Ratchet sessions', () => {
  it('no epoch secret leaves except inside a call_key for one target; every call message is targeted and acv1:; key buffers end zero-filled', async () => {
    const hkdfInputs: Uint8Array[] = [];
    const importKey = crypto.subtle.importKey.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, 'importKey').mockImplementation(((format: string, data: BufferSource, alg: AlgorithmIdentifier, ext: boolean, usages: KeyUsage[]) => {
      if (alg === 'HKDF' && data instanceof Uint8Array) hkdfInputs.push(data);
      return importKey(format as 'raw', data, alg, ext, usages);
    }) as typeof crypto.subtle.importKey);
    const secrets: Uint8Array[] = [];
    const random = (n: number) => {
      const b = crypto.getRandomValues(new Uint8Array(n));
      if (n === 32) secrets.push(Uint8Array.from(b));
      return b;
    };
    const net = new Net();
    const w = world(net.clock);
    for (const id of [A, B, C]) net.client(id, { bridge: bridgeFor(w, id), random }).mgr.start();
    await net.settle();
    await net.join(A, B);
    await net.advance(3000);
    await net.joinLate(C, [A, B]);
    await net.advance(5000);
    for (let i = 0; i < 20; i++) net.clients.get(A)!.mgr.sendAudio(Uint8Array.of(0, i, 1, 2));
    await net.settle();
    net.clients.get(A)!.mgr.onPeerLeft(B);
    net.clients.get(C)!.mgr.onPeerLeft(B);
    net.clients.get(B)!.mgr.end();
    await net.advance(10 * 60_000 + 5000);
    expect(secrets.length).toBeGreaterThan(6);
    const forms = (s: Uint8Array) => {
      const b64 = btoa(String.fromCharCode(...s));
      return [b64, b64.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'), Array.from(s, x => x.toString(16).padStart(2, '0')).join('')];
    };
    const wire = net.calls.map(m => m.wrappedKey).join('\n');
    for (const m of net.calls) {
      expect(m.wrappedKey.startsWith(CALL_ENVELOPE_PREFIX)).toBe(true);
      expect(typeof m.to).toBe('string');
      expect(m.to).not.toBe(m.from);
    }
    for (const s of secrets) for (const f of forms(s)) expect(wire.includes(f)).toBe(false);
    const contains = (hay: Uint8Array, needle: Uint8Array) => {
      outer: for (let i = 0; i + needle.length <= hay.length; i++) {
        for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
        return true;
      }
      return false;
    };
    for (const m of net.media) for (const s of secrets) expect(contains(m.frame, s)).toBe(false);
    // A call message for B decrypts only with B's session: C's cannot read it.
    const toB = net.calls.find(m => m.from === A && m.to === B)!;
    const env = new TextDecoder().decode(decodeWireBase64(toB.wrappedKey.slice(CALL_ENVELOPE_PREFIX.length))!);
    const r = await (net.clients.get(C)!.bridge as CallKeyBridgeImpl).decryptFrom(A, env);
    expect(r.ok && classifyFor('voice', r.plaintext) !== null).toBe(false);
    // REQ-27: once the calls end, every HKDF key buffer is zero (received secrets at once, screen base keys at once, sender secrets at the switch or the end).
    for (const c of net.clients.values()) c.mgr.end();
    expect(hkdfInputs.length).toBeGreaterThan(10);
    for (const buf of hkdfInputs) expect(buf.every(x => x === 0)).toBe(true);
  });
});
