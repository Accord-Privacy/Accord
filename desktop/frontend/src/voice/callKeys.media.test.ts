// @vitest-environment node
/**
 * SPEC-03 `CallKeyManager`, media keys (§11.2 step 5, with A1): T-6 (REQ-6),
 * T-14's runtime key store (REQ-14), T-15 (REQ-15), T-17's A1 cases
 * (REQ-17), T-18 (REQ-18), T-34 (REQ-34), T-35 (REQ-35), and the manager's
 * part of A1's video receive rules (§6.2.8 steps 1 to 9; REQ-45, REQ-48).
 *
 * Senders and receivers are real managers with real AMF1 crypto; only the
 * E2EE bridge and the relay are fakes (`callKeys.testkit.ts`). Frames that an
 * honest sender would not produce (old epochs, chosen counters) are sealed in
 * the test with a copy of the sender's epoch secret, as a departed member or
 * a colluding relay could.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { decodeWireBase64 } from '../attachments/base64';
import {
  CTR_LIMIT,
  MEDIA_KIND_AUDIO,
  MEDIA_KIND_VIDEO,
  buildMetadata,
  decodeSFrameHeader,
  deriveEpochKeys,
  encodeSFrameHeader,
  frameContext,
  importHkdfKey,
  parseFrame,
  sealFrame,
  sframeDecrypt,
  type EpochKeys,
} from './mediaFrame';
import { ShareNumbering, encodeFragment, type EncodedScreenFrame } from './screenFrame';
import { A, B, C, CH, Net, b64, callPlaintext, testInst, wrapFake, type Client, type ClientOptions } from './callKeys.testkit';
import type { CallKeyManager, SealFunction } from './callKeys';

afterEach(() => {
  vi.restoreAllMocks();
});

function instBytes(m: CallKeyManager): Uint8Array {
  return decodeWireBase64(m.instanceId)!;
}

/** Records the 32-byte secrets a client draws (its epochs 0, 1, … in order). */
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

/** A seal wrapper that records the sender keys it is given, by epoch. */
function recordingSeal(): { seal: SealFunction; keys: Map<number, EpochKeys> } {
  const keys = new Map<number, EpochKeys>();
  return {
    keys,
    seal: (kind, k, ctr, ctx, pt) => {
      keys.set(k.epoch, k);
      return sealFrame(kind, k, ctr, ctx, pt);
    },
  };
}

async function senderKeys(secret: Uint8Array, epoch: number): Promise<EpochKeys> {
  return deriveEpochKeys(await importHkdfKey(Uint8Array.from(secret)), epoch, 'encrypt');
}

const header = (frame: Uint8Array) => decodeSFrameHeader(frame, 2)!;

function screenFrame(size: number, key: boolean, shareSeq: number, frameNo: number): EncodedScreenFrame {
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) data[i] = (i * 7 + frameNo) & 0xff;
  return { data, key, shareSeq, frameNo, width: 1280, height: 720 };
}

function fragmentPlaintext(marker: number): Uint8Array {
  return encodeFragment(
    { vcodec: 1, flags: 1, shareSeq: 1, frameNo: marker, fragIndex: 0, fragCount: 1, width: 1280, height: 720 },
    Uint8Array.of(marker & 0xff, (marker >> 8) & 0xff, 2, 3),
  );
}

/** Seal one video frame through the manager and deliver its fragments to `to`. */
async function shareFrame(net: Net, from: Client, to: Client, frame: EncodedScreenFrame): Promise<Uint8Array[]> {
  const n = Math.ceil(frame.data.length / 16_000);
  const t = from.mgr.beginVideoFrame(n);
  if (!t) throw new Error('no ticket');
  const frags = (await from.mgr.sealVideoFrame(t, frame))!;
  for (const f of frags) to.mgr.receiveVideoFragment(from.id, CH, f);
  await net.settle();
  return frags;
}

async function pair(optsA: ClientOptions = {}, optsB: ClientOptions = {}) {
  const net = new Net();
  const a = net.client(A, optsA);
  const b = net.client(B, optsB);
  b.watching.add(A);
  await net.join(A, B);
  await net.advance(3000);
  return { net, a, b };
}

const pcm = (marker: number) => Uint8Array.of(0x00, marker & 0xff, 1, 2);

// ---------------------------------------------------------------------------
// T-6
// ---------------------------------------------------------------------------

describe('T-6 (REQ-6) counters and hand-off order', () => {
  it('hands off audio frames in CTR order and fragments in VCTR order, even when encryptions complete out of order', async () => {
    let calls = 0;
    const seal: SealFunction = async (...args) => {
      const n = calls++;
      await new Promise(r => setTimeout(r, (7 - (n % 7)) * 2));
      return sealFrame(...args);
    };
    const { net, a, b } = await pair({ seal });
    const before = net.media.length;
    for (let i = 0; i < 30; i++) expect(a.mgr.sendAudio(pcm(i))).toBe(true);
    await net.settle();
    const ctrs = net.media.slice(before).map(m => header(m.frame).ctr);
    expect(ctrs.length).toBe(30);
    for (let i = 1; i < ctrs.length; i++) expect(ctrs[i]).toBe(ctrs[i - 1] + 1);
    expect(b.heard.slice(-30).map(h => h.payload[0])).toEqual([...Array(30).keys()]);
    const t = a.mgr.beginVideoFrame(3)!;
    const frags = (await a.mgr.sealVideoFrame(t, screenFrame(32_001, true, 1, 0)))!;
    expect(frags.map(f => header(f).ctr)).toEqual([t.firstVctr, t.firstVctr + 1, t.firstVctr + 2]);
  });

  it('over 3 rotations while sharing: KIDs 0 to 3 on frames and fragments, CTR and VCTR strictly increasing across epochs and shares, independent of each other', async () => {
    const { net, a, b } = await pair();
    const numbering = new ShareNumbering();
    const audio: Array<{ kid: number; ctr: number }> = [];
    const video: Array<{ kid: number; ctr: number }> = [];
    for (let r = 0; r < 4; r++) {
      if (r === 0 || r === 2) numbering.startShare();
      const before = net.media.length;
      for (let i = 0; i < 5; i++) a.mgr.sendAudio(pcm(i));
      await net.settle();
      audio.push(...net.media.slice(before).map(m => header(m.frame)));
      const frags = await shareFrame(net, a, b, screenFrame(r % 2 ? 100 : 16_001, true, numbering.shareSeq, numbering.frameNo));
      numbering.frameDone(true);
      video.push(...frags.map(header));
      await net.advance(10 * 60_000); // REQ-16 (e)
    }
    expect([...new Set(audio.map(h => h.kid))]).toEqual([0, 1, 2, 3]);
    expect([...new Set(video.map(h => h.kid))]).toEqual([0, 1, 2, 3]);
    for (const list of [audio, video]) {
      for (let i = 1; i < list.length; i++) {
        expect(list[i].ctr).toBeGreaterThan(list[i - 1].ctr);
        expect(list[i].kid).toBeGreaterThanOrEqual(list[i - 1].kid);
      }
    }
    expect(video.map(h => h.ctr)).toEqual([0, 1, 2, 3, 4, 5]);
    expect(b.fragments.map(f => f.kid)).toEqual([0, 0, 1, 2, 2, 3]);
    // 100 fragments do not move CTR.
    const ctrBefore = audio[audio.length - 1].ctr;
    for (let i = 0; i < 2; i++) await shareFrame(net, a, b, screenFrame(16_000 * 50, false, numbering.shareSeq, numbering.frameNo));
    const n0 = net.media.length;
    a.mgr.sendAudio(pcm(1));
    await net.settle();
    expect(header(net.media[n0].frame).ctr).toBe(ctrBefore + 1);
  });

  it('asks for a new instance before CTR or VCTR reaches 2^48, and never uses 2^48', async () => {
    const { net, a, b } = await pair({ counterStart: { ctr: CTR_LIMIT - 2, vctr: CTR_LIMIT - 3 } });
    const before = net.media.length;
    expect(a.mgr.sendAudio(pcm(1))).toBe(true);
    expect(a.rejoins).toEqual([]);
    expect(a.mgr.sendAudio(pcm(2))).toBe(true);
    expect(a.rejoins).toEqual(['counter_exhausted']);
    expect(a.mgr.sendAudio(pcm(3))).toBe(false);
    await net.settle();
    expect(net.media.slice(before).map(m => header(m.frame).ctr)).toEqual([CTR_LIMIT - 2, CTR_LIMIT - 1]);
    expect(b.heard.slice(-2).map(h => h.ctr)).toEqual([CTR_LIMIT - 2, CTR_LIMIT - 1]);
    const t = a.mgr.beginVideoFrame(2)!;
    expect(t.firstVctr).toBe(CTR_LIMIT - 3);
    expect(a.mgr.beginVideoFrame(2)).toBeNull();
    a.mgr.releaseVideoFrame(t);
    // The connection rejoins with a new instance, whose counters start at 0.
    net.newCall(a);
    net.newCall(b).start();
    await net.join(A, B);
    await net.advance(3000);
    const n0 = net.media.length;
    expect(a.mgr.sendAudio(pcm(4))).toBe(true);
    await net.settle();
    expect(header(net.media[n0].frame).ctr).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// T-14, runtime key store
// ---------------------------------------------------------------------------

describe('T-14 (REQ-14) the runtime key store', () => {
  it('audio CTR c and video VCTR c under one epoch: different ciphertexts, two (kind, KID) entries, no cross-kind decryption, usages per role', async () => {
    const rec = recordingSeal();
    const { net, a, b } = await pair({ counterStart: { ctr: 5, vctr: 5 }, seal: rec.seal });
    const plain = fragmentPlaintext(9); // the same plaintext for both kinds
    const n0 = net.media.length;
    expect(a.mgr.sendAudio(plain)).toBe(true);
    await net.settle();
    const audioFrame = net.media[n0].frame;
    const t = a.mgr.beginVideoFrame(1)!;
    const video = (await a.mgr.sealVideoFrame(t, { data: plain.subarray(18), key: true, shareSeq: 1, frameNo: 9, width: 1280, height: 720 }))![0];
    expect(header(audioFrame)).toEqual(header(video)); // KID 0, counter 5
    expect(b64(audioFrame.subarray(2))).not.toBe(b64(video.subarray(2)));
    expect(b.mgr.retainedRecord(A)!.keys).toEqual(expect.arrayContaining([{ kind: 1, kid: 0 }, { kind: 2, kid: 0 }]));
    expect(b.mgr.retainedRecord(A)!.keys.length).toBe(2);
    const kA = b.mgr.receiverKey(A, MEDIA_KIND_AUDIO, 0)!;
    const kV = b.mgr.receiverKey(A, MEDIA_KIND_VIDEO, 0)!;
    const ctx = frameContext(CH, A, instBytes(a.mgr));
    const pa = parseFrame(audioFrame, MEDIA_KIND_AUDIO);
    const pv = parseFrame(video, MEDIA_KIND_VIDEO);
    if (!pa.ok || !pv.ok) throw new Error('parse');
    expect(await sframeDecrypt(kA, pa.header, buildMetadata(MEDIA_KIND_AUDIO, ctx), pa.ciphertext)).not.toBeNull();
    expect(await sframeDecrypt(kV, pv.header, buildMetadata(MEDIA_KIND_VIDEO, ctx), pv.ciphertext)).not.toBeNull();
    for (const md of [MEDIA_KIND_AUDIO, MEDIA_KIND_VIDEO] as const) {
      expect(await sframeDecrypt(kA, pv.header, buildMetadata(md, ctx), pv.ciphertext)).toBeNull();
      expect(await sframeDecrypt(kV, pa.header, buildMetadata(md, ctx), pa.ciphertext)).toBeNull();
    }
    // Receivers decrypt only, senders encrypt only; nothing is extractable.
    for (const k of [kA, kV]) {
      expect(k.key.usages).toEqual(['decrypt']);
      expect(k.key.extractable).toBe(false);
      await expect(crypto.subtle.exportKey('raw', k.key)).rejects.toThrow();
    }
    const sk = rec.keys.get(0)!;
    for (const k of [sk.audio, sk.video]) {
      expect(k.key.usages).toEqual(['encrypt']);
      expect(k.key.extractable).toBe(false);
    }
    b.mgr.receiveVideoFragment(A, CH, video);
    await net.settle();
    expect(b.heard.map(h => [h.codec, ...h.payload])).toEqual([[...plain]]);
    expect(b.fragments.map(f => [...f.plaintext])).toEqual([[...plain]]);
  });
});

// ---------------------------------------------------------------------------
// T-15
// ---------------------------------------------------------------------------

describe('T-15 (REQ-15) replay windows', () => {
  it('audio: duplicates and frames older than 128 are dropped, out-of-order frames play once, forgeries do not move the window, CTR is the playout sequence', async () => {
    const { net, a, b } = await pair();
    let hold = new Set<number>();
    net.mediaFilter = m => !hold.has(header(m.frame).ctr);
    hold = new Set([3, 10]);
    const n0 = net.media.length;
    for (let i = 0; i < 160; i++) a.mgr.sendAudio(pcm(i));
    await net.settle();
    const recs = net.media.slice(n0);
    expect(b.heard.length).toBe(158);
    expect(b.heard.every(h => h.ctr === h.payload[0])).toBe(true);
    hold = new Set();
    net.deliverMedia(recs[5]); // duplicate
    net.deliverMedia(recs[10]); // 149 behind: outside the window
    await net.settle();
    expect(b.heard.length).toBe(158);
    // Within the window and never seen: accepted once.
    const r150 = recs[150];
    hold = new Set([160]);
    a.mgr.sendAudio(pcm(160));
    await net.settle();
    const late = net.media[net.media.length - 1];
    hold = new Set();
    a.mgr.sendAudio(pcm(161));
    await net.settle();
    net.deliverMedia(late);
    net.deliverMedia(late);
    await net.settle();
    expect(b.heard.filter(h => h.ctr === 160).length).toBe(1);
    void r150;
    // A forged frame with a high CTR and a bad tag changes nothing.
    const highest = b.mgr.retainedRecord(A)!.replayHighest.audio;
    const forged = Uint8Array.of(1, 1, ...encodeSFrameHeader(0, 100_000), ...new Uint8Array(30));
    b.mgr.receiveAudioFrame(A, CH, forged);
    await net.settle();
    expect(b.mgr.retainedRecord(A)!.replayHighest.audio).toBe(highest);
    a.mgr.sendAudio(pcm(162));
    await net.settle();
    expect(b.heard[b.heard.length - 1].ctr).toBe(162);
  });

  it('video: a fragment W − 1 behind is accepted once, W behind is dropped, and the audio and video windows are independent', async () => {
    const rnd = capturingRandom();
    const { net, a, b } = await pair({ random: rnd.random });
    const keys = await senderKeys(rnd.secrets[0], 0);
    const ctx = frameContext(CH, A, instBytes(a.mgr));
    const frag = (vctr: number) => sealFrame(MEDIA_KIND_VIDEO, keys, vctr, ctx, fragmentPlaintext(vctr % 65_536));
    const deliver = async (f: Uint8Array) => {
      b.mgr.receiveVideoFragment(A, CH, f);
      await net.settle();
    };
    await deliver(await frag(2000));
    expect(b.fragments.length).toBe(1);
    await deliver(await frag(2000 - 1023));
    await deliver(await frag(2000 - 1023));
    expect(b.fragments.length).toBe(2);
    await deliver(await frag(2000 - 1024));
    expect(b.fragments.length).toBe(2);
    // VCTR 500 does not mark audio CTR 500.
    await deliver(await frag(1500));
    const audio = await sealFrame(MEDIA_KIND_AUDIO, keys, 1500, ctx, pcm(7));
    b.mgr.receiveAudioFrame(A, CH, audio);
    await net.settle();
    expect(b.heard.map(h => h.ctr)).toEqual([1500]);
    expect(b.mgr.retainedRecord(A)!.replayHighest).toEqual({ audio: 1500, video: 2000 });
  });
});

// ---------------------------------------------------------------------------
// A2 (§14.1): replay windows per epoch (REQ-15, REQ-34)
// ---------------------------------------------------------------------------

describe('A2 (§14.1) replay windows per sender instance, media kind and epoch', () => {
  it('a holder of g\'s key forging under g at 2^47 moves only g\'s windows: the sender\'s own lower counters under g+1 authenticate and reach the caller with their epoch; g\'s window goes with g\'s key', async () => {
    const rnd = capturingRandom();
    const s = await pair({ random: rnd.random });
    s.a.mgr.onPeerJoined(C); // A rotates to epoch 1 after 500 ms; B holds 0 and 1
    await s.net.advance(600);
    const { net, b } = s;
    const k0 = await senderKeys(rnd.secrets[0], 0);
    const k1 = await senderKeys(rnd.secrets[1], 1);
    const ctx = frameContext(CH, A, instBytes(s.a.mgr));
    const deliver = async (kind: 1 | 2, k: EpochKeys, ctr: number) => {
      const f = await sealFrame(kind, k, ctr, ctx, kind === MEDIA_KIND_AUDIO ? pcm(ctr & 0xff) : fragmentPlaintext(ctr & 0xffff));
      if (kind === MEDIA_KIND_AUDIO) b.mgr.receiveAudioFrame(A, CH, f);
      else b.mgr.receiveVideoFragment(A, CH, f);
      await net.settle();
      return f;
    };
    const FAR = 2 ** 47;
    await deliver(MEDIA_KIND_AUDIO, k0, FAR);
    await deliver(MEDIA_KIND_VIDEO, k0, FAR);
    expect(b.heard.map(h => [h.epoch, h.ctr])).toEqual([[0, FAR]]);
    // The sender's genuine counters, far below, under its newer epoch.
    const genuine = await deliver(MEDIA_KIND_AUDIO, k1, 5);
    await deliver(MEDIA_KIND_AUDIO, k1, 6);
    await deliver(MEDIA_KIND_VIDEO, k1, 5);
    expect(b.heard.map(h => [h.epoch, h.ctr])).toEqual([[0, FAR], [1, 5], [1, 6]]);
    expect(b.fragments.map(f => f.kid)).toEqual([0, 1]);
    expect(b.mgr.retainedRecord(A)!.replayWindows).toEqual([
      { kid: 0, audio: FAR, video: FAR },
      { kid: 1, audio: 6, video: 5 },
    ]);
    // Each window still refuses its replays, and g is closed once g+1 authenticated (REQ-18).
    b.mgr.receiveAudioFrame(A, CH, genuine);
    await deliver(MEDIA_KIND_AUDIO, k0, FAR + 1);
    expect(b.heard.length).toBe(3);
    // g's key goes 2 s after g+1 was installed; g can never be installed again, so its windows go too.
    await net.advance(2000);
    expect(b.mgr.retainedRecord(A)!.replayWindows.map(w => w.kid)).toEqual([1]);
  });

  it('the highest epoch\'s windows outlive its erased key while REQ-33 (c) may reinstall it, keep refusing recorded frames after a reinstall, and go at KEY_MAX_AGE', async () => {
    const rnd = capturingRandom();
    const { net, a, b } = await pair({ random: rnd.random, timings: { rotationIntervalMs: 60 * 60_000 } });
    const first = b.mgr.retainedRecord(A)!.maxEpochFirstInstalledAt!;
    const n0 = net.media.length;
    for (let i = 0; i < 5; i++) a.mgr.sendAudio(pcm(i));
    await net.settle();
    const recorded = net.media.slice(n0);
    const redeliver = () =>
      net.inject(B, A, wrapFake(A, B, callPlaintext({
        type: 'call_key', v: 1, suite: 5, from: A, ch: CH, inst: a.mgr.instanceId, to_inst: b.mgr.instanceId, epoch: 0, key: b64(rnd.secrets[0]),
      })));
    // A forged leave: keys erased, windows kept.
    b.mgr.onPeerLeft(A);
    expect(b.mgr.retainedRecord(A)!.keys).toEqual([]);
    expect(b.mgr.retainedRecord(A)!.replayWindows).toEqual([{ kid: 0, audio: 4, video: -1 }]);
    b.mgr.onPeerJoined(A);
    redeliver();
    await net.settle();
    expect(b.mgr.retainedRecord(A)!.keys.length).toBe(2);
    for (const r of recorded) net.deliverMedia(r);
    await net.settle();
    expect(b.heard.length).toBe(5); // the recorded frames stay refused by the retained window
    // Erased again, and KEY_MAX_AGE after the first installation the window goes.
    b.mgr.onPeerLeft(A);
    b.mgr.onPeerJoined(A);
    await net.advance(first + 11 * 60_000 - 1 - net.clock.now());
    expect(b.mgr.retainedRecord(A)!.replayWindows.map(w => w.kid)).toEqual([0]);
    await net.advance(1);
    expect(b.mgr.retainedRecord(A)!.replayWindows).toEqual([]);
    // It can no longer be reinstalled either (REQ-33 (c)).
    const installs = b.installed.length;
    redeliver();
    await net.settle();
    expect(b.installed.length).toBe(installs);
  });

  it('RG-C112-4 run 2 (U form): with A\'s next epoch withheld, forged audio and video under g at 2^47 stop at KEY_MAX_AGE, and once released A\'s own frames under the newest epoch play and decode', async () => {
    const rnd = capturingRandom();
    const net = new Net();
    const a = net.client(A, { random: rnd.random, timings: { rotationIntervalMs: 60 * 60_000 } });
    const b = net.client(B, { timings: { keyMaxAgeMs: 8000 } });
    net.client(C);
    b.watching.add(A);
    await net.join(A, B, C);
    await net.advance(3000);
    const installedAt = b.mgr.retainedRecord(A)!.maxEpochFirstInstalledAt!;
    for (let i = 0; i < 5; i++) a.mgr.sendAudio(pcm(i));
    await shareFrame(net, a, b, screenFrame(100, true, 1, 0));
    expect(b.heard.length).toBe(5);
    // C is removed; every A → B call message is withheld from now on.
    net.callFilter = m => (m.from === A && m.to === B ? 'withhold' : 'deliver');
    a.mgr.onPeerLeft(C);
    b.mgr.onPeerLeft(C);
    await net.advance(2500);
    expect(a.mgr.sendingEpoch()).toBe(1);
    // C's copy of g forges audio and video at 2^47 and above.
    const k0 = await senderKeys(rnd.secrets[0], 0);
    const ctx = frameContext(CH, A, instBytes(a.mgr));
    const FAR = 2 ** 47;
    for (let j = 0; j < 3; j++) {
      b.mgr.receiveAudioFrame(A, CH, await sealFrame(MEDIA_KIND_AUDIO, k0, FAR + j, ctx, pcm(200 + j)));
      b.mgr.receiveVideoFragment(A, CH, await sealFrame(MEDIA_KIND_VIDEO, k0, FAR + j, ctx, fragmentPlaintext(200 + j)));
    }
    await net.settle();
    expect(b.heard.filter(h => h.ctr >= FAR).length).toBe(3); // the bounded residual of §9.2 item 2
    // KEY_MAX_AGE after B first installed g: g is erased; nothing more is accepted under it.
    await net.advance(installedAt + 8000 - net.clock.now());
    expect(b.mgr.retainedRecord(A)!.keys).toEqual([]);
    b.mgr.receiveAudioFrame(A, CH, await sealFrame(MEDIA_KIND_AUDIO, k0, FAR + 10, ctx, pcm(210)));
    await net.settle();
    expect(b.heard.filter(h => h.ctr >= FAR).length).toBe(3);
    expect(b.mgr.snapshot().participants.find(p => p.userId === A)!.inbound).toBe('waiting');
    // HRP releases A's messages: B installs the newest epoch, and A's own counters, far below 2^47, play.
    net.callFilter = () => 'deliver';
    for (const m of net.withheld.splice(0)) net.deliverCall(m);
    await net.settle();
    expect(b.mgr.retainedRecord(A)!.keys.map(k => k.kid)).toContain(1);
    const n = b.heard.length;
    for (let i = 0; i < 3; i++) a.mgr.sendAudio(pcm(i));
    await net.settle();
    const resumed = b.heard.slice(n);
    expect(resumed.map(h => h.epoch)).toEqual([1, 1, 1]);
    expect(resumed.every(h => h.ctr < 100)).toBe(true);
    const f = b.fragments.length;
    await shareFrame(net, a, b, screenFrame(100, true, 1, 1));
    expect(b.fragments.slice(f).map(x => x.kid)).toEqual([1]);
  });
});

// ---------------------------------------------------------------------------
// T-17, A1
// ---------------------------------------------------------------------------

describe('T-17 (REQ-17) epoch switches while sharing (A1)', () => {
  it('a departure while a 3-fragment frame is half sent: the rest is not sent, nothing is sealed under g after, deltas wait for a key, g\'s keys of both kinds are erased', async () => {
    const rec = recordingSeal();
    const net = new Net();
    const a = net.client(A, { seal: rec.seal });
    const b = net.client(B);
    net.client(C);
    b.watching.add(A);
    await net.join(A, B, C);
    await net.advance(3000);
    const g = a.mgr.sendingEpoch()!;
    a.mgr.sendAudio(pcm(0));
    await net.settle();
    // A minimal screen sender: after a switch it discards deltas until a key.
    let needKey = false;
    const switchesBefore = a.switches.length;
    const handed: Uint8Array[] = [];
    const t = a.mgr.beginVideoFrame(3)!;
    const frags = (await a.mgr.sealVideoFrame(t, screenFrame(32_001, false, 1, 0)))!;
    for (const [i, f] of frags.entries()) {
      if (i === 2) a.mgr.onPeerLeft(C); // the trigger, after two fragments
      if (a.mgr.mayHandOff(t)) handed.push(f);
    }
    expect(handed.length).toBe(2);
    expect(a.mgr.beginVideoFrame(1)).toBeNull(); // nothing sealed under g after the trigger
    await net.settle();
    expect(a.switches.length).toBe(switchesBefore + 1);
    needKey = a.switches[a.switches.length - 1] === g + 1;
    const outputs = [screenFrame(500, false, 1, 1), screenFrame(500, false, 1, 1), screenFrame(500, true, 1, 1)];
    const discarded: boolean[] = [];
    for (const o of outputs) {
      if (needKey && !o.key) {
        discarded.push(true);
        continue;
      }
      needKey = false;
      const t2 = a.mgr.beginVideoFrame(1)!;
      expect(t2.epoch).toBe(g + 1);
      handed.push(...(await a.mgr.sealVideoFrame(t2, o))!);
    }
    expect(discarded).toEqual([true, true]);
    expect(handed.map(f => header(f).kid)).toEqual([g, g, g + 1]);
    for (const f of handed) b.mgr.receiveVideoFragment(A, CH, f);
    await net.settle();
    const last = b.fragments[b.fragments.length - 1];
    expect(last.kid).toBe(g + 1);
    expect(last.plaintext[1] & 1).toBe(1); // the first fragment under g+1 is a keyframe's
    const old = rec.keys.get(g)!;
    expect(old.audio.salt.every(x => x === 0)).toBe(true);
    expect(old.video.salt.every(x => x === 0)).toBe(true);
  });

  it('a join while a frame is being sealed: its fragments all stay under g, g\'s video key goes right after, and the switch asks for a keyframe under g+1', async () => {
    const rec = recordingSeal();
    const { net, a, b } = await pair({ seal: rec.seal });
    const g = a.mgr.sendingEpoch()!;
    a.mgr.sendAudio(pcm(0));
    await net.settle();
    const t = a.mgr.beginVideoFrame(3)!; // frame start under g
    a.mgr.onPeerJoined(C);
    await net.advance(600);
    expect(a.mgr.sendingEpoch()).toBe(g + 1);
    expect(a.switches[a.switches.length - 1]).toBe(g + 1);
    const old = rec.keys.get(g)!;
    expect(old.audio.salt.every(x => x === 0)).toBe(true);
    expect(old.video.salt.some(x => x !== 0)).toBe(true); // kept for the frame in flight
    expect(a.mgr.mayHandOff(t)).toBe(true);
    const frags = (await a.mgr.sealVideoFrame(t, screenFrame(32_001, false, 1, 0)))!;
    expect(old.video.salt.every(x => x === 0)).toBe(true);
    expect(frags.map(f => header(f).kid)).toEqual([g, g, g]);
    expect(frags.map(f => header(f).ctr)).toEqual([t.firstVctr, t.firstVctr + 1, t.firstVctr + 2]);
    for (const f of frags) b.mgr.receiveVideoFragment(A, CH, f);
    await net.settle();
    expect(b.fragments.map(f => f.kid)).toEqual([g, g, g]);
    const t2 = a.mgr.beginVideoFrame(1)!;
    expect(t2.epoch).toBe(g + 1);
    a.mgr.releaseVideoFrame(t2);
  });

  /** A frame started under g, and a join rotation that switches to g+1 while its ticket is outstanding. */
  async function outstandingAcrossSwitch() {
    const rec = recordingSeal();
    const s = await pair({ seal: rec.seal });
    const g = s.a.mgr.sendingEpoch()!;
    s.a.mgr.sendAudio(pcm(0)); // records g's keys
    await s.net.settle();
    const t = s.a.mgr.beginVideoFrame(1)!;
    s.a.mgr.onPeerJoined(C);
    await s.net.advance(600);
    expect(s.a.mgr.sendingEpoch()).toBe(g + 1);
    const old = rec.keys.get(g)!;
    expect(old.video.salt.some(x => x !== 0)).toBe(true); // kept for the frame in flight
    return { ...s, g, t, old };
  }

  it('ending the call erases a replaced epoch\'s video key kept for a frame whose ticket was never sealed or released (REQ-18, REQ-27)', async () => {
    const { a, t, old } = await outstandingAcrossSwitch();
    a.mgr.end();
    expect(old.audio.salt.every(x => x === 0)).toBe(true);
    expect(old.video.salt.every(x => x === 0)).toBe(true);
    expect(await a.mgr.sealVideoFrame(t, screenFrame(100, true, 1, 0))).toBeNull();
  });

  it('a departure trigger erases at once the video key kept for an outstanding frame, which can never be handed off (REQ-17)', async () => {
    const { a, t, old } = await outstandingAcrossSwitch();
    a.mgr.onPeerLeft(C); // C is in R_{g+1}: a departure rotation
    expect(old.video.salt.every(x => x === 0)).toBe(true);
    expect(a.mgr.mayHandOff(t)).toBe(false);
    expect(await a.mgr.sealVideoFrame(t, screenFrame(100, true, 1, 0))).toBeNull();
  });

  it('a screen frame that breaks §6.2.7 is refused before sealing and never stops audio (not a local encryption failure, §8.3)', async () => {
    const { net, a, b } = await pair();
    const g = a.mgr.sendingEpoch()!;
    const bad: EncodedScreenFrame[] = [
      { ...screenFrame(100, true, 1, 0), width: 8, height: 8 },
      { ...screenFrame(100, true, 1, 0), width: 1920, height: 1920 },
      screenFrame(100, true, 0, 0),
      screenFrame(100, false, 1, 2 ** 32),
    ];
    for (const frame of bad) {
      const t = a.mgr.beginVideoFrame(1)!;
      await expect(a.mgr.sealVideoFrame(t, frame)).rejects.toThrow(RangeError);
      expect(a.mgr.sendingEpoch()).toBe(g);
      expect(a.mgr.mayHandOff(t)).toBe(true);
    }
    expect(a.mgr.snapshot().indicator).not.toBe('unavailable');
    expect(a.mgr.sendAudio(pcm(7))).toBe(true);
    await net.settle();
    expect(b.heard[b.heard.length - 1].payload[0]).toBe(7);
    // The tickets were released: a valid frame still seals under g.
    const t = a.mgr.beginVideoFrame(1)!;
    const frags = (await a.mgr.sealVideoFrame(t, screenFrame(100, true, 1, 0)))!;
    expect(frags.map(f => header(f).kid)).toEqual([g]);
  });
});

// ---------------------------------------------------------------------------
// T-18
// ---------------------------------------------------------------------------

describe('T-18 (REQ-18) receiver key lifetime', () => {
  async function rotated() {
    const rnd = capturingRandom();
    const s = await pair({ random: rnd.random });
    s.a.mgr.onPeerJoined(C); // A rotates to epoch 1 after 500 ms
    await s.net.advance(600);
    expect(s.b.installed.filter(i => i.from === A).map(i => i.epoch)).toEqual([0, 1]);
    const k0 = await senderKeys(rnd.secrets[0], 0);
    const k1 = await senderKeys(rnd.secrets[1], 1);
    const ctx = frameContext(CH, A, instBytes(s.a.mgr));
    const audio = (k: EpochKeys, ctr: number) => sealFrame(MEDIA_KIND_AUDIO, k, ctr, ctx, pcm(ctr));
    const video = (k: EpochKeys, ctr: number) => sealFrame(MEDIA_KIND_VIDEO, k, ctr, ctx, fragmentPlaintext(ctr));
    return { ...s, k0, k1, audio, video, rnd };
  }

  it('after g+1 is installed, g still decrypts for 2 s and then fails, for audio and video alike', async () => {
    const { net, b, k0, audio, video } = await rotated();
    b.mgr.receiveAudioFrame(A, CH, await audio(k0, 100));
    b.mgr.receiveVideoFragment(A, CH, await video(k0, 100));
    await net.settle();
    expect(b.heard.map(h => h.ctr)).toEqual([100]);
    expect(b.fragments.map(f => f.kid)).toEqual([0]);
    await net.advance(1900);
    b.mgr.receiveAudioFrame(A, CH, await audio(k0, 101));
    b.mgr.receiveVideoFragment(A, CH, await video(k0, 101));
    await net.settle();
    expect(b.heard.length).toBe(1);
    expect(b.fragments.length).toBe(1);
    expect(b.mgr.retainedRecord(A)!.keys).toEqual(expect.arrayContaining([{ kind: 1, kid: 1 }, { kind: 2, kid: 1 }]));
    expect(b.mgr.retainedRecord(A)!.keys.length).toBe(2);
  });

  it('once a kind authenticated under g+1, frames of that kind under g are dropped (made with a copy of g\'s key), while the other kind still accepts g', async () => {
    const { net, b, k0, k1, audio, video } = await rotated();
    const deliverAudio = async (f: Promise<Uint8Array>) => {
      b.mgr.receiveAudioFrame(A, CH, await f);
      await net.settle();
    };
    const deliverVideo = async (f: Promise<Uint8Array>) => {
      b.mgr.receiveVideoFragment(A, CH, await f);
      await net.settle();
    };
    await deliverAudio(audio(k1, 200));
    await deliverAudio(audio(k0, 201));
    expect(b.heard.map(h => [h.epoch, h.ctr])).toEqual([[1, 200]]);
    await deliverVideo(video(k0, 50));
    await deliverVideo(video(k1, 60));
    await deliverVideo(video(k0, 61));
    expect(b.fragments.map(f => f.kid)).toEqual([0, 1]);
    expect(b.mgr.retainedRecord(A)!.highestAuthEpoch).toEqual({ audio: 1, video: 1 });
  });

  it('a key never superseded is erased KEY_MAX_AGE after its first installation (the peer falls back to waiting); a re-delivery before then is reinstalled with that time, after then refused', async () => {
    const rnd = capturingRandom();
    const { net, a, b } = await pair({ random: rnd.random, timings: { rotationIntervalMs: 60 * 60_000 } });
    const first = b.mgr.retainedRecord(A)!.maxEpochFirstInstalledAt!;
    const redeliver = () =>
      net.inject(B, A, wrapFake(A, B, callPlaintext({
        type: 'call_key', v: 1, suite: 5, from: A, ch: CH, inst: a.mgr.instanceId, to_inst: b.mgr.instanceId, epoch: 0, key: b64(rnd.secrets[0]),
      })));
    await net.advance(5 * 60_000);
    b.mgr.onPeerLeft(A);
    expect(b.mgr.retainedRecord(A)!.keys).toEqual([]);
    b.mgr.onPeerJoined(A);
    redeliver();
    await net.settle();
    expect(b.mgr.retainedRecord(A)!.keys.length).toBe(2);
    expect(b.mgr.retainedRecord(A)!.maxEpochFirstInstalledAt).toBe(first);
    await net.advance(first + 11 * 60_000 - 1 - net.clock.now());
    expect(b.mgr.retainedRecord(A)!.keys.length).toBe(2);
    await net.advance(1);
    expect(b.mgr.retainedRecord(A)!.keys).toEqual([]);
    expect(b.mgr.snapshot().participants.find(p => p.userId === A)!.inbound).toBe('waiting');
    expect(b.resets).toContainEqual({ from: A, cause: 'erased' });
    const installs = b.installed.length;
    redeliver();
    await net.settle();
    expect(b.installed.length).toBe(installs);
    expect(b.mgr.retainedRecord(A)!.keys).toEqual([]);
  });

  it('at most 2 epochs are held, each with both kinds', async () => {
    const net = new Net();
    const b = net.client(B);
    b.mgr.start();
    b.mgr.onJoined([A]);
    await net.settle();
    const instA = testInst(0x18);
    for (let e = 0; e < 4; e++) {
      net.inject(B, A, wrapFake(A, B, callPlaintext({
        type: 'call_key', v: 1, suite: 5, from: A, ch: CH, inst: b64(instA), to_inst: b.mgr.instanceId, epoch: e, key: b64(new Uint8Array(32).fill(e + 1)),
      })));
    }
    await net.settle();
    const keys = b.mgr.retainedRecord(A)!.keys;
    expect(keys.length).toBe(4);
    expect(new Set(keys.map(k => k.kid))).toEqual(new Set([2, 3]));
  });

  it('voice_peer_left erases the sender\'s keys at once; a re-delivered CKM reinstalls them with the old replay window', async () => {
    const rnd = capturingRandom();
    const { net, a, b } = await pair({ random: rnd.random });
    const n0 = net.media.length;
    for (let i = 0; i < 10; i++) a.mgr.sendAudio(pcm(i));
    await net.settle();
    expect(b.heard.length).toBe(10);
    b.mgr.onPeerLeft(A);
    expect(b.mgr.retainedRecord(A)!.keys).toEqual([]); // at once
    b.mgr.onPeerJoined(A);
    net.inject(B, A, wrapFake(A, B, callPlaintext({
      type: 'call_key', v: 1, suite: 5, from: A, ch: CH, inst: a.mgr.instanceId, to_inst: b.mgr.instanceId, epoch: 0, key: b64(rnd.secrets[0]),
    })));
    await net.settle();
    expect(b.mgr.retainedRecord(A)!.keys.length).toBe(2);
    net.deliverMedia(net.media[n0 + 5]);
    await net.settle();
    expect(b.heard.length).toBe(10); // the old counter stays rejected
    a.mgr.sendAudio(pcm(10));
    await net.settle();
    expect(b.heard.map(h => h.ctr).slice(-1)).toEqual([10]);
  });

  it('ending the call erases everything, including retained records', async () => {
    const { b } = await pair();
    expect(b.mgr.retainedRecord(A)).not.toBeNull();
    b.mgr.end();
    expect(b.mgr.retainedRecord(A)).toBeNull();
    expect(b.mgr.snapshot().participants).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// T-34
// ---------------------------------------------------------------------------

describe('T-34 (REQ-34) the retained record', () => {
  it('survives leave, ineligibility and replacement, with both replay windows, the first installation time and the highest authenticated epochs', async () => {
    const rnd = capturingRandom();
    const { net, a, b } = await pair({ random: rnd.random });
    for (let i = 0; i < 5; i++) a.mgr.sendAudio(pcm(i));
    await net.settle();
    const frags = await shareFrame(net, a, b, screenFrame(16_001, true, 1, 0));
    const r1 = b.mgr.retainedRecord(A)!;
    expect(r1.replayHighest).toEqual({ audio: 4, video: 1 });
    expect(r1.highestAuthEpoch).toEqual({ audio: 0, video: 0 });
    b.mgr.onPeerLeft(A);
    const r2 = b.mgr.retainedRecord(A)!;
    expect(r2.keys).toEqual([]);
    expect({ ...r2, keys: [] }).toEqual({ ...r1, keys: [] });
    b.mgr.onPeerJoined(A);
    // A fake leave and rejoin, a re-delivered key: the recorded fragment is still a replay.
    net.inject(B, A, wrapFake(A, B, callPlaintext({
      type: 'call_key', v: 1, suite: 5, from: A, ch: CH, inst: a.mgr.instanceId, to_inst: b.mgr.instanceId, epoch: 0, key: b64(rnd.secrets[0]),
    })));
    await net.settle();
    const seen = b.fragments.length;
    b.mgr.receiveVideoFragment(A, CH, frags[0]);
    await net.settle();
    expect(b.fragments.length).toBe(seen);
    b.fake.setMembership(A, 'not_member');
    expect(b.mgr.retainedRecord(A)!.replayHighest).toEqual({ audio: 4, video: 1 });
    b.fake.setMembership(A, 'member');
    net.inject(B, A, wrapFake(A, B, callPlaintext({ type: 'call_hello', v: 1, from: A, ch: CH, inst: b64(testInst(0x34)), to_inst: b.mgr.instanceId })));
    await net.settle();
    expect(b.mgr.retainedRecord(A)!.replaced).toEqual([a.mgr.instanceId]);
  });

  it('after 70 instances, at least the newest 64 replaced ids are kept, and they are refused', async () => {
    const net = new Net();
    const b = net.client(B);
    b.mgr.start();
    b.mgr.onJoined([A]);
    await net.settle();
    const hello = (i: number) => wrapFake(A, B, callPlaintext({ type: 'call_hello', v: 1, from: A, ch: CH, inst: b64(testInst(i)), to_inst: null }));
    for (let i = 1; i <= 71; i++) net.inject(B, A, hello(i));
    await net.settle();
    const r = b.mgr.retainedRecord(A)!;
    expect(r.currentInst).toBe(b64(testInst(71)));
    expect(r.replaced.length).toBeGreaterThanOrEqual(64);
    for (let i = 7; i <= 70; i++) expect(r.replaced).toContain(b64(testInst(i)));
    net.inject(B, A, hello(70));
    await net.settle();
    expect(b.mgr.retainedRecord(A)!.currentInst).toBe(b64(testInst(71)));
  });
});

// ---------------------------------------------------------------------------
// T-35
// ---------------------------------------------------------------------------

describe('T-35 (REQ-35) the receive pipeline', () => {
  it('a sender that restarts at CTR 0 without voice_peer_left is heard once its new key is installed (pipeline reset)', async () => {
    const { net, a, b } = await pair();
    for (let i = 0; i < 5; i++) a.mgr.sendAudio(pcm(i));
    await net.settle();
    expect(b.heard.length).toBe(5);
    net.newCall(a);
    a.mgr.start();
    a.mgr.onJoined([B]);
    await net.advance(5000);
    expect(b.resets).toContainEqual({ from: A, cause: 'new_instance' });
    for (let i = 0; i < 5; i++) a.mgr.sendAudio(pcm(i));
    await net.settle();
    expect(b.heard.map(h => h.ctr)).toEqual([0, 1, 2, 3, 4, 0, 1, 2, 3, 4]);
  });

  async function installing() {
    const net = new Net();
    const b = net.client(B);
    b.watching.add(A);
    b.mgr.start();
    b.mgr.onJoined([A]);
    await net.settle();
    const instA = testInst(0x35);
    const secret = new Uint8Array(32).fill(0x35);
    const keys = await senderKeys(secret, 0);
    const ctx = frameContext(CH, A, instA);
    const ckm = wrapFake(A, B, callPlaintext({
      type: 'call_key', v: 1, suite: 5, from: A, ch: CH, inst: b64(instA), to_inst: b.mgr.instanceId, epoch: 0, key: b64(secret),
    }));
    return { net, b, keys, ctx, ckm };
  }

  it('of 60 frames arriving during an installation, the oldest 10 are dropped and the rest play in order', async () => {
    const { net, b, keys, ctx, ckm } = await installing();
    const frames = await Promise.all([...Array(60).keys()].map(i => sealFrame(MEDIA_KIND_AUDIO, keys, i, ctx, pcm(i))));
    b.mgr.handleKeyExchange({ from: A, channel_id: CH, wrapped_key: ckm });
    for (const f of frames) b.mgr.receiveAudioFrame(A, CH, f);
    await net.settle();
    expect(b.heard.map(h => h.ctr)).toEqual([...Array(50).keys()].map(i => i + 10));
  });

  it('A1: of 140 fragments arriving during an installation, the oldest 12 are dropped and the rest are processed in order, after the video keys are derived', async () => {
    const { net, b, keys, ctx, ckm } = await installing();
    const frags = await Promise.all([...Array(140).keys()].map(i => sealFrame(MEDIA_KIND_VIDEO, keys, i, ctx, fragmentPlaintext(i))));
    let videoKeyAtInstall: boolean | null = null;
    const installedHook = b.installed.push.bind(b.installed);
    b.installed.push = (...items) => {
      videoKeyAtInstall = b.mgr.receiverKey(A, MEDIA_KIND_VIDEO, 0) !== null;
      expect(b.fragments.length).toBe(0);
      return installedHook(...items);
    };
    b.mgr.handleKeyExchange({ from: A, channel_id: CH, wrapped_key: ckm });
    for (const f of frags) b.mgr.receiveVideoFragment(A, CH, f);
    await net.settle();
    expect(videoKeyAtInstall).toBe(true);
    const markers = b.fragments.map(f => f.plaintext[18] | (f.plaintext[19] << 8));
    expect(markers).toEqual([...Array(128).keys()].map(i => i + 12));
  });

  it('A1: a watched sharer that restarts with a new instance resets its share, and its new video key is announced once installed', async () => {
    const { net, a, b } = await pair();
    await shareFrame(net, a, b, screenFrame(100, true, 1, 0));
    expect(b.mgr.hasVideoKey(A)).toBe(true);
    const installs = b.installed.length;
    net.newCall(a);
    a.mgr.start();
    a.mgr.onJoined([B]);
    await net.settle();
    expect(b.resets).toContainEqual({ from: A, cause: 'new_instance' });
    await net.advance(5000);
    expect(b.installed.length).toBe(installs + 1);
    expect(b.mgr.hasVideoKey(A)).toBe(true);
    expect(b.mgr.retainedRecord(A)!.currentInst).toBe(a.mgr.instanceId);
  });
});

// ---------------------------------------------------------------------------
// A1: receiving fragments (manager part of §6.2.8)
// ---------------------------------------------------------------------------

describe('A1: video fragments at the receiver (§6.2.8 steps 1 to 9, REQ-45, REQ-48)', () => {
  it('nothing is decrypted for a sharer the client does not watch, nor over the decryption budget; AEAD failures are counted and reset', async () => {
    const { net, a, b } = await pair();
    b.watching.delete(A);
    const t = a.mgr.beginVideoFrame(2)!;
    const frags = (await a.mgr.sealVideoFrame(t, screenFrame(16_001, true, 1, 0)))!;
    const spy = vi.spyOn(crypto.subtle, 'decrypt');
    for (const f of frags) b.mgr.receiveVideoFragment(A, CH, f);
    await net.settle();
    expect(spy).not.toHaveBeenCalled();
    expect(b.fragments).toEqual([]);
    b.watching.add(A);
    b.decryptBudget = 0;
    for (const f of frags) b.mgr.receiveVideoFragment(A, CH, f);
    await net.settle();
    expect(spy).not.toHaveBeenCalled();
    expect(b.videoFailures).toEqual([]);
    b.decryptBudget = Infinity;
    const tampered = frags.map(f => {
      const x = Uint8Array.from(f);
      x[x.length - 1] ^= 1;
      return x;
    });
    for (const f of tampered) b.mgr.receiveVideoFragment(A, CH, f);
    await net.settle();
    expect(b.videoFailures.map(v => v.consecutive)).toEqual([1, 2]);
    for (const f of frags) b.mgr.receiveVideoFragment(A, CH, f);
    await net.settle();
    expect(b.fragments.length).toBe(2);
    expect(b.videoFailures.map(v => v.consecutive)).toEqual([1, 2, 0]);
  });

  it('an audio frame moved to SCREEN_DOWN, and a fragment moved to srtp_voice_packet, are discarded without touching either window', async () => {
    const { net, a, b } = await pair();
    const n0 = net.media.length;
    a.mgr.sendAudio(pcm(1));
    await net.settle();
    const audio = net.media[n0].frame;
    const t = a.mgr.beginVideoFrame(1)!;
    const frag = (await a.mgr.sealVideoFrame(t, screenFrame(100, true, 1, 0)))![0];
    const before = b.mgr.retainedRecord(A)!.replayHighest;
    const spy = vi.spyOn(crypto.subtle, 'decrypt');
    b.mgr.receiveVideoFragment(A, CH, audio);
    b.mgr.receiveAudioFrame(A, CH, frag);
    await net.settle();
    expect(spy).not.toHaveBeenCalled();
    expect(b.fragments).toEqual([]);
    expect(b.heard.length).toBe(1);
    expect(b.mgr.retainedRecord(A)!.replayHighest).toEqual(before);
  });

  it('video goes to exactly R_g of the epoch it is sealed under (REQ-45, REQ-54): the audience counts addressees, not acknowledgments', async () => {
    const net = new Net();
    const a = net.client(A);
    net.client(B);
    net.client(C);
    net.callFilter = m => (m.to === A && m.wrappedKey && m.from === C ? 'drop' : 'deliver');
    await net.join(A, B, C);
    await net.advance(3000);
    const aud = a.mgr.videoAudience()!;
    expect(aud.epoch).toBe(a.mgr.sendingEpoch());
    expect([...aud.members].sort()).toEqual([B, C].sort());
    expect(aud.acknowledged).toBe(1); // C's acknowledgments are dropped; C still counts
    expect([...aud.members].sort()).toEqual(a.mgr.currentRecipients().sort());
  });
});
