// @vitest-environment node
/**
 * SPEC-03 A1 U tests of the screen-sharing sender (`ScreenShareSender` in
 * `voice/screenShare.ts`) and the probes, with the screen fakes of §10.1
 * (`voice/screenShare.testkit.ts`), a manual clock, a fake transport that
 * reports a chosen `bufferedAmount`, and fake keys that record every frame
 * the sender fixes and seal it as plaintext fragments so their headers can be
 * read: the probes of §6.13.1 (T-42, U part), T-43 (U part: the options, the
 * audio track, the content hint and the capture errors), T-44, T-46 (the
 * sender's numbering and hand-off), T-47 (U), T-51 (U) and T-52 (U).
 */

import { describe, expect, it } from 'vitest';
import { A, B, C, CH, D, E, ManualClock } from './callKeys.testkit';
import type { VideoAudience, VideoFrameTicket } from './callKeys';
import {
  FRAG_PAYLOAD,
  encodeFragment,
  parseFragment,
  splitFrame,
  type EncodedScreenFrame,
  type FragmentHeader,
} from './screenFrame';
import {
  KEYFRAME_INTERVAL_MS,
  SEND_BUFFER_HIGH,
  ScreenShareSender,
  SentStops,
  VIDEO_BITRATE_FLOOR,
  bitrateStepDown,
  bitrateStepUp,
  displayMediaOptions,
  encoderConfig,
  probeCapture,
  probeViewing,
  scaledSize,
  videoBitrates,
  watchRejectedText,
  type ScreenNotice,
  type ScreenSenderKeys,
} from './screenShare';
import { FakeScreenPlatform, FakeScreenFrame, readMarker } from './screenShare.testkit';

const SELF = A;

/** Fake keys: an epoch that tests can suspend or invalidate, and plaintext "sealing". */
class FakeKeys implements ScreenSenderKeys {
  epoch: number | null = 0;
  invalidBelow = 0;
  vctr = 0;
  view = [B, C, D, E];
  recipients = new Set([B, C, D, E]);
  readonly sealed: EncodedScreenFrame[] = [];
  readonly tickets: VideoFrameTicket[] = [];

  beginVideoFrame(fragments: number): VideoFrameTicket | null {
    if (this.epoch === null) return null;
    const t: VideoFrameTicket = { epoch: this.epoch, firstVctr: this.vctr, count: fragments };
    this.vctr += fragments;
    this.tickets.push(t);
    return t;
  }

  async sealVideoFrame(t: VideoFrameTicket, frame: EncodedScreenFrame): Promise<Uint8Array[] | null> {
    await Promise.resolve();
    if (t.epoch < this.invalidBelow) return null;
    this.sealed.push(frame);
    const parts = splitFrame(frame.data);
    expect(parts.length).toBe(t.count);
    return parts.map((p, fragIndex) =>
      encodeFragment({ vcodec: 1, flags: frame.key ? 1 : 0, shareSeq: frame.shareSeq, frameNo: frame.frameNo, fragIndex, fragCount: parts.length, width: frame.width, height: frame.height }, p),
    );
  }

  mayHandOff(t: VideoFrameTicket): boolean {
    return t.epoch >= this.invalidBelow;
  }

  sendingEpoch(): number | null {
    return this.epoch;
  }

  videoAudience(): VideoAudience | null {
    return this.epoch === null ? null : { epoch: this.epoch, members: [...this.recipients], acknowledged: 0 };
  }

  participants(): string[] {
    return [...this.view];
  }

  isCurrentRecipient(u: string): boolean {
    return this.recipients.has(u);
  }
}

interface SentFragment {
  readonly header: FragmentHeader;
  readonly payloadLength: number;
  readonly at: number;
}

interface Env {
  clock: ManualClock;
  platform: FakeScreenPlatform;
  keys: FakeKeys;
  sender: ScreenShareSender;
  notices: ScreenNotice[];
  t: {
    open: boolean;
    buffered: number;
    /** Each handed-off fragment adds this many bytes to `buffered`. */
    grow: number;
    refuse: (i: number) => boolean;
    attempts: number;
    fragments: SentFragment[];
    messages: Array<{ type: 'start' | 'stop'; id: string; at: number }>;
  };
  lastStartId(): string;
  /** Click, capture, the relay's acknowledgment, one watcher. */
  start(): Promise<void>;
  /** One source frame, then `every` ms. */
  frames(n: number, opts?: { every?: number; w?: number; h?: number }): Promise<void>;
  advance(ms: number): Promise<void>;
}

async function flush(): Promise<void> {
  for (let i = 0; i < 6; i++) await new Promise<void>(r => setImmediate(r));
}

function senderEnv(opts: { limits?: { maxBytesPerSecond: number; maxSharers: number }; config?: 'A' | 'B'; source?: 'processor' | 'video' } = {}): Env {
  const clock = new ManualClock();
  const platform = new FakeScreenPlatform(7);
  platform.clock = clock;
  const keys = new FakeKeys();
  const notices: ScreenNotice[] = [];
  let seq = 0;
  const t: Env['t'] = { open: true, buffered: 0, grow: 0, refuse: () => false, attempts: 0, fragments: [], messages: [] };
  const rec = (type: 'start' | 'stop') => {
    if (!t.open) return { handedOff: false, messageId: '' };
    const id = `r${++seq}`;
    t.messages.push({ type, id, at: clock.now() });
    return { handedOff: true, messageId: id };
  };
  const sender = new ScreenShareSender({
    channelId: CH,
    selfId: SELF,
    platform,
    keys,
    clock,
    transport: {
      isOpen: () => t.open,
      bufferedAmount: () => t.buffered,
      sendScreenFragment: (_ch, f) => {
        const i = t.attempts++;
        if (!t.open || t.refuse(i)) return false;
        const p = parseFragment(f)!;
        t.fragments.push({ header: p.header, payloadLength: p.payload.length, at: clock.now() });
        if (t.grow) t.buffered += f.length + 17;
        return true;
      },
      screenShareStart: () => rec('start'),
      screenShareStop: () => rec('stop'),
    },
    probe: { ok: true, config: opts.config ?? 'A', source: opts.source ?? 'processor' },
    limits: () => opts.limits ?? { maxBytesPerSecond: 500_000, maxSharers: 2 },
    canStart: () => true,
    onNotice: n => notices.push(n),
  });
  const env: Env = {
    clock,
    platform,
    keys,
    sender,
    notices,
    t,
    lastStartId: () => [...t.messages].reverse().find(m => m.type === 'start')!.id,
    async start() {
      expect(sender.startFromClick()).toBe(true);
      await flush();
      sender.onShareStarted(SELF, env.lastStartId());
      sender.onWatchers(1);
      await flush();
    },
    async frames(n, o = {}) {
      for (let i = 0; i < n; i++) {
        platform.source.push(o.w ?? 1280, o.h ?? 720);
        await flush();
        await clock.advance(o.every ?? 67, flush);
      }
    },
    advance: ms => clock.advance(ms, flush),
  };
  return env;
}

/** The largest number of `times` (ascending) inside any window [t, t + 1000 ms). */
function maxPerSecond(times: number[]): number {
  let max = 0;
  for (let i = 0, j = 0; i < times.length; i++) {
    while (times[i] - times[j] >= 1000) j++;
    max = Math.max(max, i - j + 1);
  }
  return max;
}

const keyTimes = (e: Env, from = -Infinity) => e.platform.enc.inputs.filter(i => i.keyFrame && i.at >= from).map(i => i.at);

// ---------------------------------------------------------------------------
// Probes and pure rules
// ---------------------------------------------------------------------------

describe('§6.13.1 probes (T-42, U part)', () => {
  it('the capture probe: shell, getDisplayMedia, configuration A or B at 1920 × 1080, a frame source', async () => {
    const p = new FakeScreenPlatform();
    expect(await probeCapture(p)).toEqual({ ok: true, config: 'A', source: 'processor' });
    // The macOS app: the shell says no, although getDisplayMedia is present.
    p.shell = false;
    expect(await probeCapture(p)).toEqual({ ok: false, reason: 'no_capture' });
    expect(p.shellCalls).toBe(1);
    p.shell = true;
    expect((await probeCapture(p)).ok).toBe(true);
    p.displayMedia = false;
    expect(await probeCapture(p)).toEqual({ ok: false, reason: 'no_capture' });
    p.displayMedia = true;
    p.encoder = 'missing';
    expect(await probeCapture(p)).toEqual({ ok: false, reason: 'no_encoder' });
    p.encoder = 'ok';
    p.encoderSupport = { A: false, B: false };
    expect(await probeCapture(p)).toEqual({ ok: false, reason: 'no_encoder' });
    // Configuration B only when A is rejected.
    p.encoderSupport = { A: false, B: true };
    expect(await probeCapture(p)).toEqual({ ok: true, config: 'B', source: 'processor' });
    p.encoderSupport = { A: true, B: false };
    expect(await probeCapture(p)).toEqual({ ok: true, config: 'A', source: 'processor' });
    const asked = p.encoderConfigsAsked;
    expect(asked.every(c => c.width === 1920 && c.height === 1080 && c.codec === 'vp8')).toBe(true);
    p.encoderSupport = { A: true, B: true };
    p.processor = false;
    expect(await probeCapture(p)).toEqual({ ok: true, config: 'A', source: 'video' });
    p.videoFrame = false;
    expect(await probeCapture(p)).toEqual({ ok: false, reason: 'no_frame_source' });
    // No probe ever calls getDisplayMedia.
    expect(p.displayMediaCalls).toHaveLength(0);
  });

  it('the viewing probe: VP8 at 1920 × 1080 with optimizeForLatency, retried without it, and a 2D canvas', async () => {
    const p = new FakeScreenPlatform();
    expect(await probeViewing(p)).toEqual({ ok: true, optimizeForLatency: true });
    p.decoder = 'rejects_option';
    expect(await probeViewing(p)).toEqual({ ok: true, optimizeForLatency: false });
    expect(p.decoderConfigsAsked.slice(-2)).toEqual([
      { codec: 'vp8', codedWidth: 1920, codedHeight: 1080, optimizeForLatency: true },
      { codec: 'vp8', codedWidth: 1920, codedHeight: 1080 },
    ]);
    p.decoder = 'unsupported';
    expect(await probeViewing(p)).toEqual({ ok: false });
    p.decoder = 'missing';
    expect(await probeViewing(p)).toEqual({ ok: false });
    p.decoder = 'ok';
    p.canvas = false;
    expect(await probeViewing(p)).toEqual({ ok: false });
  });
});

describe('§6.13 rules', () => {
  it('T-44 scaling: 3840 × 2160 → 1920 × 1080; 2560 × 1600 → 1820 × 1138; 1080 × 1920, 1366 × 768 unchanged; 5120 × 1440 → 1920 × 540', () => {
    expect(scaledSize(3840, 2160)).toEqual({ width: 1920, height: 1080 });
    expect(scaledSize(2560, 1600)).toEqual({ width: 1820, height: 1138 });
    expect(scaledSize(1080, 1920)).toEqual({ width: 1080, height: 1920 });
    expect(scaledSize(1366, 768)).toEqual({ width: 1366, height: 768 });
    expect(scaledSize(5120, 1440)).toEqual({ width: 1920, height: 540 });
    expect(scaledSize(8, 4)).toEqual({ width: 16, height: 16 });
    expect(scaledSize(0, 720)).toBeNull();
  });

  it('T-47 bitrates: 500,000 B/s gives 1,500,000 and 2,500,000; 200,000 B/s gives 960,000 and 1,280,000', () => {
    expect(videoBitrates(500_000)).toEqual({ target: 1_500_000, maximum: 2_500_000 });
    expect(videoBitrates(200_000)).toEqual({ target: 960_000, maximum: 1_280_000 });
    expect(videoBitrates(10_000_000)).toEqual({ target: 1_500_000, maximum: 2_500_000 });
  });

  it('§8.4 "Couldn\'t start watching ([reason])": the relay\'s reasons, and any other relay-supplied reason shown as it is', () => {
    expect(watchRejectedText('watch_limit')).toBe("Couldn't start watching (watching too many screens).");
    expect(watchRejectedText('not_sharing')).toBe("Couldn't start watching (no longer sharing).");
    for (const reason of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueof', 'error']) {
      expect(watchRejectedText(reason), reason).toBe(`Couldn't start watching (${reason}).`);
    }
  });

  it('§6.13.2 and §6.13.4: the capture options and configurations A and B', () => {
    expect(displayMediaOptions()).toEqual({ video: { width: { max: 1920 }, height: { max: 1920 }, frameRate: { max: 15 } }, audio: false });
    expect(encoderConfig('A', 1280, 720, 1_500_000)).toEqual({ codec: 'vp8', width: 1280, height: 720, bitrate: 1_500_000, framerate: 15, latencyMode: 'realtime' });
    expect(encoderConfig('B', 1280, 720, 1_500_000)).toEqual({ codec: 'vp8', width: 1280, height: 720, bitrate: 1_500_000, framerate: 15 });
  });
});

// ---------------------------------------------------------------------------
// T-43 (U part) and T-52 (U)
// ---------------------------------------------------------------------------

describe('T-43 (REQ-43) capture, U part', () => {
  it('getDisplayMedia is called inside startFromClick with exactly the options of §6.13.2; audio is stopped; contentHint is "detail"', async () => {
    const e = senderEnv();
    e.platform.capture = { audio: true };
    e.sender.startFromClick();
    // Synchronously, before any microtask ran.
    expect(e.platform.displayMediaCalls).toEqual([displayMediaOptions()]);
    expect(e.sender.isPicking).toBe(true);
    await flush();
    const stream = e.platform.stream;
    const audio = stream.getAudioTracks()[0];
    expect(audio.stopped).toBe(true);
    expect(audio.reads).toBe(0);
    expect(stream.getVideoTracks()[0].reads).toBe(1); // the frame source reads the video track only
    expect(stream.getVideoTracks()[0].contentHint).toBe('detail');
    expect(stream.getVideoTracks()[0].stopped).toBe(false);
    expect(e.sender.state).toBe('starting');
  });

  it('each capture error maps to its §8.4 message, leaves the share idle and sends no ScreenShareStart', async () => {
    for (const [name, code] of [
      ['NotAllowedError', 'cancelled'],
      ['NotFoundError', 'capture_failed'],
      ['NotReadableError', 'capture_failed'],
      ['NotSupportedError', 'capture_failed'],
      ['AbortError', 'capture_failed'],
      ['TypeError', 'capture_failed'],
      ['InvalidStateError', 'capture_failed'],
    ] as const) {
      const e = senderEnv();
      e.platform.capture = { error: name };
      e.sender.startFromClick();
      await flush();
      expect(e.notices, name).toEqual([{ code }]);
      expect(e.sender.state).toBe('idle');
      expect(e.sender.isPicking).toBe(false);
      expect(e.t.messages).toHaveLength(0);
    }
    // A stream without a video track is a capture failure too.
    const e = senderEnv();
    e.platform.capture = { noVideo: true, audio: true };
    e.sender.startFromClick();
    await flush();
    expect(e.notices).toEqual([{ code: 'capture_failed' }]);
    expect(e.platform.stream.allStopped).toBe(true);
    expect(e.t.messages).toHaveLength(0);
  });
});

describe('T-52 (REQ-52) share lifecycle, U', () => {
  it('starting → sharing only on the answer with the outstanding request_id, with share_seq incremented', async () => {
    const e = senderEnv();
    e.sender.startFromClick();
    await flush();
    expect(e.sender.state).toBe('starting');
    const id = e.lastStartId();
    // Answers with another request_id are not the answer, and (A2, §14.3) are ignored while
    // starting: no ScreenShareStop, which would end the share being started.
    e.sender.onShareStarted(SELF, 'other');
    e.sender.onShareStarted(SELF, undefined);
    e.sender.onShareRejected('other', 'limit');
    expect(e.sender.state).toBe('starting');
    expect(e.notices).toEqual([]);
    expect(e.t.messages.map(m => m.type)).toEqual(['start']);
    e.sender.onShareStarted(B, id); // another user's share
    expect(e.sender.state).toBe('starting');
    e.sender.onShareStarted(SELF, id);
    expect(e.sender.state).toBe('sharing');
    expect(e.sender.snapshot().shareSeq).toBe(1);
    // Ignored while sharing too, whatever its request_id.
    for (const stray of ['other', id, undefined]) e.sender.onShareStarted(SELF, stray);
    await e.advance(2000);
    expect(e.sender.state).toBe('sharing');
    expect(e.t.messages.map(m => m.type)).toEqual(['start']);
  });

  it('a rejection and a 10 s silence each stop the capture and show their messages; only the timeout sends ScreenShareStop', async () => {
    const e = senderEnv({ limits: { maxBytesPerSecond: 500_000, maxSharers: 2 } });
    e.sender.startFromClick();
    await flush();
    e.sender.onShareRejected(e.lastStartId(), 'limit');
    expect(e.sender.state).toBe('idle');
    expect(e.platform.stream.allStopped).toBe(true);
    expect(e.notices).toEqual([{ code: 'rejected_limit', limit: 2 }]);
    expect(e.t.messages.map(m => m.type)).toEqual(['start']);

    for (const reason of ['disabled', 'not_participant', 'rate_limited']) {
      const r = senderEnv();
      r.sender.startFromClick();
      await flush();
      r.sender.onShareRejected(r.lastStartId(), reason);
      expect(r.notices).toEqual([{ code: 'relay_didnt_start' }]);
    }

    const t = senderEnv();
    t.sender.startFromClick();
    await flush();
    await t.advance(9_999);
    expect(t.sender.state).toBe('starting');
    await t.advance(1);
    expect(t.sender.state).toBe('idle');
    expect(t.platform.stream.allStopped).toBe(true);
    expect(t.notices).toEqual([{ code: 'relay_didnt_start' }]);
    expect(t.t.messages.map(m => m.type)).toEqual(['start', 'stop']);
    // A late acknowledgment is answered with ScreenShareStop and changes nothing else.
    t.sender.onShareStarted(SELF, t.t.messages[0].id);
    expect(t.sender.state).toBe('idle');
    expect(t.t.messages.map(m => m.type)).toEqual(['start', 'stop', 'stop']);
    expect(t.platform.encoders).toHaveLength(0);
  });

  it('Cancel while starting sends ScreenShareStop; a later acknowledgment is answered with another stop', async () => {
    const e = senderEnv();
    e.sender.startFromClick();
    await flush();
    const id = e.lastStartId();
    e.sender.stopFromUser();
    expect(e.sender.state).toBe('idle');
    expect(e.platform.stream.allStopped).toBe(true);
    expect(e.t.messages.map(m => m.type)).toEqual(['start', 'stop']);
    e.sender.onShareStarted(SELF, id);
    expect(e.sender.state).toBe('idle');
    expect(e.t.messages.map(m => m.type)).toEqual(['start', 'stop', 'stop']);
    expect(e.notices).toEqual([]);
  });

  it('Cancel while the picker is open stops the stream as soon as it arrives, and sends nothing', async () => {
    const e = senderEnv();
    e.platform.capture = { manual: true };
    e.sender.startFromClick();
    expect(e.sender.isPicking).toBe(true);
    e.sender.stopFromUser();
    expect(e.sender.isPicking).toBe(false);
    e.platform.resolveCapture();
    await flush();
    expect(e.platform.stream.allStopped).toBe(true);
    expect(e.t.messages).toEqual([]);
    expect(e.sender.state).toBe('idle');
  });

  it('a stop the client sent is only confirmed; a stop it did not send ends the share with "stopped by the relay"', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(3);
    e.sender.stopFromUser();
    const stopId = e.t.messages[e.t.messages.length - 1].id;
    e.sender.onShareStopped(SELF, stopId);
    expect(e.notices).toEqual([]);

    const r = senderEnv();
    await r.start();
    r.sender.onShareStopped(B, undefined); // someone else's share
    expect(r.sender.state).toBe('sharing');
    r.sender.onShareStopped(SELF, 'not-ours');
    expect(r.sender.state).toBe('idle');
    expect(r.notices).toEqual([{ code: 'stopped_by_relay' }]);
  });

  it('every stop condition stops all tracks and the encoder, and sends ScreenShareStop exactly when starting or sharing with the socket open', async () => {
    type Stop = (e: Env) => void;
    const conditions: Array<[string, Stop]> = [
      ['the user stops', e => e.sender.stopFromUser()],
      ['the platform control (track ended)', e => e.platform.stream.getVideoTracks()[0].end()],
      ['the encoder fails', e => e.platform.enc.fail()],
      ['the relay stops it', e => e.sender.onShareStopped(SELF, undefined)],
      ['the self-check does not list it', e => e.sender.onNotListedAsSharer()],
      ['the call ends (leave, eviction, rejoin, channel switch, unmount)', e => e.sender.end()],
    ];
    for (const [name, stop] of conditions) {
      for (const open of [true, false]) {
        const e = senderEnv();
        await e.start();
        await e.frames(2);
        e.t.open = open;
        stop(e);
        expect(e.sender.state, name).toBe('idle');
        expect(e.platform.stream.allStopped, name).toBe(true);
        expect(e.platform.enc.state, name).toBe('closed');
        expect(e.platform.source.closed, name).toBe(true);
        const stops = e.t.messages.filter(m => m.type === 'stop').length;
        expect(stops, `${name}, socket ${open ? 'open' : 'closed'}`).toBe(open ? 1 : 0);
        // Every video frame was closed: the kept copy too (REQ-27).
        expect(e.platform.frames.open.size, name).toBe(0);
      }
    }
    // Ending the call while idle sends nothing.
    const idle = senderEnv();
    idle.sender.end();
    expect(idle.t.messages).toEqual([]);
    // The encoder error shows its message (§8.4).
    const err = senderEnv();
    await err.start();
    await err.frames(1);
    err.platform.enc.fail();
    expect(err.notices).toEqual([{ code: 'encoder_failed' }]);
  });

  it('a frame source that cannot be opened, or that fails while starting or sharing, ends the attempt with "Couldn\'t capture your screen"', async () => {
    // It cannot be opened: no ScreenShareStart at all.
    const e = senderEnv();
    e.platform.sourceThrows = true;
    e.sender.startFromClick();
    await flush();
    expect(e.notices).toEqual([{ code: 'capture_failed' }]);
    expect(e.sender.state).toBe('idle');
    expect(e.platform.stream.allStopped).toBe(true);
    expect(e.t.messages).toEqual([]);
    // It fails while starting: the start is withdrawn with a stop.
    const s = senderEnv();
    s.sender.startFromClick();
    await flush();
    expect(s.sender.state).toBe('starting');
    s.platform.source.fail();
    expect(s.sender.state).toBe('idle');
    expect(s.notices).toEqual([{ code: 'capture_failed' }]);
    expect(s.platform.stream.allStopped).toBe(true);
    expect(s.t.messages.map(m => m.type)).toEqual(['start', 'stop']);
    // It fails while sharing: the share ends at once instead of sending nothing.
    const r = senderEnv();
    await r.start();
    await r.frames(3);
    expect(r.t.fragments.length).toBeGreaterThan(0);
    r.platform.source.fail();
    expect(r.sender.state).toBe('idle');
    expect(r.notices).toEqual([{ code: 'capture_failed' }]);
    expect(r.platform.stream.allStopped).toBe(true);
    expect(r.platform.enc.state).toBe('closed');
    expect(r.platform.frames.open.size).toBe(0);
    expect(r.t.messages.filter(m => m.type === 'stop')).toHaveLength(1);
    // A failure reported after the share ended changes nothing.
    r.platform.sources[0].fail();
    expect(r.notices).toHaveLength(1);
  });

  it('stray acknowledgments while idle are answered with at most one ScreenShareStop per second, and only the newest 8 stop ids are kept', async () => {
    const e = senderEnv();
    const stops = () => e.t.messages.filter(m => m.type === 'stop');
    for (let i = 0; i < 10; i++) e.sender.onShareStarted(SELF, `stray-${i}`);
    expect(stops()).toHaveLength(1);
    await e.advance(999);
    e.sender.onShareStarted(SELF, 'stray-a');
    expect(stops()).toHaveLength(1);
    await e.advance(1);
    e.sender.onShareStarted(SELF, 'stray-b');
    expect(stops()).toHaveLength(2);
    for (let i = 0; i < 20; i++) {
      await e.advance(1000);
      e.sender.onShareStarted(SELF, `stray-c${i}`);
    }
    expect(stops()).toHaveLength(22);
    const kept = (e.sender as unknown as { sentStops: SentStops }).sentStops;
    expect(kept.recorded()).toEqual(stops().slice(-8).map(m => m.id));
    // The newest stop's late confirmation only confirms it, also during a new start.
    e.sender.startFromClick();
    await flush();
    expect(e.sender.state).toBe('starting');
    e.sender.onShareStopped(SELF, stops()[stops().length - 1].id);
    expect(e.sender.state).toBe('starting');
    expect(e.notices).toEqual([]);
  });

  it('REQ-54: the audience is R_e of the sealing epoch, kept while sending is briefly suspended for the next epoch', async () => {
    const e = senderEnv();
    await e.start();
    expect(e.sender.snapshot().audience?.members).toEqual([B, C, D, E]);
    e.keys.epoch = null; // suspended until the next epoch is ready
    expect(e.sender.snapshot().audience?.members).toEqual([B, C, D, E]);
    e.keys.epoch = 1;
    e.keys.recipients = new Set([B, C]);
    expect(e.sender.snapshot().audience).toEqual({ epoch: 1, members: [B, C], acknowledged: 0 });
    e.keys.recipients = new Set();
    expect(e.sender.snapshot().audience?.members).toEqual([]);
  });

  it('a rotation does not end the share; its first frame under the new epoch is a keyframe', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(3);
    e.keys.epoch = 1;
    e.sender.onEpochSwitch();
    await e.frames(2);
    expect(e.sender.state).toBe('sharing');
    const after = e.keys.sealed.filter((_, i) => e.keys.tickets[i].epoch === 1);
    expect(after[0].key).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// T-44 (REQ-44)
// ---------------------------------------------------------------------------

describe('T-44 (REQ-44) frames, encoding and keyframes', () => {
  it('a 30 fps source gives at most 150 encoded frames in 10 s, never two less than 46.7 ms apart', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(300, { every: 1000 / 30 });
    const times = e.platform.enc.inputs.map(i => i.at);
    expect(times.length).toBeLessThanOrEqual(150);
    expect(times.length).toBeGreaterThanOrEqual(140);
    for (let i = 1; i < times.length; i++) expect(times[i] - times[i - 1]).toBeGreaterThanOrEqual(46.7 - 1e-9);
    // Frames that were not encoded were closed: only the kept copy is open.
    expect(e.platform.frames.open.size).toBe(1);
  });

  it('a 15 fps source with ±8 ms arrival jitter gives at least 14 encoded frames per second', async () => {
    const e = senderEnv();
    await e.start();
    const start = e.clock.now();
    let seed = 7;
    const jitter = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return (seed % 17) - 8;
    };
    let t = 0;
    for (let k = 0; k < 150; k++) {
      const due = start + k * (1000 / 15) + jitter();
      await e.clock.advance(Math.max(0, due - e.clock.now()), flush);
      e.platform.source.push(1280, 720);
      await flush();
      t = e.clock.now();
    }
    const n = e.platform.enc.inputs.length;
    expect(n / ((t - start) / 1000)).toBeGreaterThanOrEqual(14);
  });

  it('a size change reconfigures the encoder and the next output is a key; changes every 100 ms reconfigure at most once per 2 s, scaling to the current size in between', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(3, { w: 3840, h: 2160 });
    expect(e.platform.enc.configs.map(c => [c.width, c.height])).toEqual([[1920, 1080]]);
    expect(e.platform.scaled.every(s => s.to[0] === 1920 && s.to[1] === 1080)).toBe(true);
    await e.advance(2000);
    await e.frames(1, { w: 1366, h: 768 });
    expect(e.platform.enc.configs.map(c => [c.width, c.height])).toEqual([[1920, 1080], [1366, 768]]);
    const last = e.platform.enc.inputs[e.platform.enc.inputs.length - 1];
    expect(last.keyFrame).toBe(true);
    // Every 100 ms another size, for 6 s.
    const before = e.platform.enc.configs.length;
    const configAt: number[] = [];
    const sizes = [[2560, 1600], [1366, 768], [5120, 1440], [1080, 1920]] as const;
    for (let i = 0; i < 60; i++) {
      const [w, h] = sizes[i % sizes.length];
      const n = e.platform.enc.configs.length;
      await e.frames(1, { w, h, every: 100 });
      if (e.platform.enc.configs.length > n) configAt.push(e.clock.now());
    }
    const added = e.platform.enc.configs.length - before;
    expect(added).toBeGreaterThan(0);
    expect(added).toBeLessThanOrEqual(4);
    for (let i = 1; i < configAt.length; i++) expect(configAt[i] - configAt[i - 1]).toBeGreaterThanOrEqual(2000);
    // The fake encoder throws on a frame of another size than configured: none did.
    expect(e.sender.state).toBe('sharing');
  });

  it('a keyframe for the first frame, after a reconfiguration, an epoch switch and a discard, and every 10 s', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(3);
    const inputs = () => e.platform.enc.inputs;
    expect(inputs()[0].keyFrame).toBe(true);
    expect(inputs().slice(1).every(i => !i.keyFrame)).toBe(true);
    // Epoch switch.
    e.sender.onEpochSwitch();
    await e.frames(2);
    expect(inputs().slice(-2).map(i => i.keyFrame)).toEqual([true, false]);
    // Discard: an output above 1,024,000 bytes.
    const n = inputs().length;
    e.platform.outputSize = o => (o.seq === n + 1 ? 1_024_001 : o.key ? 4000 : 600);
    await e.frames(2);
    expect(inputs().slice(-2).map(i => i.keyFrame)).toEqual([false, true]);
    expect(e.keys.sealed.some(f => f.data.length === 1_024_001)).toBe(false);
    // Reconfiguration (a bitrate change counts too, REQ-47) — here a size change.
    await e.advance(2000);
    await e.frames(2, { w: 1024, h: 768 });
    expect(inputs().slice(-2).map(i => i.keyFrame)).toEqual([true, false]);
    // Every 10 s.
    const t0 = inputs().filter(i => i.keyFrame)!.slice(-1)[0].at;
    await e.frames(320);
    const keys = keyTimes(e, t0);
    expect(keys.length).toBeGreaterThanOrEqual(3);
    for (let i = 1; i < keys.length; i++) expect(keys[i] - keys[i - 1]).toBeLessThanOrEqual(KEYFRAME_INTERVAL_MS + 67);
  });

  it('a static screen: the kept copy is encoded as a key every 10 s and closed', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(3);
    const lastPicture = e.platform.source.push(1280, 720).picture;
    await flush();
    const n = e.platform.enc.inputs.length;
    await e.advance(25_000);
    const fromCopy = e.platform.enc.inputs.slice(n);
    expect(fromCopy.length).toBe(2);
    expect(fromCopy.every(i => i.keyFrame && i.picture === lastPicture)).toBe(true);
    // Only the kept copy itself stays open.
    expect(e.platform.frames.open.size).toBe(1);
    expect([...e.platform.frames.open][0].picture).toBe(lastPicture);
  });

  it('with a stopped source, a key from the kept copy within 200 ms of a watcher count rising from 0, a request acted on, and an epoch switch', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(5);
    // The copy is replaced on every source frame, also while the count is 0; the previous copy is closed.
    e.sender.onWatchers(0);
    let last: FakeScreenFrame | null = null;
    for (let i = 0; i < 3; i++) {
      last = e.platform.source.push(1280, 720);
      await flush();
      await e.advance(67);
    }
    expect(e.platform.frames.open.size).toBe(1);
    expect([...e.platform.frames.open][0].picture).toBe(last!.picture);
    expect(last!.closed).toBe(true);
    await e.advance(2000);
    for (const [name, trigger] of [
      ['watchers 0 → 1', () => e.sender.onWatchers(1)],
      ['a request acted on', () => e.sender.onKeyframeRequest(B)],
      ['an epoch switch', () => e.sender.onEpochSwitch()],
    ] as const) {
      await e.advance(1500);
      const at = e.clock.now();
      trigger();
      await e.advance(200);
      const k = keyTimes(e, at);
      expect(k.length, name).toBe(1);
      expect(k[0] - at, name).toBeLessThanOrEqual(200);
    }
  });

  it('relay-driven triggers are coalesced to one keyframe per second; an epoch switch and a reconfiguration still give one at once', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(20);
    const t0 = e.clock.now();
    // 5 s of a watcher count toggling every 50 ms, plus requests from B and C every 100 ms.
    let on = true;
    for (let i = 0; i < 100; i++) {
      on = !on;
      e.sender.onWatchers(on ? 1 : 0);
      if (i % 2 === 0) e.sender.onKeyframeRequest(i % 4 === 0 ? B : C);
      if (i % 4 === 0) e.platform.source.push(1280, 720);
      await flush();
      await e.advance(50);
    }
    e.sender.onWatchers(1);
    await e.frames(5);
    const storm = keyTimes(e, t0);
    expect(storm.length).toBeGreaterThan(0);
    expect(maxPerSecond(storm)).toBeLessThanOrEqual(1);
    // An epoch switch right after a keyframe: a key at once.
    await e.frames(1);
    const lastKey = keyTimes(e)!.slice(-1)[0];
    expect(e.clock.now() - lastKey).toBeLessThan(1000);
    e.sender.onEpochSwitch();
    await e.frames(1);
    expect(e.platform.enc.inputs!.slice(-1)[0].keyFrame).toBe(true);
    // And a reconfiguration.
    await e.advance(2000);
    await e.frames(1, { w: 1600, h: 900 });
    expect(e.platform.enc.inputs!.slice(-1)[0].keyFrame).toBe(true);
  });

  it('after an epoch switch or a discard, delta outputs are discarded until a key output', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(3);
    const sealed = () => e.keys.sealed.length;
    // A delta encoded before the switch comes out after it.
    e.platform.enc.hold = true;
    e.platform.source.push(1280, 720);
    await flush();
    expect(e.platform.enc.inputs!.slice(-1)[0].keyFrame).toBe(false);
    const n = sealed();
    e.sender.onEpochSwitch();
    e.platform.enc.hold = false;
    e.platform.enc.release();
    await flush();
    expect(sealed()).toBe(n); // the delta was dropped
    await e.advance(67);
    await e.frames(2);
    expect(e.keys.sealed.slice(n).map(f => f.key)).toEqual([true, false]);
    // A discard: the second of three fragments is not handed off; a delta already encoded is dropped.
    e.platform.outputSize = o => (o.key ? 4000 : 40_000);
    const i0 = e.t.attempts;
    e.t.refuse = i => i === i0 + 1;
    const m = sealed();
    await e.frames(1);
    e.t.refuse = () => false;
    e.platform.enc.hold = true;
    e.platform.source.push(1280, 720); // waits behind nothing: the frame was discarded
    await flush();
    e.platform.enc.hold = false;
    e.platform.enc.release();
    await flush();
    await e.advance(67);
    await e.frames(1);
    const after = e.keys.sealed.slice(m + 1);
    expect(after[0].key).toBe(true);
  });

  it('every configuration is checked with isConfigSupported before configure: the scaled sizes and the relay-derived and halved bitrates', async () => {
    const e = senderEnv({ limits: { maxBytesPerSecond: 200_000, maxSharers: 2 } });
    await e.start();
    const enc = e.platform.enc;
    const asked = e.platform.encoderConfigsAsked;
    const unchecked: unknown[] = [];
    const configure = enc.configure.bind(enc);
    enc.configure = c => {
      if (!asked.some(a => JSON.stringify(a) === JSON.stringify(c))) unchecked.push(c);
      configure(c);
    };
    await e.frames(3, { w: 2560, h: 1600 });
    await e.advance(2000);
    await e.frames(3, { w: 5120, h: 1440 });
    e.t.buffered = SEND_BUFFER_HIGH + 1;
    await e.frames(16, { w: 5120, h: 1440 });
    e.t.buffered = 0;
    await e.frames(170, { w: 5120, h: 1440 });
    expect(enc.configs.map(c => [c.width, c.height, c.bitrate])).toEqual([
      [1820, 1138, 960_000],
      [1920, 540, 960_000],
      [1920, 540, 480_000],
      [1920, 540, 960_000],
    ]);
    expect(unchecked).toEqual([]);
    expect(e.sender.state).toBe('sharing');
  });

  it('while the check runs, input frames are closed; then the newest is encoded as the keyframe; configuration B is used where A is rejected', async () => {
    const e = senderEnv();
    let release: (ok: boolean) => void = () => undefined;
    e.platform.configSupport = c => (c.width === 1280 ? new Promise<boolean>(r => { release = r; }) : true);
    await e.start();
    const pushed = [e.platform.source.push(1280, 720), e.platform.source.push(1280, 720), e.platform.source.push(1280, 720)];
    await flush();
    expect(pushed.every(f => f.closed)).toBe(true);
    expect(e.platform.enc.configs).toEqual([]);
    expect(e.platform.enc.inputs).toEqual([]);
    release(true);
    await flush();
    expect(e.platform.enc.configs).toHaveLength(1);
    expect(e.platform.enc.inputs.map(i => [i.picture, i.keyFrame])).toEqual([[pushed[2].picture, true]]);
    // A rejected at the real size, B accepted: B, without latencyMode.
    const b = senderEnv();
    b.platform.configSupport = c => c.latencyMode !== 'realtime' || c.width !== 1820;
    await b.start();
    await b.frames(2, { w: 2560, h: 1600 });
    expect(b.platform.enc.configs).toEqual([encoderConfig('B', 1820, 1138, 1_500_000)]);
    expect(b.sender.state).toBe('sharing');
  });

  it('a configuration isConfigSupported rejects ends the share as an encoder failure without configure', async () => {
    const e = senderEnv();
    e.platform.configSupport = c => !(c.width === 1920 && c.height === 540);
    await e.start();
    await e.frames(3);
    expect(e.platform.enc.configs).toHaveLength(1);
    await e.advance(2000);
    await e.frames(1, { w: 5120, h: 1440 });
    expect(e.sender.state).toBe('idle');
    expect(e.notices).toEqual([{ code: 'encoder_failed' }]);
    expect(e.platform.enc.configs.map(c => [c.width, c.height])).toEqual([[1280, 720]]);
    expect(e.platform.enc.state).toBe('closed');
    expect(e.platform.stream.allStopped).toBe(true);
    expect(e.t.messages.filter(m => m.type === 'stop')).toHaveLength(1);
    expect(e.platform.frames.open.size).toBe(0);
  });

  it('an input frame is closed unencoded while encodeQueueSize is 3', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(2);
    const n = e.platform.enc.inputs.length;
    e.platform.enc.forcedQueueSize = 3;
    const f = e.platform.source.push(1280, 720);
    await flush();
    expect(e.platform.enc.inputs.length).toBe(n);
    expect(f.closed).toBe(true);
    e.platform.enc.forcedQueueSize = 2;
    await e.advance(67);
    await e.frames(1);
    expect(e.platform.enc.inputs.length).toBe(n + 1);
  });
});

// ---------------------------------------------------------------------------
// T-46 (REQ-46): the sender's numbering and hand-off
// ---------------------------------------------------------------------------

describe('T-46 (REQ-46) fragments and numbering at the sender', () => {
  it('16,000; 16,001; 32,000; 32,001 and 1,024,000 bytes leave as 1, 2, 2, 3 and 64 fragments, in index order, with one header, consecutive VCTRs and the key flag', async () => {
    const e = senderEnv();
    const sizes = [16_000, 16_001, 32_000, 32_001, 1_024_000];
    e.platform.outputSize = o => sizes[o.seq - 1] ?? 600;
    await e.start();
    await e.frames(5);
    expect(e.keys.tickets.map(t => t.count)).toEqual([1, 2, 2, 3, 64]);
    for (let i = 1; i < e.keys.tickets.length; i++) {
      expect(e.keys.tickets[i].firstVctr).toBe(e.keys.tickets[i - 1].firstVctr + e.keys.tickets[i - 1].count);
    }
    const byFrame = new Map<number, SentFragment[]>();
    for (const f of e.t.fragments) byFrame.set(f.header.frameNo, [...(byFrame.get(f.header.frameNo) ?? []), f]);
    expect([...byFrame.keys()]).toEqual([0, 1, 2, 3, 4]);
    for (const [no, frags] of byFrame) {
      const sealed = e.keys.sealed[no];
      expect(frags.map(f => f.header.fragIndex)).toEqual(frags.map((_, i) => i));
      for (const f of frags) {
        expect({ ...f.header, fragIndex: 0 }).toEqual({ ...frags[0].header, fragIndex: 0 });
        expect(f.header.flags).toBe(sealed.key ? 1 : 0);
      }
      for (const f of frags.slice(0, -1)) expect(f.payloadLength).toBe(FRAG_PAYLOAD);
    }
    // The order on the wire: every fragment of a frame before the next frame's.
    const nos = e.t.fragments.map(f => f.header.frameNo);
    expect(nos).toEqual([...nos].sort((a, b) => a - b));
  });

  it('share_seq is 1 then 2; frame_no counts only frames with a handed-off fragment', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(2);
    // The first fragment of the third frame is not handed off: it keeps frame_no 2 for the next.
    const i0 = e.t.attempts;
    e.t.refuse = i => i === i0;
    await e.frames(1);
    e.t.refuse = () => false;
    await e.frames(2);
    expect(e.keys.sealed.map(f => f.frameNo)).toEqual([0, 1, 2, 2, 3]);
    expect(e.t.fragments.map(f => f.header.frameNo)).toEqual([0, 1, 2, 3]);
    // A frame that lost its second of two fragments still counts.
    e.platform.outputSize = o => (o.key ? 4000 : 20_000);
    const i1 = e.t.attempts;
    e.t.refuse = i => i === i1 + 1;
    await e.frames(1);
    e.t.refuse = () => false;
    await e.frames(1);
    expect(e.keys.sealed.slice(-2).map(f => f.frameNo)).toEqual([4, 5]);
    expect(e.keys.sealed.every(f => f.shareSeq === 1)).toBe(true);
    // A second share.
    e.sender.stopFromUser();
    await e.start();
    await e.frames(2);
    expect(e.keys.sealed.slice(-2).map(f => [f.shareSeq, f.frameNo])).toEqual([[2, 0], [2, 1]]);
  });
});

// ---------------------------------------------------------------------------
// T-47 (REQ-47) U
// ---------------------------------------------------------------------------

describe('T-47 (REQ-47) sending, U', () => {
  it('no fragment before screen_share_started, before a watcher count above 0, or while sending is suspended', async () => {
    const e = senderEnv();
    e.sender.startFromClick();
    await flush();
    await e.frames(3);
    expect(e.platform.encoders).toHaveLength(0);
    e.sender.onShareStarted(SELF, e.lastStartId());
    await e.frames(3); // the count is 0 until the first screen_watchers
    e.sender.onWatchers(0);
    await e.frames(3);
    expect(e.platform.enc.inputs).toHaveLength(0);
    e.keys.epoch = null; // no current epoch key, or suspended
    e.sender.onWatchers(1);
    await e.frames(3);
    expect(e.platform.enc.inputs).toHaveLength(0);
    expect(e.t.fragments).toHaveLength(0);
    e.keys.epoch = 0;
    await e.frames(2);
    expect(e.t.fragments.length).toBeGreaterThan(0);
    // A departure while a 3-fragment frame waits: sending is suspended and
    // nothing under the old epoch is handed off (REQ-17), not even the rest.
    e.platform.outputSize = () => 40_000;
    e.t.buffered = SEND_BUFFER_HIGH + 1;
    await e.frames(1);
    e.t.buffered = SEND_BUFFER_HIGH + 1;
    const n = e.t.fragments.length;
    e.keys.invalidBelow = 1;
    e.keys.epoch = null;
    e.t.buffered = 0;
    await e.frames(3);
    expect(e.t.fragments.length).toBe(n);
    // The next epoch: its first frame is a key.
    e.keys.epoch = 1;
    e.sender.onEpochSwitch();
    await e.frames(1);
    expect(e.t.fragments.length).toBeGreaterThan(n);
    expect(e.t.fragments[n].header.flags).toBe(1);
  });

  it('with bufferedAmount above 65,536 or fragments waiting, frames are closed unencoded and no keyframe is forced; fragments go one by one, checked every 20 ms', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(3);
    const inputs = e.platform.enc.inputs.length;
    e.t.buffered = 65_537;
    const skipped = e.platform.source.push(1280, 720);
    await flush();
    expect(skipped.closed).toBe(true);
    expect(e.platform.enc.inputs.length).toBe(inputs);
    e.t.buffered = 65_536;
    await e.advance(67);
    await e.frames(1);
    expect(e.platform.enc.inputs!.slice(-1)[0].keyFrame).toBe(false); // skipping keeps the chain
    // A 3-fragment frame, encoded while the buffer was low, waits behind a full one.
    e.platform.outputSize = () => 40_000;
    e.platform.enc.hold = true;
    const n = e.t.fragments.length;
    await e.advance(67);
    e.platform.source.push(1280, 720);
    await flush();
    e.t.buffered = 70_000;
    e.platform.enc.hold = false;
    e.platform.enc.release();
    await flush();
    expect(e.t.fragments.length).toBe(n);
    await e.advance(20);
    expect(e.t.fragments.length).toBe(n);
    // While fragments wait, source frames are not encoded either.
    const k = e.platform.enc.inputs.length;
    await e.advance(67);
    e.platform.source.push(1280, 720);
    await flush();
    expect(e.platform.enc.inputs.length).toBe(k);
    e.t.buffered = SEND_BUFFER_HIGH;
    e.t.grow = 1;
    const at = e.clock.now();
    await e.advance(20);
    expect(e.t.fragments.length).toBe(n + 1); // one, then the buffer is above the mark again
    expect(e.t.fragments[n].at - at).toBeLessThanOrEqual(20);
    e.t.grow = 0;
    e.t.buffered = 0;
    await e.advance(20);
    expect(e.t.fragments.length).toBe(n + 3);
    expect(e.t.fragments.slice(n).map(f => f.header.fragIndex)).toEqual([0, 1, 2]);
  });

  it('when the second of three fragments is not handed off, the third is not sent and the next frame is a key', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(2);
    e.platform.outputSize = () => 40_000;
    const i0 = e.t.attempts;
    e.t.refuse = i => i === i0 + 1;
    const n = e.t.fragments.length;
    await e.frames(1);
    expect(e.t.fragments.slice(n).map(f => f.header.fragIndex)).toEqual([0]);
    e.t.refuse = () => false;
    await e.frames(1);
    expect(e.platform.enc.inputs!.slice(-1)[0].keyFrame).toBe(true);
  });

  it('A2 steps: target and maximum halve down to a 200,000 bit/s target and double back up to §6.13.4', () => {
    const full = videoBitrates(500_000);
    const downs = [full];
    for (let s = bitrateStepDown(full); s; s = bitrateStepDown(s)) downs.push(s);
    expect(downs).toEqual([
      { target: 1_500_000, maximum: 2_500_000 },
      { target: 750_000, maximum: 1_250_000 },
      { target: 375_000, maximum: 625_000 },
      { target: VIDEO_BITRATE_FLOOR, maximum: 312_500 },
    ]);
    const ups = [downs[downs.length - 1]];
    for (let s = bitrateStepUp(ups[0], full); s; s = bitrateStepUp(s, full)) ups.push(s);
    expect(ups.map(s => s.target)).toEqual([200_000, 400_000, 800_000, 1_500_000]);
    expect(ups[ups.length - 1]).toEqual(full);
    // The lowest relay rate: 960,000 and 1,280,000 down to the floor and back.
    const low = videoBitrates(200_000);
    expect(bitrateStepDown(low)).toEqual({ target: 480_000, maximum: 640_000 });
    expect(bitrateStepDown(bitrateStepDown(bitrateStepDown(low)!)!)).toEqual({ target: 200_000, maximum: 200_000 });
    expect(bitrateStepDown({ target: 200_000, maximum: 200_000 })).toBeNull();
    expect(bitrateStepUp({ target: 800_000, maximum: 800_000 }, low)).toEqual(low);
  });

  /**
   * REQ-47 as amended by A2 (§14.2): more than 15 skips within 10 s halve the
   * target and the maximum; each further 10 s with more than 15 skips halves
   * them again, down to a 200,000 bit/s target; each 10 s without a skip
   * doubles them, up to §6.13.4's values, which are never exceeded.
   */
  it('more than 15 skips in 10 s halve the bitrate, each further 10 s of skips halves it again down to 200,000, and each 10 s without a skip doubles it back up', async () => {
    const cases = [
      { rate: 500_000, down: [1_500_000, 750_000, 375_000, 200_000], up: [400_000, 800_000, 1_500_000], maximum: 2_500_000 },
      { rate: 200_000, down: [960_000, 480_000, 240_000, 200_000], up: [400_000, 800_000, 960_000], maximum: 1_280_000 },
    ];
    for (const c of cases) {
      const e = senderEnv({ limits: { maxBytesPerSecond: c.rate, maxSharers: 2 } });
      await e.start();
      const log: Array<{ at: number; bitrate: number }> = [];
      const enc = e.platform.enc;
      const configure = enc.configure.bind(enc);
      enc.configure = cfg => {
        log.push({ at: e.clock.now(), bitrate: cfg.bitrate });
        configure(cfg);
      };
      const last = () => log[log.length - 1].bitrate;
      await e.frames(2);
      expect(log.map(l => l.bitrate)).toEqual([c.down[0]]);
      // Backpressure: every source frame is skipped.
      e.t.buffered = SEND_BUFFER_HIGH + 1;
      await e.frames(15);
      expect(last()).toBe(c.down[0]);
      await e.frames(1); // the 16th skip within 10 s
      expect(last()).toBe(c.down[1]);
      // Each further 10 s with more than 15 skips halves again, not sooner.
      await e.frames(148); // 9.9 s
      expect(last()).toBe(c.down[1]);
      await e.frames(2);
      expect(last()).toBe(c.down[2]);
      await e.frames(150);
      expect(last()).toBe(c.down[3]);
      await e.frames(300); // at the floor: no lower
      expect(last()).toBe(VIDEO_BITRATE_FLOOR);
      const downSteps = log.slice(1);
      expect(downSteps.map(l => l.bitrate)).toEqual(c.down.slice(1));
      for (let i = 1; i < downSteps.length; i++) expect(downSteps[i].at - downSteps[i - 1].at).toBeGreaterThanOrEqual(10_000);
      // The backpressure ends: each 10 s without a skip doubles, up to §6.13.4.
      e.t.buffered = 0;
      const lastSkipAt = e.clock.now() - 67;
      await e.frames(148); // 9.9 s
      expect(last()).toBe(VIDEO_BITRATE_FLOOR);
      await e.frames(450); // 30 s more
      const upSteps = log.slice(1 + downSteps.length);
      expect(upSteps.map(l => l.bitrate)).toEqual(c.up);
      expect(upSteps[0].at - lastSkipAt).toBeGreaterThanOrEqual(10_000);
      for (let i = 1; i < upSteps.length; i++) expect(upSteps[i].at - upSteps[i - 1].at).toBeGreaterThanOrEqual(10_000);
      await e.frames(200);
      expect(log.length).toBe(1 + downSteps.length + upSteps.length);
      // The first frame encoded after every reconfiguration is a keyframe; nothing exceeds §6.13.4's maximum.
      for (const step of log) expect(enc.inputs.find(i => i.at >= step.at)?.keyFrame).toBe(true);
      expect(log.every(l => l.bitrate <= c.maximum)).toBe(true);
      expect(e.sender.state).toBe('sharing');
    }
  });

  it('skips that pause for less than 10 s do not step the bitrate up; a new burst after a step up halves it again', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(2);
    const bitrate = () => e.platform.enc.configs[e.platform.enc.configs.length - 1].bitrate;
    e.t.buffered = SEND_BUFFER_HIGH + 1;
    await e.frames(16);
    expect(bitrate()).toBe(750_000);
    // Single skips every 9 s keep it down without halving it again.
    for (let i = 0; i < 4; i++) {
      e.t.buffered = 0;
      await e.frames(134); // about 9 s
      e.t.buffered = SEND_BUFFER_HIGH + 1;
      await e.frames(1);
    }
    expect(bitrate()).toBe(750_000);
    e.t.buffered = 0;
    await e.frames(160);
    expect(bitrate()).toBe(1_500_000);
    e.t.buffered = SEND_BUFFER_HIGH + 1;
    await e.frames(16);
    expect(bitrate()).toBe(750_000);
  });

  it('a count of 0 stops feeding the encoder; a count of 1 resumes with a key', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(5);
    e.sender.onWatchers(0);
    const n = e.platform.enc.inputs.length;
    await e.frames(5);
    expect(e.platform.enc.inputs.length).toBe(n);
    await e.advance(1000);
    e.sender.onWatchers(1);
    await e.frames(2);
    expect(e.platform.enc.inputs.slice(n).map(i => i.keyFrame)).toEqual([true, false]);
  });
});

// ---------------------------------------------------------------------------
// T-51 (REQ-51) U
// ---------------------------------------------------------------------------

describe('T-51 (REQ-51) keyframe requests, U', () => {
  it('ignores requests from outside V, outside R_g, and while not sharing', async () => {
    const e = senderEnv();
    e.keys.view = [B, C, D];
    e.keys.recipients = new Set([B, D]);
    e.sender.onKeyframeRequest(B); // not sharing yet
    await e.start();
    await e.frames(5);
    await e.advance(2000);
    const n = keyTimes(e).length;
    e.sender.onKeyframeRequest(E); // not in V
    e.sender.onKeyframeRequest(C); // in V, not in R_g
    e.sender.onKeyframeRequest(42);
    await e.frames(5);
    expect(keyTimes(e).length).toBe(n);
    e.sender.onKeyframeRequest(D);
    await e.frames(2);
    expect(keyTimes(e).length).toBe(n + 1);
  });

  it('20 requests from 4 users within one second force one keyframe at once and one 1 s later, and none more; requests change no keys, bitrate or frame rate', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(20);
    const configs = e.platform.enc.configs.length;
    const t0 = e.clock.now();
    const users = [B, C, D, E];
    for (let i = 0; i < 20; i++) {
      e.sender.onKeyframeRequest(users[i % 4]);
      if (i % 2 === 0) e.platform.source.push(1280, 720);
      await flush();
      await e.advance(50);
    }
    await e.frames(45); // 3 s more
    const keys = keyTimes(e, t0);
    expect(keys).toHaveLength(2);
    expect(keys[0] - t0).toBeLessThan(100);
    expect(keys[1] - keys[0]).toBeGreaterThanOrEqual(1000);
    expect(keys[1] - keys[0]).toBeLessThan(1100);
    // A second request from the same user within 5 s is ignored; after 5 s it counts again.
    e.sender.onKeyframeRequest(B);
    await e.frames(5);
    expect(keyTimes(e, t0)).toHaveLength(2);
    await e.clock.advance(t0 + 5100 - e.clock.now(), flush);
    e.sender.onKeyframeRequest(B);
    await e.frames(5);
    expect(keyTimes(e, t0)).toHaveLength(3);
    expect(e.platform.enc.configs.length).toBe(configs);
    expect(e.keys.epoch).toBe(0);
    const inputs = e.platform.enc.inputs.filter(i => i.at >= t0).map(i => i.at);
    expect(maxPerSecond(inputs)).toBeLessThanOrEqual(15);
  });
});

describe('REQ-27: video frames are closed on every path', () => {
  it('a share with skips, scaling, discards, a static period and a stop leaves no frame open', async () => {
    const e = senderEnv();
    await e.start();
    await e.frames(5, { w: 3840, h: 2160 });
    e.t.buffered = SEND_BUFFER_HIGH + 1;
    await e.frames(5, { w: 2560, h: 1600 });
    e.t.buffered = 0;
    e.platform.outputSize = o => (o.seq % 7 === 0 ? 1_100_000 : o.key ? 4000 : 600);
    await e.frames(20, { w: 1920, h: 1080 });
    await e.advance(12_000);
    e.sender.stopFromUser();
    expect(e.platform.frames.open.size).toBe(0);
    expect(e.platform.frames.created).toBeGreaterThan(30);
    // Markers carry the sender tag.
    expect(readMarker(new Uint8Array(0))).toBeNull();
  });
});
