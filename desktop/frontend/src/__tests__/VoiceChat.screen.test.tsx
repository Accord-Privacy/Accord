/**
 * SPEC-03 A1 F tests of the voice panel's screen sharing (`VoiceChat.tsx`,
 * §8.4), over the in-memory relay of `voice/relay.testkit.ts` with its
 * screen path, real `RelayVoiceConnection`s and `CallKeyManager`s, and the
 * browser adapter of `voice/screenShare.ts` driven through stubs of
 * `navigator.mediaDevices.getDisplayMedia`, `MediaStreamTrackProcessor`,
 * `VideoFrame`, `VideoEncoder`, `VideoDecoder` and `EncodedVideoChunk` (each
 * switchable to missing, unsupported or throwing), a stub of the Tauri
 * `invoke` that answers `display_capture_supported`, a controllable
 * `requestAnimationFrame`, and a canvas context that records `drawImage`
 * with its source rectangle (§10.1). Other participants are headless
 * connections with the screen fakes.
 *
 * T-42, T-43, T-50 (F), T-52 (F), T-54 and RG-C117-1 (F).
 */
import React, { useState } from 'react';
import { act, cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppContext, type AppContextType } from '../components/AppContext';
import { VoiceChat, type VoiceCallEnvironment } from '../VoiceChat';
import { A, B, C, CH, NODE } from '../voice/callKeys.testkit';
import type { RelayVoiceConnection } from '../voice/relay';
import { FakeBridge, FakeVoiceRelay, voiceClient, type VoiceClient } from '../voice/relay.testkit';
import { FakeScreenPlatform, FakeSurface, readMarker, syntheticVp8, type VideoMarker } from '../voice/screenShare.testkit';
import { encodeSFrameHeader, parseFrame, MEDIA_KIND_VIDEO } from '../voice/mediaFrame';
import { decodeScreenUp, encodeFragment } from '../voice/screenFrame';

// ---------------------------------------------------------------------------
// Browser stubs (§10.1)
// ---------------------------------------------------------------------------

interface StubConfig {
  shell: boolean | null;
  getDisplayMedia: 'ok' | 'missing' | { error: string };
  audioTrack: boolean;
  encoder: 'ok' | 'missing' | 'throws';
  encoderSupport: { A: boolean; B: boolean };
  processor: boolean;
  videoFrame: boolean;
  decoder: 'ok' | 'missing' | 'unsupported' | 'throws';
}

const DEFAULT_STUBS: StubConfig = {
  shell: null,
  getDisplayMedia: 'ok',
  audioTrack: false,
  encoder: 'ok',
  encoderSupport: { A: true, B: true },
  processor: true,
  videoFrame: true,
  decoder: 'ok',
};

class StubTrack {
  contentHint = '';
  readonly stop = vi.fn();
  private readonly ended = new Set<() => void>();
  constructor(readonly kind: 'video' | 'audio') {}
  addEventListener(_t: string, l: () => void): void {
    this.ended.add(l);
  }
  removeEventListener(_t: string, l: () => void): void {
    this.ended.delete(l);
  }
  end(): void {
    for (const l of [...this.ended]) l();
  }
}

class StubStream {
  constructor(readonly tracks: StubTrack[]) {}
  getTracks() {
    return [...this.tracks];
  }
  getVideoTracks() {
    return this.tracks.filter(t => t.kind === 'video');
  }
  getAudioTracks() {
    return this.tracks.filter(t => t.kind === 'audio');
  }
}

class StubVideoFrame {
  readonly displayWidth: number;
  readonly displayHeight: number;
  readonly timestamp: number;
  closed = false;
  constructor(src: { displayWidth?: number; displayHeight?: number; width?: number; height?: number; timestamp?: number }, init?: { timestamp?: number }) {
    this.displayWidth = src.displayWidth ?? src.width ?? 0;
    this.displayHeight = src.displayHeight ?? src.height ?? 0;
    this.timestamp = init?.timestamp ?? src.timestamp ?? 0;
  }
  clone(): StubVideoFrame {
    return new StubVideoFrame(this);
  }
  close(): void {
    this.closed = true;
  }
}

interface Probe {
  stubs: StubConfig;
  /** Calls of getDisplayMedia: their options, whether inside a click, whether a microtask had run. */
  displayCalls: Array<{ options: unknown; inClick: boolean; microtaskRan: boolean }>;
  streams: StubStream[];
  processorTracks: StubTrack[];
  readers: Array<{ push(w: number, h: number): void }>;
  encoderConfigs: Array<Record<string, unknown>>;
  encoded: number;
  decoded: VideoMarker[];
  decoderConfigs: Array<Record<string, unknown>>;
  raf: Array<() => void>;
  decoderErrors: Array<() => void>;
  draws: Array<{ canvas: HTMLCanvasElement; args: unknown[] }>;
  clears: number;
  invoke: ReturnType<typeof vi.fn>;
  inClick: boolean;
  microtaskRan: boolean;
}

let probe: Probe;
let relay: FakeVoiceRelay;
let peerConnections = 0;

function installStubs(cfg: Partial<StubConfig> = {}): void {
  const stubs: StubConfig = { ...DEFAULT_STUBS, ...cfg };
  probe.stubs = stubs;
  // getDisplayMedia
  const mediaDevices = stubs.getDisplayMedia === 'missing'
    ? {}
    : {
        getDisplayMedia: (options: unknown) => {
          probe.displayCalls.push({ options, inClick: probe.inClick, microtaskRan: probe.microtaskRan });
          const g = stubs.getDisplayMedia;
          if (typeof g === 'object') {
            const e = new Error(g.error);
            e.name = g.error;
            return Promise.reject(e);
          }
          const s = new StubStream([new StubTrack('video'), ...(stubs.audioTrack ? [new StubTrack('audio')] : [])]);
          probe.streams.push(s);
          return Promise.resolve(s);
        },
      };
  Object.defineProperty(window.navigator, 'mediaDevices', { configurable: true, value: mediaDevices });
  // The shell
  if (stubs.shell === null) delete (window as any).__TAURI__;
  else (window as any).__TAURI__ = { core: { invoke: probe.invoke } };
  // VideoFrame, MediaStreamTrackProcessor
  if (stubs.videoFrame) vi.stubGlobal('VideoFrame', StubVideoFrame);
  if (stubs.processor) {
    vi.stubGlobal('MediaStreamTrackProcessor', class {
      readable: { getReader(): unknown };
      constructor({ track }: { track: StubTrack }) {
        probe.processorTracks.push(track);
        const queue: StubVideoFrame[] = [];
        let waiting: ((r: { done: boolean; value?: StubVideoFrame }) => void) | null = null;
        let cancelled = false;
        probe.readers.push({
          push(w, h) {
            const f = new StubVideoFrame({ displayWidth: w, displayHeight: h, timestamp: Math.round(relay.clock.now() * 1000) });
            if (waiting) {
              const r = waiting;
              waiting = null;
              r({ done: false, value: f });
            } else queue.push(f);
          },
        });
        this.readable = {
          getReader: () => ({
            read: () => {
              if (cancelled) return Promise.resolve({ done: true });
              const f = queue.shift();
              if (f) return Promise.resolve({ done: false, value: f });
              return new Promise(r => {
                waiting = r;
              });
            },
            cancel: () => {
              cancelled = true;
              waiting?.({ done: true });
              return Promise.resolve();
            },
          }),
        };
      }
    });
  }
  // VideoEncoder
  if (stubs.encoder !== 'missing') {
    vi.stubGlobal('VideoEncoder', class {
      static isConfigSupported(c: { latencyMode?: string }) {
        if (stubs.encoder === 'throws') return Promise.reject(new TypeError('no'));
        return Promise.resolve({ supported: c.latencyMode === 'realtime' ? stubs.encoderSupport.A : stubs.encoderSupport.B });
      }
      state = 'unconfigured';
      encodeQueueSize = 0;
      private cfg: { width: number; height: number } | null = null;
      private seq = 0;
      private first = true;
      constructor(private readonly init: { output: (c: unknown) => void; error: (e: unknown) => void }) {}
      configure(c: { width: number; height: number }) {
        probe.encoderConfigs.push({ ...c });
        this.cfg = c;
        this.state = 'configured';
        this.first = true;
      }
      encode(_f: StubVideoFrame, o: { keyFrame: boolean }) {
        const key = o.keyFrame || this.first;
        this.first = false;
        const data = syntheticVp8(key, this.cfg!.width, this.cfg!.height, { tag: 1, seq: ++this.seq, picture: 0 }, key ? 3000 : 500);
        probe.encoded++;
        queueMicrotask(() => this.init.output({ type: key ? 'key' : 'delta', byteLength: data.length, copyTo: (d: Uint8Array) => d.set(data) }));
      }
      close() {
        this.state = 'closed';
      }
    });
  }
  // VideoDecoder and EncodedVideoChunk
  vi.stubGlobal('EncodedVideoChunk', class {
    readonly type: string;
    readonly timestamp: number;
    readonly data: Uint8Array;
    constructor(init: { type: string; timestamp: number; data: Uint8Array }) {
      this.type = init.type;
      this.timestamp = init.timestamp;
      this.data = Uint8Array.from(init.data);
    }
  });
  if (stubs.decoder !== 'missing') {
    vi.stubGlobal('VideoDecoder', class {
      static isConfigSupported(c: Record<string, unknown>) {
        probe.decoderConfigs.push({ ...c });
        if (stubs.decoder === 'throws') return Promise.reject(new TypeError('no'));
        return Promise.resolve({ supported: stubs.decoder === 'ok' });
      }
      state = 'unconfigured';
      decodeQueueSize = 0;
      private cfg: { codedWidth: number; codedHeight: number } | null = null;
      constructor(private readonly init: { output: (f: unknown) => void; error: (e: unknown) => void }) {
        probe.decoderErrors.push(() => this.init.error(new Error('decoder error')));
      }
      configure(c: { codedWidth: number; codedHeight: number }) {
        this.cfg = c;
        this.state = 'configured';
      }
      decode(chunk: { data: Uint8Array }) {
        const m = readMarker(chunk.data);
        if (m) probe.decoded.push(m);
        const { codedWidth: w, codedHeight: h } = this.cfg!;
        queueMicrotask(() => {
          if (this.state === 'closed') return;
          this.init.output({
            codedWidth: Math.ceil(w / 16) * 16,
            codedHeight: Math.ceil(h / 16) * 16,
            visibleRect: { x: 0, y: 0, width: w, height: h },
            displayWidth: w,
            displayHeight: h,
            close: () => undefined,
          });
        });
      }
      close() {
        this.state = 'closed';
      }
    });
  }
}

beforeEach(() => {
  relay = new FakeVoiceRelay();
  relay.enableScreen();
  peerConnections = 0;
  probe = {
    stubs: DEFAULT_STUBS,
    displayCalls: [],
    streams: [],
    processorTracks: [],
    readers: [],
    encoderConfigs: [],
    encoded: 0,
    decoded: [],
    decoderConfigs: [],
    raf: [],
    decoderErrors: [],
    draws: [],
    clears: 0,
    invoke: vi.fn(async (cmd: string) => (cmd === 'display_capture_supported' ? probe.stubs.shell : undefined)),
    inClick: false,
    microtaskRan: false,
  };
  vi.stubGlobal('RTCPeerConnection', class {
    constructor() {
      peerConnections++;
    }
  });
  vi.stubGlobal('requestAnimationFrame', (cb: () => void) => {
    probe.raf.push(cb);
    return probe.raf.length;
  });
  vi.spyOn(HTMLMediaElement.prototype, 'play').mockImplementation(() => Promise.resolve());
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockImplementation(function (this: HTMLCanvasElement) {
    const canvas = this;
    return {
      drawImage: (...args: unknown[]) => void probe.draws.push({ canvas, args }),
      clearRect: () => void probe.clears++,
    } as unknown as CanvasRenderingContext2D;
  } as never);
});

afterEach(() => {
  cleanup();
  for (const s of relay.sockets.values()) s.connected = false;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  delete (window as any).__TAURI__;
  Reflect.deleteProperty(window.navigator, 'mediaDevices');
});

// ---------------------------------------------------------------------------
// The panel and headless peers
// ---------------------------------------------------------------------------

interface Member {
  id: string;
  name: string;
}

function membersOf(list: Member[]): AppContextType['members'] {
  return list.map(m => ({ node_id: NODE, user_id: m.id, public_key_hash: '', role: 'member', joined_at: 0, user: { id: m.id, display_name: m.name } })) as unknown as AppContextType['members'];
}

interface Panel {
  bridge: FakeBridge;
  conn(): RelayVoiceConnection;
}

function renderPanel(opts: { bridge?: FakeBridge; members?: Member[]; selfName?: string; onVoiceUsers?: (users: unknown) => void } = {}): Panel {
  const bridge = opts.bridge ?? new FakeBridge(A);
  const conns: RelayVoiceConnection[] = [];
  const env: VoiceCallEnvironment = {
    input: { start: async () => true, setMuted: () => undefined, stop: () => undefined },
    output: { open: async () => true, createOpusDecoder: () => null, play: () => undefined, removeUser: () => undefined, setDeafened: () => undefined, close: () => undefined },
    clock: relay.clock,
    onConnection: c => {
      conns.push(c);
      relay.track(c);
    },
  };
  const sock = relay.socket(A);
  const Harness: React.FC = () => {
    const [muted, setMuted] = useState(false);
    const [deafened, setDeafened] = useState(false);
    const ctx = {
      voiceMuted: muted,
      setVoiceMuted: setMuted,
      voiceDeafened: deafened,
      setVoiceDeafened: setDeafened,
      appState: { user: { display_name: opts.selfName ?? 'Alice' } },
      members: membersOf(opts.members ?? [{ id: B, name: 'Bob' }, { id: C, name: 'Carol' }]),
      setVoiceChannelUsers: (users: unknown) => opts.onVoiceUsers?.(users),
    } as unknown as AppContextType;
    return (
      <AppContext.Provider value={ctx}>
        <VoiceChat ws={sock as never} currentUserId={A} channelId={CH} channelName="Voice" nodeId={NODE} bridge={bridge} onLeave={() => undefined} callEnv={env} />
      </AppContext.Provider>
    );
  };
  render(<Harness />);
  return { bridge, conn: () => conns[conns.length - 1] };
}

async function settle(): Promise<void> {
  await act(async () => {
    await relay.settle();
  });
}

async function advance(ms: number): Promise<void> {
  await act(async () => {
    await relay.advance(ms);
  });
}

interface Peer extends VoiceClient {
  screen: FakeScreenPlatform;
  surface: FakeSurface;
}

async function peer(id: string, tag: number): Promise<Peer> {
  const p = new FakeScreenPlatform(tag);
  p.clock = relay.clock;
  const c = voiceClient(relay, id, { channelId: CH, screen: p });
  void c.conn.connect();
  await settle();
  return Object.assign(c, { screen: p, surface: new FakeSurface() });
}

async function peerShares(p: Peer): Promise<void> {
  await act(async () => {
    expect(p.conn.startScreenShare()).toBe(true);
    await relay.settle();
  });
}

async function peerFrames(p: Peer, n: number, every = 67): Promise<void> {
  for (let i = 0; i < n; i++) {
    await act(async () => {
      p.screen.source.push(1280, 720);
      await relay.settle();
    });
    await advance(every);
  }
}

function control(): HTMLButtonElement {
  return screen.getByTestId('screen-share-control') as HTMLButtonElement;
}

function controlText(): string {
  return screen.getByTestId('screen-share-state').textContent ?? '';
}

function tile(sharer: string): HTMLElement | null {
  return document.querySelector<HTMLElement>(`[data-testid="screen-tile"][data-sharer-id="${sharer}"]`);
}

function runAnimationFrames(): void {
  act(() => {
    for (const cb of probe.raf.splice(0)) cb();
  });
}

/** Click a button the way a user does, recording whether getDisplayMedia ran inside it before any microtask. */
function userClick(el: HTMLElement): void {
  act(() => {
    probe.microtaskRan = false;
    queueMicrotask(() => {
      probe.microtaskRan = true;
    });
    probe.inClick = true;
    el.click();
    probe.inClick = false;
  });
}

function sentTypes(): string[] {
  return relay.log.filter(m => m.from === A).map(m => m.type);
}

// ---------------------------------------------------------------------------
// T-42
// ---------------------------------------------------------------------------

describe('T-42 (REQ-42) availability', () => {
  type Case = {
    name: string;
    stubs?: Partial<StubConfig>;
    hello?: { features?: unknown; screen_limits?: unknown };
    expect: RegExp;
    enabled: boolean;
  };
  const NOT_RELAY = /^Encrypted screen sharing isn't available on this relay yet\.$/;
  const cases: Case[] = [
    { name: 'hello without features', hello: {}, expect: NOT_RELAY, enabled: false },
    { name: 'features without screen/1', hello: { features: ['admission/1'] }, expect: NOT_RELAY, enabled: false },
    { name: 'screen/1 without screen_limits', hello: { features: ['screen/1'] }, expect: NOT_RELAY, enabled: false },
    { name: 'max_sharers 0', hello: { features: ['screen/1'], screen_limits: { max_sharers: 0, max_bytes_per_second: 500_000 } }, expect: NOT_RELAY, enabled: false },
    { name: 'max_sharers 9', hello: { features: ['screen/1'], screen_limits: { max_sharers: 9, max_bytes_per_second: 500_000 } }, expect: NOT_RELAY, enabled: false },
    { name: 'max_bytes_per_second 199,999', hello: { features: ['screen/1'], screen_limits: { max_sharers: 2, max_bytes_per_second: 199_999 } }, expect: NOT_RELAY, enabled: false },
    { name: 'screen/1 with valid limits', expect: /^Share Screen$/, enabled: true },
    { name: 'the shell says no (the macOS app), getDisplayMedia present', stubs: { shell: false }, expect: /this app can't capture the screen/, enabled: false },
    { name: 'the shell says yes', stubs: { shell: true }, expect: /^Share Screen$/, enabled: true },
    { name: 'getDisplayMedia missing', stubs: { getDisplayMedia: 'missing' }, expect: /this app can't capture the screen/, enabled: false },
    { name: 'VideoEncoder missing', stubs: { encoder: 'missing' }, expect: /no VP8 video encoder/, enabled: false },
    { name: 'isConfigSupported throws', stubs: { encoder: 'throws' }, expect: /no VP8 video encoder/, enabled: false },
    { name: 'configurations A and B unsupported', stubs: { encoderSupport: { A: false, B: false } }, expect: /no VP8 video encoder/, enabled: false },
    { name: 'configuration A unsupported', stubs: { encoderSupport: { A: false, B: true } }, expect: /^Share Screen$/, enabled: true },
    { name: 'no MediaStreamTrackProcessor, VideoFrame present', stubs: { processor: false }, expect: /^Share Screen$/, enabled: true },
    { name: 'neither MediaStreamTrackProcessor nor VideoFrame', stubs: { processor: false, videoFrame: false }, expect: /no way to read video frames/, enabled: false },
  ];

  for (const c of cases) {
    it(`Share Screen: ${c.name}`, async () => {
      installStubs(c.stubs);
      renderPanel();
      await settle();
      if (c.hello) {
        act(() => relay.sendHello(A, c.hello));
        await settle();
      }
      expect(controlText()).toMatch(c.expect);
      expect(control().disabled).toBe(!c.enabled);
      expect(control()).toHaveAccessibleDescription(expect.stringMatching(c.expect));
      if (!c.enabled) {
        // A click on the disabled control, or a direct call, starts nothing.
        userClick(control());
        expect(probe.displayCalls).toHaveLength(0);
        await settle();
        expect(sentTypes()).not.toContain('ScreenShareStart');
      }
      if (c.stubs?.shell === false) expect(probe.invoke).toHaveBeenCalledWith('display_capture_supported');
      expect(sentTypes()).not.toContain('P2PSignal');
      expect(peerConnections).toBe(0);
    });
  }

  it('configuration B is used only when A is rejected; Source B adds the pause note', async () => {
    installStubs({ encoderSupport: { A: false, B: true }, processor: false });
    renderPanel();
    await settle();
    const b = await peer(B, 2);
    void b;
    await advance(3000);
    userClick(control());
    await settle();
    expect(controlText()).toBe('Sharing your screen');
    expect(screen.getByTestId('screen-sharing-status')).toHaveTextContent('Sharing may pause while Accord is minimized or hidden.');
    await act(async () => {
      b.conn.attachScreenSurface(A, b.surface);
      expect(b.conn.watchScreen(A)).toBe(true);
      await relay.settle();
    });
    // Source B reads the preview element: give it a picture through the stub.
    const video = document.querySelector('[data-testid="screen-preview"] video') as HTMLVideoElement;
    expect(video).not.toBeNull();
    Object.assign(video, { displayWidth: 1280, displayHeight: 720 });
    await advance(200);
    expect(probe.encoderConfigs.length).toBeGreaterThan(0);
    for (const cfg of probe.encoderConfigs) expect(cfg.latencyMode).toBeUndefined();
  });

  it('the remote share list at max_sharers, the call not joined, E2EE not ready, and reconnecting show their rows', async () => {
    installStubs();
    // Not joined: the join reply is withheld.
    relay.filter = (to, data) => !(to === A && data.type === 'voice_channel_joined');
    renderPanel();
    await settle();
    expect(controlText()).toBe('Connecting…');
    expect(control().disabled).toBe(true);
    relay.filter = () => true;
    cleanup();
    // E2EE not ready.
    const locked = new FakeBridge(A);
    locked.ready = false;
    renderPanel({ bridge: locked });
    await settle();
    expect(controlText()).toBe('Connecting…');
    expect(control().disabled).toBe(true);
    cleanup();
    // Two others share: the limit.
    relay = new FakeVoiceRelay();
    relay.enableScreen();
    renderPanel();
    await settle();
    const b = await peer(B, 2);
    const c = await peer(C, 3);
    await advance(3000);
    await peerShares(b);
    await peerShares(c);
    expect(controlText()).toBe('2 people are already sharing.');
    expect(control().disabled).toBe(true);
    // Reconnecting on a relay that lists screen/1: the socket closed, then open before its hello.
    act(() => relay.closeSocket(A));
    await settle();
    expect(controlText()).toBe('Connecting…');
    act(() => relay.reopenSocket(A, { hello: false }));
    await settle();
    await advance(3000);
    expect(controlText()).toBe('Connecting…');
    act(() => relay.sendHello(A));
    await settle();
    expect(controlText()).toBe('2 people are already sharing.');
    expect(probe.displayCalls).toHaveLength(0);
  });

  it('viewing: VideoDecoder missing or VP8 unsupported shows the viewing-unavailable tile without Watch; the dictionary rejected is retried without optimizeForLatency', async () => {
    for (const decoder of ['missing', 'unsupported'] as const) {
      relay = new FakeVoiceRelay();
      relay.enableScreen();
      installStubs({ decoder });
      renderPanel();
      await settle();
      const b = await peer(B, 2);
      await advance(3000);
      await peerShares(b);
      const t = tile(B)!;
      expect(t).toHaveTextContent("Bob is sharing their screen. This app can't display screen shares (no VP8 video decoder).");
      expect(within(t).queryByRole('button', { name: 'Watch' })).toBeNull();
      expect(sentTypes()).not.toContain('ScreenWatch');
      cleanup();
      vi.unstubAllGlobals();
    }
    relay = new FakeVoiceRelay();
    relay.enableScreen();
    probe.decoderConfigs = [];
    installStubs({ decoder: 'throws' });
    renderPanel();
    await settle();
    expect(probe.decoderConfigs.map(c => 'optimizeForLatency' in c)).toEqual([true, false]);
  });

  it('a relay without screen/1: tiles from forged announcements show the relay reason; no watch is possible', async () => {
    installStubs();
    relay.enableScreen(false);
    renderPanel();
    await settle();
    await peer(B, 2);
    await advance(3000);
    relay.inject(A, { type: 'screen_share_started', channel_id: CH, user_id: B });
    await settle();
    const t = tile(B)!;
    expect(t).toHaveTextContent("Bob is sharing their screen. Encrypted screen sharing isn't available on this relay yet.");
    expect(within(t).queryByRole('button', { name: 'Watch' })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// T-43, T-52 (F), RG-C117-1 (F)
// ---------------------------------------------------------------------------

describe('T-43 (REQ-43) capture from the click', () => {
  it('getDisplayMedia runs synchronously inside the click handler with the §6.13.2 options; audio is stopped and never read; contentHint and the preview', async () => {
    installStubs({ audioTrack: true });
    renderPanel();
    await settle();
    await peer(B, 2);
    await advance(3000);
    expect(probe.displayCalls).toHaveLength(0); // never without a click
    userClick(control());
    expect(probe.displayCalls).toEqual([
      { options: { video: { width: { max: 1920 }, height: { max: 1920 }, frameRate: { max: 15 } }, audio: false }, inClick: true, microtaskRan: false },
    ]);
    await settle();
    const stream = probe.streams[0];
    const audio = stream.getAudioTracks()[0];
    expect(audio.stop).toHaveBeenCalled();
    expect(probe.processorTracks).not.toContain(audio); // never connected to anything
    expect(stream.getVideoTracks()[0].contentHint).toBe('detail');
    const video = document.querySelector('[data-testid="screen-preview"] video') as HTMLVideoElement & { srcObject: unknown };
    expect(video.srcObject).toBe(stream);
    expect(video.muted).toBe(true);
  });

  for (const [error, text] of [
    ['NotAllowedError', 'Screen sharing was cancelled.'],
    ['NotFoundError', "Couldn't capture your screen."],
    ['NotReadableError', "Couldn't capture your screen."],
    ['NotSupportedError', "Couldn't capture your screen."],
    ['AbortError', "Couldn't capture your screen."],
    ['TypeError', "Couldn't capture your screen."],
    ['InvalidStateError', "Couldn't capture your screen."],
  ] as const) {
    it(`${error} shows "${text}", leaves the control idle and sends no ScreenShareStart`, async () => {
      installStubs({ getDisplayMedia: { error } });
      renderPanel();
      await settle();
      await advance(3000);
      userClick(control());
      await settle();
      expect(screen.getByTestId('screen-notice').textContent).toContain(text);
      expect(controlText()).toBe('Share Screen');
      expect(sentTypes()).not.toContain('ScreenShareStart');
    });
  }
});

describe('T-52 (REQ-52) and RG-C117-1 (F)', () => {
  it('Starting with Cancel, then Sharing only after screen_share_started; B watches and decodes A\'s frames; Stop Sharing sends ScreenShareStop', async () => {
    installStubs();
    relay.filter = (to, data) => !(to === A && data.type === 'screen_share_started');
    renderPanel();
    await settle();
    const b = await peer(B, 2);
    await advance(3000);
    userClick(control());
    await settle();
    expect(controlText()).toBe('Starting screen share…');
    expect(control()).toHaveAccessibleName('Cancel');
    expect(screen.queryByRole('button', { name: 'Stop Sharing' })).toBeNull();
    // The relay's acknowledgment arrives: only now "Sharing".
    relay.filter = () => true;
    const start = relay.log.filter(m => m.from === A && m.type === 'ScreenShareStart')[0];
    relay.inject(A, { type: 'screen_share_started', channel_id: CH, user_id: A, request_id: start.body.message_id });
    await settle();
    expect(controlText()).toBe('Sharing your screen');
    expect(control()).toHaveAccessibleName('Stop Sharing');
    // B sees the tile and watches; A's frames reach B's decoder.
    await act(async () => {
      b.conn.attachScreenSurface(A, b.surface);
      expect(b.conn.watchScreen(A)).toBe(true);
      await relay.settle();
    });
    expect(screen.getByTestId('screen-sharing-status')).toHaveTextContent('1 watching');
    for (let i = 0; i < 5; i++) {
      act(() => probe.readers[0].push(1280, 720));
      await settle();
      await advance(67);
    }
    expect(b.screen.decodedMarkers.filter(m => m.tag === 1).length).toBe(5);
    // Stop Sharing.
    userClick(control());
    await settle();
    expect(sentTypes().filter(t => t === 'ScreenShareStop')).toHaveLength(1);
    expect(probe.streams[0].getVideoTracks()[0].stop).toHaveBeenCalled();
    expect(controlText()).toBe('Share Screen');
    expect(screen.queryByTestId('screen-notice')).toBeNull(); // our own stop is not "stopped by the relay"
  });

  it('Cancel while starting sends ScreenShareStop; the relay stopping the share shows its message', async () => {
    installStubs();
    relay.filter = (to, data) => !(to === A && data.type === 'screen_share_started');
    renderPanel();
    await settle();
    await peer(B, 2);
    await advance(3000);
    userClick(control());
    await settle();
    userClick(control()); // Cancel
    await settle();
    expect(sentTypes().filter(t => t === 'ScreenShareStop')).toHaveLength(1);
    expect(controlText()).toBe('Share Screen');
    relay.filter = () => true;
    userClick(control());
    await settle();
    expect(controlText()).toBe('Sharing your screen');
    relay.inject(A, { type: 'screen_share_stopped', channel_id: CH, user_id: A, reason: 'removed' });
    await settle();
    expect(screen.getByTestId('screen-notice')).toHaveTextContent('Your screen share was stopped by the relay.');
    expect(controlText()).toBe('Share Screen');
  });

  it('a rejection and a 10 s silence show their messages', async () => {
    installStubs();
    relay.enableScreen(true, { maxSharers: 1 });
    renderPanel();
    await settle();
    const b = await peer(B, 2);
    await advance(3000);
    // The relay rejects with limit (its list changed after the click).
    // B's start reaches the relay first; A's is rejected with limit.
    await act(async () => {
      expect(b.conn.startScreenShare()).toBe(true);
      control().click();
      await relay.settle();
    });
    expect(screen.getByTestId('screen-notice')).toHaveTextContent('1 person is already sharing.');
    act(() => b.conn.stopScreenShare());
    await settle();
    // Silence for 10 s.
    relay.enableScreen(true, { maxSharers: 2 });
    relay.filter = (to, data) => !(to === A && data.type.startsWith('screen_share'));
    await settle();
    userClick(control());
    await settle();
    await advance(10_000);
    expect(screen.getByTestId('screen-notice')).toHaveTextContent("The relay didn't start your screen share.");
    expect(controlText()).toBe('Share Screen');
  });

  it('RG-C117-1 without screen/1: the control is disabled with the reason; no getDisplayMedia, no ScreenShareStart, no P2PSignal, never "Stop Sharing"', async () => {
    installStubs();
    relay.enableScreen(false);
    renderPanel();
    await settle();
    await peer(B, 2);
    await advance(3000);
    expect(controlText()).toBe("Encrypted screen sharing isn't available on this relay yet.");
    userClick(control());
    await settle();
    expect(probe.displayCalls).toHaveLength(0);
    expect(sentTypes().filter(t => /^Screen|P2PSignal/.test(t))).toEqual([]);
    expect(screen.queryByRole('button', { name: 'Stop Sharing' })).toBeNull();
    expect(peerConnections).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// T-50 (F) and T-54
// ---------------------------------------------------------------------------

describe('T-50 (REQ-50) F and T-54 (REQ-54) the viewer tiles and the sharing status', () => {
  it('Watch only after a click; rows 3, 6, 9, 8 and 7 over time; only the visible rectangle is drawn; every tile carries the identity label and the indicator', async () => {
    installStubs();
    renderPanel({ members: [{ id: B, name: 'Bob' }, { id: C, name: 'Alice' }] });
    await settle();
    const b = await peer(B, 2);
    const c = await peer(C, 3);
    await advance(3000);
    await peerShares(b);
    let t = tile(B)!;
    expect(t.dataset.row).toBe('3');
    expect(t).toHaveTextContent('Bob is sharing their screen');
    expect(t).not.toHaveTextContent('Same name as another participant');
    // C's display name equals the local user's: its tile carries the duplicate-name mark (REQ-11).
    await peerShares(c);
    expect(tile(C)!).toHaveTextContent('Alice is sharing their screen');
    expect(tile(C)!).toHaveTextContent('Same name as another participant');
    expect(t).toHaveTextContent('00000000');
    expect(t).toHaveTextContent('End-to-end encrypted · not verified');
    expect(t.textContent).not.toMatch(/P2P/);
    expect(sentTypes()).not.toContain('ScreenWatch');
    // Watch: row 6 while awaiting the first keyframe.
    userClick(within(t).getByRole('button', { name: 'Watch' }));
    await settle();
    expect(relay.log.filter(m => m.from === A && m.type === 'ScreenWatch').map(m => m.body)).toEqual([expect.objectContaining({ sharer_id: B, watch: true })]);
    t = tile(B)!;
    expect(t.dataset.row).toBe('6');
    expect(t).toHaveTextContent('Waiting for video…');
    // Frames: row 9 and a draw of the visible rectangle only.
    await peerFrames(b, 3);
    runAnimationFrames();
    await settle();
    t = tile(B)!;
    expect(t.dataset.row).toBe('9');
    expect(probe.decoded.filter(m => m.tag === 2).length).toBe(3);
    expect(probe.draws.length).toBeGreaterThan(0);
    for (const d of probe.draws) expect(d.args.slice(1)).toEqual([0, 0, 1280, 720, 0, 0, 1280, 720]);
    // No frame for 15 s (the relay delivers nothing, not even the sharer's
    // periodic keyframe): stalled, dimmed.
    relay.screenFilter = () => false;
    await advance(15_000);
    t = tile(B)!;
    expect(t.dataset.row).toBe('8');
    expect(t).toHaveTextContent(/No new video for 1[5-6] s\./);
    expect(t.querySelector('canvas')?.className).toContain('dimmed');
    // A decoder error with nothing arriving afterwards: awaiting a keyframe,
    // 10 s or more after the last decoded frame — "No video received".
    relay.screenFilter = () => false;
    act(() => probe.decoderErrors[probe.decoderErrors.length - 1]());
    await settle();
    t = tile(B)!;
    expect(t.dataset.row).toBe('7');
    expect(t).toHaveTextContent(/No video received from Bob for 1[5-6] s\./);
    // A fresh awaiting period shows row 6 for its first 10 s.
    relay.screenFilter = () => true;
    await peerFrames(b, 1);
    runAnimationFrames();
    await settle();
    expect(tile(B)!.dataset.row).toBe('9');
    t = tile(B)!;
    // Stop watching: ScreenWatch false and a cleared canvas.
    const clears = probe.clears;
    userClick(within(t).getByRole('button', { name: 'Stop watching' }));
    await settle();
    expect(relay.log.filter(m => m.from === A && m.type === 'ScreenWatch').map(m => m.body.watch)).toEqual([true, false]);
    expect(probe.clears).toBeGreaterThan(clears);
    expect(tile(B)!.dataset.row).toBe('3');
  });

  it('rows 5 (keys, 12 s), 4 (can\'t verify), 2 (blocked) and 3 with the watch limit, the rejected watch and "can\'t be displayed"', async () => {
    installStubs();
    const bridge = new FakeBridge(A);
    renderPanel({ bridge });
    await settle();
    const b = await peer(B, 2);
    const c = await peer(C, 3);
    await advance(3000);
    relay.enableScreen(true, { maxSharers: 3 });
    await settle();
    await peerShares(b);
    await peerShares(c);
    // Row 4: 50 consecutive AEAD failures while keys are held.
    userClick(within(tile(B)!).getByRole('button', { name: 'Watch' }));
    await settle();
    await peerFrames(b, 2);
    const genuine = relay.binaryLog.filter(m => m.from === B).map(m => decodeScreenUp(m.bytes)!.fragment);
    const parsed = parseFrame(Uint8Array.from(genuine[genuine.length - 1]), MEDIA_KIND_VIDEO);
    if (!parsed.ok) throw new Error('bad fixture');
    for (let i = 0; i < 50; i++) {
      relay.injectFragment(A, CH, B, Uint8Array.from([0x01, 0x02, ...encodeSFrameHeader(parsed.kid, parsed.ctr + 10 + i), ...parsed.ciphertext]));
    }
    await settle();
    expect(tile(B)!.dataset.row).toBe('4');
    expect(tile(B)!).toHaveTextContent("Video from Bob can't be verified.");
    // Watch limit: C's tile says so when two are watched.
    userClick(within(tile(C)!).getByRole('button', { name: 'Watch' }));
    await settle();
    const d = await peer('00000000-0000-4000-8000-0000000000a4', 4);
    await advance(3000);
    await peerShares(d);
    const dt = tile('00000000-0000-4000-8000-0000000000a4')!;
    expect(within(dt).getByRole('button', { name: 'Watch' })).toBeDisabled();
    expect(dt).toHaveTextContent("You're already watching 2 screens");
    // A rejected watch: row 3 with the reason.
    relay.inject(A, { type: 'screen_watch_rejected', channel_id: CH, sharer_id: C, reason: 'rate_limited', error: 'x', request_id: 'r' });
    await settle();
    expect(tile(C)!.dataset.row).toBe('3');
    expect(tile(C)!).toHaveTextContent("Couldn't start watching (too many requests).");
    // Row 2: the sharer becomes ineligible.
    act(() => bridge.setMembership(C, 'not_member'));
    await settle();
    expect(tile(C)!.dataset.row).toBe('2');
    expect(tile(C)!).toHaveTextContent('Carol is sharing their screen. Not a verified member, so the share is blocked.');
    // Row 5: watching without a key for the sharer's current instance.
    act(() => bridge.setMembership(C, 'member'));
    await settle();
    userClick(within(tile(B)!).getByRole('button', { name: 'Stop watching' }));
    await settle();
    relay.filter = (to, data) => !(to === A && data.type === 'voice_key_exchange' && data.from === C);
    act(() => bridge.setMembership(C, 'not_member'));
    act(() => bridge.setMembership(C, 'member'));
    await settle();
    userClick(within(tile(C)!).getByRole('button', { name: 'Watch' }));
    await settle();
    expect(tile(C)!.dataset.row).toBe('5');
    expect(tile(C)!).toHaveTextContent('Waiting for encryption keys…');
    await advance(12_000);
    expect(tile(C)!).toHaveTextContent("Can't decrypt this screen share yet.");
  });

  it('row 3 says "Video from [name] can\'t be displayed." after decoder setups were refused 3 times in 30 s (REQ-49)', async () => {
    installStubs();
    const p = renderPanel();
    await settle();
    const b = await peer(B, 2);
    await advance(3000);
    await peerShares(b);
    userClick(within(tile(B)!).getByRole('button', { name: 'Watch' }));
    await settle();
    // Key frames whose size alternates, as a malicious sharer could seal them under its own keys.
    const viewers = p.conn().screenParts!.viewers;
    for (let i = 0; i < 100 && viewers.isWatching(B); i++) {
      const [w, h] = i % 2 === 0 ? [640, 360] : [1280, 720];
      const data = syntheticVp8(true, w, h, { tag: 98, seq: i, picture: 0 }, 64);
      act(() => viewers.onFragment(B, 0, encodeFragment({ vcodec: 1, flags: 1, shareSeq: 1, frameNo: i, fragIndex: 0, fragCount: 1, width: w, height: h }, data)));
      await advance(100);
    }
    const t = tile(B)!;
    expect(t.dataset.row).toBe('3');
    expect(t).toHaveTextContent("Video from Bob can't be displayed.");
    expect(within(t).getByRole('button', { name: 'Watch' })).toBeEnabled();
  });

  it('the sharing status: N is the size of R_e even with every call_key_ack dropped; activating it lists exactly R_e; N is 0 only when R_e is empty; W watching', async () => {
    installStubs();
    renderPanel({ members: [{ id: B, name: 'Bob' }, { id: C, name: 'Carol' }] });
    await settle();
    await advance(3000);
    userClick(control());
    await settle();
    expect(screen.getByTestId('screen-sharing-status')).toHaveTextContent('No one else can see your screen yet');
    // Drop every ACK to A.
    relay.filter = (to, data) => !(to === A && data.type === 'voice_key_exchange');
    const b = await peer(B, 2);
    await peer(C, 3);
    await advance(5000);
    const status = screen.getByTestId('screen-sharing-status');
    expect(status).toHaveTextContent('Your screen can be seen by 2 participants (0 confirmed)');
    expect(status).toHaveTextContent('0 watching');
    act(() => within(status).getByRole('button', { name: /can be seen by/ }).click());
    const list = document.getElementById('voice-screen-audience-list')!;
    expect([...list.querySelectorAll('li')].map(li => li.dataset.userId).sort()).toEqual([B, C].sort());
    expect(list).toHaveTextContent('Bob');
    expect(list).toHaveTextContent('Carol');
    await act(async () => {
      b.conn.attachScreenSurface(A, b.surface);
      b.conn.watchScreen(A);
      await relay.settle();
    });
    expect(screen.getByTestId('screen-sharing-status')).toHaveTextContent('1 watching');
  });
});


describe('§8.4 refreshes in the panel', () => {
  it('the app\'s voice user list is updated when its content changes, not on every refresh of the panel while a share is watched', async () => {
    installStubs();
    const updates: unknown[] = [];
    renderPanel({ members: [{ id: B, name: 'Bob' }], onVoiceUsers: users => updates.push(users) });
    await settle();
    const b = await peer(B, 2);
    await advance(3000);
    // B joining changed the list.
    expect(updates[updates.length - 1]).toEqual([
      expect.objectContaining({ userId: A, displayName: 'Alice' }),
      expect.objectContaining({ userId: B, displayName: 'Bob' }),
    ]);
    await peerShares(b);
    userClick(within(tile(B)!).getByRole('button', { name: 'Watch' }));
    await settle();
    const before = updates.length;
    for (let i = 0; i < 20; i++) {
      await peerFrames(b, 1);
      runAnimationFrames();
      await settle();
    }
    // A stall (nothing delivered, not even the periodic keyframe), shown by the panel's timer.
    relay.screenFilter = () => false;
    await advance(16_000);
    expect(tile(B)!.dataset.row).toBe('8');
    expect(probe.draws.length).toBeGreaterThan(10);
    expect(updates.length).toBe(before);
  });
});
