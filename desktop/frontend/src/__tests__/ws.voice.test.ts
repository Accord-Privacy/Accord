/**
 * SPEC-03 tests of the WebSocket layer's call transport (§6.1, §6.12, REQ-37,
 * REQ-39): T-37, the binary half of T-26, the relay features of §6.1, and
 * the removal of the P2P and legacy senders.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AccordWebSocket, parseScreenLimits } from '../ws';
import { decodeWireBase64 } from '../attachments/base64';
import { encodeScreenDown } from '../voice/screenFrame';

const CH = '00000000-0000-4000-8000-0000000000c1';
const SHARER = '00000000-0000-4000-8000-0000000000a2';
const PEER = '00000000-0000-4000-8000-0000000000a3';

class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  static instances: MockWebSocket[] = [];

  readyState = MockWebSocket.CONNECTING;
  binaryType = 'blob';
  binaryTypeAtOpen: string | null = null;
  bufferedAmount = 0;
  readonly sent: Array<string | Uint8Array> = [];
  onopen: ((e: Event) => void) | null = null;
  onclose: ((e: CloseEvent) => void) | null = null;
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;

  constructor(public url: string) {
    MockWebSocket.instances.push(this);
  }

  send(data: string | Uint8Array): void {
    this.sent.push(typeof data === 'string' ? data : Uint8Array.from(data));
  }

  close(code = 1000): void {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.({ code, reason: '', wasClean: code === 1000 } as CloseEvent);
  }

  open(): void {
    this.binaryTypeAtOpen = this.binaryType;
    this.readyState = MockWebSocket.OPEN;
    this.onopen?.(new Event('open'));
  }

  json(payload: object): void {
    this.onmessage?.({ data: JSON.stringify(payload) });
  }

  binary(bytes: Uint8Array | unknown): void {
    this.onmessage?.({ data: bytes instanceof Uint8Array ? bytes.slice().buffer : bytes });
  }

  drop(): void {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.({ code: 1006, reason: '', wasClean: false } as CloseEvent);
  }

  jsonSent(): any[] {
    return this.sent.filter((m): m is string => typeof m === 'string').map(m => JSON.parse(m));
  }

  binarySent(): Uint8Array[] {
    return this.sent.filter((m): m is Uint8Array => typeof m !== 'string');
  }
}

vi.stubGlobal('WebSocket', MockWebSocket);

const latest = () => MockWebSocket.instances[MockWebSocket.instances.length - 1];

const SCREEN_HELLO = { type: 'hello', protocol_version: 1, features: ['screen/1'], screen_limits: { max_sharers: 2, max_bytes_per_second: 500_000 } };

function open(client: AccordWebSocket, hello: object | null = SCREEN_HELLO): MockWebSocket {
  client.connect();
  const ws = latest();
  ws.open();
  ws.json({ type: 'authenticated', user_id: 'u' });
  if (hello) ws.json(hello);
  return ws;
}

function fragment(len = 40): Uint8Array {
  const f = new Uint8Array(len);
  f[0] = 0x01;
  f[1] = 0x02;
  for (let i = 2; i < len; i++) f[i] = i & 0xff;
  return f;
}

describe('SPEC-03 call transport in ws.ts', () => {
  let client: AccordWebSocket;

  beforeEach(() => {
    vi.useFakeTimers();
    MockWebSocket.instances = [];
    client = new AccordWebSocket('t', 'http://localhost:8080');
  });

  afterEach(() => {
    client.disconnect();
    vi.useRealTimers();
  });

  it('sets binaryType to arraybuffer before the socket opens (§6.12.2)', () => {
    client.connect();
    expect(latest().binaryType).toBe('arraybuffer');
    latest().open();
    expect(latest().binaryTypeAtOpen).toBe('arraybuffer');
  });

  describe('T-37 (REQ-37) the non-queuing senders', () => {
    it('return false while disconnected, leave the queue unchanged, and send nothing from before after reconnecting', () => {
      client.connect();
      const ws = latest();
      ws.open(); // open but not authenticated yet
      const queued = client.getQueuedMessageCount();
      expect(client.sendCallMessage(CH, PEER, 'acv1:AAAA')).toBe(false);
      expect(client.sendMediaFrame(CH, new Uint8Array(30))).toBe(false);
      expect(client.sendScreenFragment(CH, fragment())).toBe(false);
      expect(client.screenShareStart(CH).handedOff).toBe(false);
      expect(client.getQueuedMessageCount()).toBe(queued);
      expect(ws.sent).toHaveLength(1); // only Authenticate

      ws.json({ type: 'authenticated', user_id: 'u' });
      ws.json(SCREEN_HELLO);
      ws.drop();
      expect(client.sendCallMessage(CH, PEER, 'acv1:BBBB')).toBe(false);
      expect(client.sendMediaFrame(CH, new Uint8Array(30))).toBe(false);
      expect(client.sendScreenFragment(CH, fragment())).toBe(false);
      expect(client.getQueuedMessageCount()).toBe(queued);

      vi.advanceTimersByTime(60_000);
      const ws2 = latest();
      expect(ws2).not.toBe(ws);
      ws2.open();
      ws2.json({ type: 'authenticated', user_id: 'u' });
      expect(ws2.sent).toHaveLength(1); // Authenticate only: nothing was queued
      expect(ws2.binarySent()).toHaveLength(0);
    });

    it('sendMediaFrame sends SrtpVoicePacket with the frame as standard base64, and sendCallMessage a targeted VoiceKeyExchange', () => {
      const ws = open(client, null);
      const frame = Uint8Array.from({ length: 33 }, (_, i) => (i * 7) & 0xff);
      expect(client.sendMediaFrame(CH, frame)).toBe(true);
      expect(client.sendCallMessage(CH, PEER, 'acv1:Zm9v')).toBe(true);
      const [media, call] = ws.jsonSent().slice(1);
      expect(Object.keys(media.message_type)).toEqual(['SrtpVoicePacket']);
      expect(media.message_type.SrtpVoicePacket.channel_id).toBe(CH);
      expect(decodeWireBase64(media.message_type.SrtpVoicePacket.packet_data)).toEqual(frame);
      expect(call.message_type).toEqual({
        VoiceKeyExchange: { channel_id: CH, wrapped_key: 'acv1:Zm9v', target_user_id: PEER, sender_ssrc: 0, key_generation: 0 },
      });
      // REQ-1: never without a target.
      expect(client.sendCallMessage(CH, '', 'acv1:Zm9v')).toBe(false);
      expect(ws.jsonSent()).toHaveLength(3);
    });

    it('the queuing send() refuses call traffic', () => {
      for (const t of ['VoiceKeyExchange', 'SrtpVoicePacket', 'ScreenShareStart', 'ScreenShareStop', 'ScreenWatch', 'ScreenKeyframeRequest']) {
        expect(() => client.send(JSON.stringify({ message_type: { [t]: { channel_id: CH } }, message_id: 'x', timestamp: 0 }))).toThrow(TypeError);
      }
      expect(client.getQueuedMessageCount()).toBe(0);
    });

    it('(A1) sendScreenFragment sends exactly one binary SCREEN_UP: type 0x01, the 16-byte channel id, the fragment', () => {
      const ws = open(client);
      const queued = client.getQueuedMessageCount();
      const f = fragment(100);
      expect(client.sendScreenFragment(CH, f)).toBe(true);
      const bins = ws.binarySent();
      expect(bins).toHaveLength(1);
      const msg = bins[0];
      expect(msg[0]).toBe(0x01);
      expect(Array.from(msg.subarray(1, 17), b => b.toString(16).padStart(2, '0')).join('')).toBe(CH.replace(/-/g, ''));
      expect(msg.subarray(17)).toEqual(f);
      expect(msg.length).toBe(117);
      expect(client.getQueuedMessageCount()).toBe(queued);
      // Fragments outside 20 to 16,384 bytes, or a malformed channel id, are refused.
      expect(client.sendScreenFragment(CH, fragment(19))).toBe(false);
      expect(client.sendScreenFragment(CH, fragment(16_385))).toBe(false);
      expect(client.sendScreenFragment('not-a-uuid', fragment())).toBe(false);
      expect(ws.binarySent()).toHaveLength(1);
    });

    it('bufferedAmount() reports the open socket\'s buffered bytes (REQ-47)', () => {
      const ws = open(client);
      ws.bufferedAmount = 65_537;
      expect(client.bufferedAmount()).toBe(65_537);
      ws.drop();
      expect(client.bufferedAmount()).toBe(0);
    });
  });

  describe('relay features and screen limits from hello (§6.1, §6.12.1)', () => {
    const cases: Array<[string, object, boolean]> = [
      ['no features', { type: 'hello' }, false],
      ['features without screen/1', { type: 'hello', features: ['admission/1'], screen_limits: { max_sharers: 2, max_bytes_per_second: 500_000 } }, false],
      ['screen/1 without screen_limits', { type: 'hello', features: ['screen/1'] }, false],
      ['max_sharers 0', { type: 'hello', features: ['screen/1'], screen_limits: { max_sharers: 0, max_bytes_per_second: 500_000 } }, false],
      ['max_sharers 9', { type: 'hello', features: ['screen/1'], screen_limits: { max_sharers: 9, max_bytes_per_second: 500_000 } }, false],
      ['max_sharers 1.5', { type: 'hello', features: ['screen/1'], screen_limits: { max_sharers: 1.5, max_bytes_per_second: 500_000 } }, false],
      ['max_sharers as a string', { type: 'hello', features: ['screen/1'], screen_limits: { max_sharers: '2', max_bytes_per_second: 500_000 } }, false],
      ['max_bytes_per_second 199,999', { type: 'hello', features: ['screen/1'], screen_limits: { max_sharers: 2, max_bytes_per_second: 199_999 } }, false],
      ['screen_limits an array', { type: 'hello', features: ['screen/1'], screen_limits: [2, 500_000] }, false],
      ['a screen-capable relay', SCREEN_HELLO, true],
      ['the lowest allowed limits', { type: 'hello', features: ['screen/1'], screen_limits: { max_sharers: 1, max_bytes_per_second: 200_000 } }, true],
    ];
    for (const [name, hello, capable] of cases) {
      it(`${name}: ${capable ? 'screen-capable' : 'not screen-capable'}, and screen messages ${capable ? 'are' : 'are not'} sent`, () => {
        const ws = open(client, hello);
        expect(client.isScreenCapable()).toBe(capable);
        expect(client.screenLimits() !== null).toBe(capable || (name.includes('without screen/1')));
        const start = client.screenShareStart(CH);
        const watch = client.screenWatch(CH, SHARER, true);
        const kfr = client.screenKeyframeRequest(CH, SHARER);
        const stop = client.screenShareStop(CH);
        const frag = client.sendScreenFragment(CH, fragment());
        for (const r of [start, watch, kfr, stop]) expect(r.handedOff).toBe(capable);
        expect(frag).toBe(capable);
        const types = ws.jsonSent().slice(1).map(m => Object.keys(m.message_type)[0]);
        expect(types).toEqual(capable ? ['ScreenShareStart', 'ScreenWatch', 'ScreenKeyframeRequest', 'ScreenShareStop'] : []);
      });
    }

    it('the screen JSON messages carry exactly the fields of §6.12.1', () => {
      const ws = open(client);
      const start = client.screenShareStart(CH);
      client.screenWatch(CH, SHARER, false);
      client.screenKeyframeRequest(CH, SHARER);
      client.screenShareStop(CH);
      const msgs = ws.jsonSent().slice(1);
      expect(msgs[0].message_id).toBe(start.messageId);
      expect(msgs.map(m => m.message_type)).toEqual([
        { ScreenShareStart: { channel_id: CH } },
        { ScreenWatch: { channel_id: CH, sharer_id: SHARER, watch: false } },
        { ScreenKeyframeRequest: { channel_id: CH, sharer_id: SHARER } },
        { ScreenShareStop: { channel_id: CH } },
      ]);
    });

    it('forgets features and limits on disconnect, and a new socket is not screen-capable before its own hello', () => {
      const ws = open(client);
      expect(client.isScreenCapable()).toBe(true);
      expect(client.helloProcessed()).toBe(true);
      ws.drop();
      expect(client.relayFeatures()).toEqual([]);
      expect(client.screenLimits()).toBeNull();
      expect(client.isScreenCapable()).toBe(false);
      expect(client.helloProcessed()).toBe(false);
      vi.advanceTimersByTime(60_000);
      const ws2 = latest();
      ws2.open();
      ws2.json({ type: 'authenticated', user_id: 'u' });
      expect(client.isScreenCapable()).toBe(false);
      // §8.4 row 3: open, but its hello not processed yet.
      expect(client.helloProcessed()).toBe(false);
      ws2.json(SCREEN_HELLO);
      expect(client.isScreenCapable()).toBe(true);
      expect(client.helloProcessed()).toBe(true);
    });

    it('helloProcessed() is true after any hello, also one without screen/1 (§8.4 rows 3 and 4)', () => {
      const ws = open(client);
      ws.drop();
      vi.advanceTimersByTime(60_000);
      const ws2 = latest();
      ws2.open();
      ws2.json({ type: 'authenticated', user_id: 'u' });
      ws2.json({ type: 'hello', protocol_version: 1 });
      expect(client.helloProcessed()).toBe(true);
      expect(client.isScreenCapable()).toBe(false);
    });

    it('parseScreenLimits keeps only well-formed limits', () => {
      expect(parseScreenLimits({ max_sharers: 8, max_bytes_per_second: 200_000 })).toEqual({ maxSharers: 8, maxBytesPerSecond: 200_000 });
      expect(parseScreenLimits(null)).toBeNull();
      expect(parseScreenLimits({ max_sharers: 2 })).toBeNull();
      expect(parseScreenLimits({ max_sharers: 2, max_bytes_per_second: Number.MAX_VALUE })).toBeNull();
    });
  });

  describe('binary messages (§6.12.2; T-26)', () => {
    it('a well-formed SCREEN_DOWN becomes screen_fragment, handled before JSON.parse', () => {
      const ws = open(client);
      const got: any[] = [];
      const errors: unknown[] = [];
      const messages: unknown[] = [];
      client.on('screen_fragment', e => got.push(e));
      client.on('error', e => errors.push(e));
      client.on('message', m => messages.push(m));
      const f = fragment(64);
      ws.binary(encodeScreenDown(CH, SHARER, f));
      expect(got).toHaveLength(1);
      expect(got[0].channelId).toBe(CH);
      expect(got[0].from).toBe(SHARER);
      expect(got[0].fragment).toEqual(f);
      expect(errors).toEqual([]);
      expect(messages).toEqual([]);
    });

    it('drops every other binary message silently: type bytes 0x00, 0x01 and 0x03, wrong sizes, Blobs, and before authentication', () => {
      const ws = open(client);
      const got: unknown[] = [];
      const errors: unknown[] = [];
      client.on('screen_fragment', e => got.push(e));
      client.on('error', e => errors.push(e));
      const good = encodeScreenDown(CH, SHARER, fragment(64));
      for (const type of [0x00, 0x01, 0x03]) {
        const m = Uint8Array.from(good);
        m[0] = type;
        ws.binary(m);
      }
      ws.binary(good.subarray(0, 52)); // below 53 bytes
      const long = new Uint8Array(16_418);
      long.set(good.subarray(0, 33));
      ws.binary(long); // above 16,417 bytes
      ws.binary(new Uint8Array(16)); // a 16-byte message
      ws.binary(new Blob([good])); // binaryType not honored
      expect(got).toEqual([]);
      expect(errors).toEqual([]);

      ws.drop();
      ws.binary(good); // the socket is gone
      expect(got).toEqual([]);
    });

    it('a JSON message never produces an event this class generates itself, such as screen_fragment or disconnected', () => {
      const ws = open(client);
      const local = ['screen_fragment', 'disconnected', 'connected', 'connection_status', 'reconnecting', 'auth_error', 'message'] as const;
      const got: Array<{ event: string; data: unknown }> = [];
      for (const event of local) client.on(event, (data: unknown) => got.push({ event, data }));
      for (const type of local) {
        ws.json({ type, channelId: CH, from: SHARER, fragment: [1, 2, 3], channel_id: CH, status: 'disconnected' });
      }
      // Each JSON message is still a `message` (the generic event), and nothing else.
      expect(got.filter(g => g.event !== 'message')).toEqual([]);
      expect(got.filter(g => g.event === 'message')).toHaveLength(local.length);
      expect(client.isSocketConnected()).toBe(true);
      // Relay error frames (SPEC-01 §6.3) are still delivered as `error`.
      const errors: unknown[] = [];
      client.on('error', e => errors.push(e));
      ws.json({ type: 'error', code: 'attachment_claim_failed', reason: 'x', error: 'y' });
      expect(errors).toEqual([{ type: 'error', code: 'attachment_claim_failed', reason: 'x', error: 'y' }]);
    });
  });

  it('REQ-39: no P2P, mode or legacy senders remain', () => {
    const c = client as unknown as Record<string, unknown>;
    for (const m of ['sendP2PSignal', 'setVoiceMode', 'sendVoicePacket', 'sendVoiceKeyExchange']) {
      expect(c[m]).toBeUndefined();
    }
  });
});
