/**
 * The hostile relay proxy (HRP) of SPEC-03 §10.1: a test-only WebSocket and
 * HTTP proxy on 127.0.0.1 between the headless clients and the real relay.
 *
 * HTTP requests are parsed by `node:http` and forwarded to the relay with
 * `http.request`; a rule can substitute any response (REST substitution,
 * for example a member list without a user). WebSocket upgrades are taken
 * over at the TCP level: the handshake is forwarded byte for byte, then the
 * proxy parses every frame in both directions (client frames are masked,
 * RFC 6455 §5.3), joins fragmented messages, and hands each complete text
 * or binary message to the rules of its direction. A rule can forward,
 * drop, modify, duplicate or delay the message, or hold it for later
 * delivery; tests can inject text (JSON) and binary messages in either
 * direction. Messages are re-framed on the way out (masked towards the
 * relay), so modified or injected client messages are valid frames.
 *
 * Binary messages are the screen-sharing `SCREEN_UP` and `SCREEN_DOWN` of
 * §6.12.2; `screenUp` and `screenDown` decode them for rules and analyses.
 *
 * Every message that reaches the proxy is recorded in `log` (with its
 * direction, connection, time and, for text, its parsed JSON), and every
 * HTTP request and response body in `http`, for the leak scans.
 *
 * Link emulation: either direction of one connection can be throttled to a
 * byte rate, or stopped (the proxy stops reading the source socket, so the
 * sender's kernel buffers and then its own queues fill), and the proxy
 * never buffers more than about 64 KiB per direction (or the smaller link
 * buffer a throttle names) before it stops reading the source, so
 * backpressure reaches the real endpoints. Node has no API to set
 * `SO_RCVBUF` on a TCP socket, so the 64 KiB receive buffers that §10.1
 * asks for come from the kernel: the CI voice job caps the
 * `net.ipv4.tcp_rmem` maximum at 64 KiB (`kernelReceiveBuffersCapped` in
 * world.ts) and leaves send buffers large, so the relay's TCP_NOTSENT_LOWAT
 * (A2) is what bounds its unsent data. Without that cap, loopback kernel
 * buffers absorb a few megabytes before a stalled reader pushes back
 * (measured: about 3 MB for a 500 KB/s writer), and the queue-fill tests
 * run their fallback forms.
 */

import http from 'node:http';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { decodeScreenDown, decodeScreenUp, type ScreenDownMessage, type ScreenUpMessage } from '../../src/voice/screenFrame';

export type Dir = 'c2s' | 's2c';

export interface HrpConn {
  readonly id: number;
  /** The token of the WebSocket's `Authenticate` frame, once seen. */
  token: string | null;
  /** The user id of the relay's `authenticated` frame, once seen. */
  userId: string | null;
  readonly client: net.Socket;
  readonly server: net.Socket;
  closed: boolean;
  readonly openedAt: number;
  /** Per-direction output state (throttle, queue, stall). */
  readonly out: Record<Dir, Writer>;
}

export interface HrpMessage {
  /** Order across all connections and directions. */
  readonly seq: number;
  /** `Date.now()` when the message reached the proxy (or was injected). */
  readonly at: number;
  readonly dir: Dir;
  readonly conn: HrpConn;
  /** 1 text, 2 binary. */
  readonly opcode: 1 | 2;
  readonly data: Buffer;
  /** The parsed JSON of a text message, or null. */
  readonly json: Record<string, any> | null;
  readonly injected: boolean;
  /** When the proxy wrote the message, unchanged, to its destination (unset when dropped or replaced). */
  forwardedAt?: number;
}

/** What a rule or a test sends: JSON (text), a string (text) or bytes (binary). */
export type Outgoing = Record<string, unknown> | string | Uint8Array;

/**
 * A rule's decision: undefined passes the message to the next rule (and
 * finally forwards it), 'drop' discards it, and `send` replaces it with
 * zero or more messages, optionally after a delay.
 */
export type RuleResult = undefined | 'drop' | { readonly send: readonly Outgoing[]; readonly delayMs?: number };
export type Rule = (msg: HrpMessage) => RuleResult;

export interface HttpExchange {
  readonly seq: number;
  readonly at: number;
  readonly method: string;
  readonly path: string;
  readonly token: string | null;
  readonly requestBody: Buffer;
  responseStatus: number;
  responseBody: Buffer;
  readonly substituted: boolean;
}

/** A REST substitution: answer this request locally instead of forwarding it. */
export type HttpRule = (req: { method: string; path: string; token: string | null; body: Buffer }) =>
  | { status: number; json: unknown }
  | undefined;

const HEADER_END = Buffer.from('\r\n\r\n');
/** Bytes the proxy queues per direction before it stops reading the source. */
const QUEUE_HIGH = 64 * 1024;
const QUEUE_LOW = 16 * 1024;
/** The readable and writable buffers of the proxy's sockets (Node's default is 64 KiB). */
const PROXY_STREAM_HWM = 16 * 1024;
/**
 * The proxy reads the relay's side of each WebSocket into one buffer of this
 * size (`net.connect`'s `onread`), so a paused relay socket stops being read
 * at once and one read never takes more than this from the kernel (a plain
 * Node socket reads 64 KiB at a time and keeps reading into its stream
 * buffer after `pause()`). What the proxy holds of a slow link is then its
 * queue mark plus at most one read, for the bounds of T-51 and RG-SCR-8.
 */
export const PROXY_READ_SIZE = 16 * 1024;

interface RawFrame {
  fin: boolean;
  opcode: number;
  payload: Buffer;
  length: number;
}

function parseFrame(buf: Buffer): RawFrame | null {
  if (buf.length < 2) return null;
  const fin = (buf[0] & 0x80) !== 0;
  const opcode = buf[0] & 0x0f;
  const masked = (buf[1] & 0x80) !== 0;
  let len = buf[1] & 0x7f;
  let off = 2;
  if (len === 126) {
    if (buf.length < 4) return null;
    len = buf.readUInt16BE(2);
    off = 4;
  } else if (len === 127) {
    if (buf.length < 10) return null;
    len = Number(buf.readBigUInt64BE(2));
    off = 10;
  }
  let mask: Buffer | null = null;
  if (masked) {
    if (buf.length < off + 4) return null;
    mask = buf.subarray(off, off + 4);
    off += 4;
  }
  if (buf.length < off + len) return null;
  const payload = Buffer.from(buf.subarray(off, off + len));
  if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
  return { fin, opcode, payload, length: off + len };
}

/** One frame, FIN set; masked when it goes to the relay (RFC 6455 §5.3). */
export function encodeFrame(opcode: number, payload: Buffer, masked: boolean): Buffer {
  const len = payload.length;
  let head: Buffer;
  if (len < 126) {
    head = Buffer.from([0x80 | opcode, (masked ? 0x80 : 0) | len]);
  } else if (len < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x80 | opcode;
    head[1] = (masked ? 0x80 : 0) | 126;
    head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x80 | opcode;
    head[1] = (masked ? 0x80 : 0) | 127;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  if (!masked) return Buffer.concat([head, payload]);
  const mask = randomBytes(4);
  const body = Buffer.from(payload);
  for (let i = 0; i < body.length; i++) body[i] ^= mask[i & 3];
  return Buffer.concat([head, mask, body]);
}

/** Parses one direction after the handshake: complete data messages and control frames. */
class FrameStream {
  private pending: Buffer = Buffer.alloc(0);
  private parts: Buffer[] = [];
  private opcode = 0;

  constructor(
    private readonly onMessage: (opcode: 1 | 2, payload: Buffer) => void,
    private readonly onControl: (raw: Buffer, opcode: number) => void,
  ) {}

  push(chunk: Buffer): void {
    this.pending = this.pending.length === 0 ? chunk : Buffer.concat([this.pending, chunk]);
    for (;;) {
      const f = parseFrame(this.pending);
      if (!f) return;
      const raw = Buffer.from(this.pending.subarray(0, f.length));
      this.pending = this.pending.subarray(f.length);
      if (f.opcode === 0x1 || f.opcode === 0x2) {
        this.opcode = f.opcode;
        this.parts = [f.payload];
        if (f.fin) this.onMessage(f.opcode as 1 | 2, f.payload);
      } else if (f.opcode === 0x0) {
        this.parts.push(f.payload);
        if (f.fin) this.onMessage(this.opcode as 1 | 2, Buffer.concat(this.parts));
      } else {
        this.onControl(raw, f.opcode);
      }
    }
  }
}

/**
 * The output side of one direction of one connection: a queue of encoded
 * frames written to the destination socket, optionally at a byte rate.
 * While more than `QUEUE_HIGH` bytes wait (here or in Node's socket
 * buffer), the source socket is paused.
 */
class Writer {
  private queue: Buffer[] = [];
  private queued = 0;
  private rate: number | null = null;
  /** Bytes held here (and in Node's socket buffer) before the source is paused, and resumed below. */
  private high = QUEUE_HIGH;
  private low = QUEUE_LOW;
  private tokens = 0;
  private lastRefill = Date.now();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly pausers = new Set<string>();
  private readonly callbacks = new Map<Buffer, () => void>();
  closed = false;

  constructor(
    private readonly dest: net.Socket,
    private readonly source: net.Socket,
  ) {
    dest.on('drain', () => this.pump());
  }

  /**
   * Throttle to `bytesPerSecond`, or remove the throttle with null.
   * `buffer` is the link's own queue: what the proxy holds before it stops
   * reading the source (default 64 KiB).
   */
  throttle(bytesPerSecond: number | null, buffer?: number): void {
    this.rate = bytesPerSecond;
    this.high = buffer ?? QUEUE_HIGH;
    this.low = Math.min(QUEUE_LOW, Math.floor(this.high / 2));
    this.tokens = 0;
    this.lastRefill = Date.now();
    this.pump();
  }

  /** Stop or resume reading the source socket (a stalled reader). */
  stall(on: boolean): void {
    this.setPaused('stall', on);
  }

  write(frame: Buffer, onWritten?: () => void): void {
    if (this.closed) return;
    this.queue.push(frame);
    if (onWritten) this.callbacks.set(frame, onWritten);
    this.queued += frame.length;
    this.pump();
  }

  private setPaused(reason: string, on: boolean): void {
    if (on) this.pausers.add(reason);
    else this.pausers.delete(reason);
    if (this.pausers.size > 0) this.source.pause();
    else if (!this.source.destroyed) this.source.resume();
  }

  private pump(): void {
    if (this.closed) return;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    const now = Date.now();
    if (this.rate !== null) {
      this.tokens = Math.min(this.tokens + ((now - this.lastRefill) * this.rate) / 1000, Math.max(this.rate / 20, 16_500));
      this.lastRefill = now;
    }
    while (this.queue.length > 0 && this.dest.writableLength < this.high) {
      const next = this.queue[0];
      if (this.rate !== null && this.tokens < Math.min(next.length, 1)) break;
      this.queue.shift();
      this.queued -= next.length;
      if (this.rate !== null) this.tokens -= next.length;
      if (!this.dest.destroyed) this.dest.write(next);
      const cb = this.callbacks.get(next);
      if (cb) {
        this.callbacks.delete(next);
        cb();
      }
    }
    const backlog = this.queued + this.dest.writableLength;
    if (backlog > this.high) this.setPaused('backpressure', true);
    else if (backlog < this.low) this.setPaused('backpressure', false);
    if (this.queue.length > 0 && this.rate !== null) {
      const deficit = Math.max(1, -this.tokens + 1);
      this.timer = setTimeout(() => this.pump(), Math.max(2, Math.min(50, (deficit * 1000) / this.rate)));
    }
  }

  close(): void {
    this.closed = true;
    if (this.timer) clearTimeout(this.timer);
    this.queue = [];
    this.queued = 0;
    this.callbacks.clear();
  }
}

export class HostileRelayProxy {
  private httpServer: http.Server | null = null;
  private nextConn = 1;
  private nextSeq = 1;
  port = 0;
  readonly connections: HrpConn[] = [];
  readonly log: HrpMessage[] = [];
  readonly http: HttpExchange[] = [];
  /** Rules per direction, run in order; the first decision wins. */
  readonly rules: Record<Dir, Rule[]> = { c2s: [], s2c: [] };
  readonly httpRules: HttpRule[] = [];
  /** Record binary payloads in `log` (large screen tests may turn it off). */
  recordBinary = true;
  /** Remove `screen/1` and `screen_limits` from every `hello`, or from those of the connections it selects (RG-C117-1, RG-SCR-10). */
  stripScreenFeature: boolean | ((conn: HrpConn) => boolean) = false;
  /** Replace `screen_limits` in every `hello` with this value (T-42-style tampering). */
  screenLimitsOverride: unknown = undefined;
  private readonly timers = new Set<ReturnType<typeof setTimeout>>();

  constructor(private readonly relayPort: number) {}

  get baseUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  async start(): Promise<void> {
    // Small stream buffers: a paused socket keeps at most this much in the
    // proxy's memory, so the kernel's buffers (64 KiB under the CI cap) are
    // what a slow link holds, as §10.1 intends.
    const server = http.createServer({ highWaterMark: PROXY_STREAM_HWM }, (req, res) => void this.onRequest(req, res));
    server.on('upgrade', (req, socket, head) => this.onUpgrade(req, socket as net.Socket, head));
    server.keepAliveTimeout = 5000;
    this.httpServer = server;
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    this.port = (server.address() as net.AddressInfo).port;
  }

  async close(): Promise<void> {
    for (const t of this.timers) clearTimeout(t);
    this.timers.clear();
    for (const c of this.connections) this.closeConn(c);
    const server = this.httpServer;
    if (!server) return;
    server.closeAllConnections?.();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }

  // ---------------------------------------------------------------------------
  // Rules and helpers for tests
  // ---------------------------------------------------------------------------

  /** Add a rule; returns a function that removes it. */
  addRule(dir: Dir, rule: Rule): () => void {
    this.rules[dir].push(rule);
    return () => {
      const i = this.rules[dir].indexOf(rule);
      if (i >= 0) this.rules[dir].splice(i, 1);
    };
  }

  addHttpRule(rule: HttpRule): () => void {
    this.httpRules.push(rule);
    return () => {
      const i = this.httpRules.indexOf(rule);
      if (i >= 0) this.httpRules.splice(i, 1);
    };
  }

  /** The live WebSocket connections of a user, oldest first. */
  connsOf(userId: string): HrpConn[] {
    const u = userId.toLowerCase();
    return this.connections.filter(c => !c.closed && c.userId === u);
  }

  /** Inject a message towards the client (`s2c`) or the relay (`c2s`) on every live connection of `userId`. */
  inject(userId: string, dir: Dir, msg: Outgoing): number {
    const conns = this.connsOf(userId);
    for (const c of conns) this.deliver(c, dir, msg, true);
    return conns.length;
  }

  /** Deliver a message on one connection (a held message, or an injection). */
  deliver(conn: HrpConn, dir: Dir, msg: Outgoing, injected = true): void {
    if (conn.closed) return;
    const { opcode, data } = this.encode(msg);
    if (injected) this.record(conn, dir, opcode, data, true);
    conn.out[dir].write(encodeFrame(opcode, data, dir === 'c2s'));
  }

  /** Close both sides of a connection, as a network failure would. */
  closeConn(conn: HrpConn): void {
    if (conn.closed) return;
    conn.closed = true;
    conn.out.c2s.close();
    conn.out.s2c.close();
    conn.client.destroy();
    conn.server.destroy();
  }

  /** Close every live WebSocket of `userId`. */
  closeUser(userId: string): void {
    for (const c of this.connsOf(userId)) this.closeConn(c);
  }

  /**
   * Throttle one direction of a connection (null removes the throttle);
   * `buffer` bounds the proxy's own queue on that link (default 64 KiB).
   */
  throttle(conn: HrpConn, dir: Dir, bytesPerSecond: number | null, buffer?: number): void {
    conn.out[dir].throttle(bytesPerSecond, buffer);
  }

  /**
   * Stop (or resume) reading one direction's source: `s2c` stops reading
   * the relay's socket of this connection, `c2s` the client's.
   */
  stall(conn: HrpConn, dir: Dir, on: boolean): void {
    conn.out[dir].stall(on);
  }

  /** A position in the message order; later messages have a greater `seq`. */
  mark(): number {
    return this.nextSeq;
  }

  /** Recorded messages matching the filter, in order. */
  messages(filter: { dir?: Dir; user?: string; type?: string; since?: number; opcode?: 1 | 2; injected?: boolean } = {}): HrpMessage[] {
    const u = filter.user?.toLowerCase();
    return this.log.filter(m =>
      (filter.dir === undefined || m.dir === filter.dir) &&
      (u === undefined || m.conn.userId === u) &&
      (filter.since === undefined || m.seq >= filter.since) &&
      (filter.opcode === undefined || m.opcode === filter.opcode) &&
      (filter.injected === undefined || m.injected === filter.injected) &&
      (filter.type === undefined || typeOf(m) === filter.type));
  }

  /** Every recorded byte sequence (HTTP bodies and WebSocket payloads), for leak scans. */
  capturedChunks(): Buffer[] {
    const out: Buffer[] = [];
    for (const h of this.http) {
      if (h.requestBody.length > 0) out.push(h.requestBody);
      if (h.responseBody.length > 0) out.push(h.responseBody);
    }
    for (const m of this.log) out.push(m.data);
    return out;
  }

  /** Run `fn` after `ms`, cancelled when the proxy closes. */
  later(ms: number, fn: () => void): void {
    const t = setTimeout(() => {
      this.timers.delete(t);
      fn();
    }, ms);
    this.timers.add(t);
  }

  // ---------------------------------------------------------------------------
  // HTTP
  // ---------------------------------------------------------------------------

  private async onRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks);
    const auth = req.headers.authorization;
    const token = typeof auth === 'string' && auth.startsWith('Bearer ') ? auth.slice(7) : null;
    const method = req.method ?? 'GET';
    const path = req.url ?? '/';
    for (const rule of this.httpRules) {
      const sub = rule({ method, path, token, body });
      if (!sub) continue;
      const out = Buffer.from(JSON.stringify(sub.json));
      this.http.push({ seq: this.nextSeq++, at: Date.now(), method, path, token, requestBody: body, responseStatus: sub.status, responseBody: out, substituted: true });
      res.writeHead(sub.status, { 'content-type': 'application/json', 'content-length': String(out.length), 'access-control-allow-origin': '*' });
      res.end(out);
      return;
    }
    const exchange: HttpExchange = { seq: this.nextSeq++, at: Date.now(), method, path, token, requestBody: body, responseStatus: 0, responseBody: Buffer.alloc(0), substituted: false };
    this.http.push(exchange);
    const headers = { ...req.headers };
    delete headers['content-length'];
    if (body.length > 0) headers['content-length'] = String(body.length);
    const upstream = http.request({ host: '127.0.0.1', port: this.relayPort, method, path, headers }, up => {
      exchange.responseStatus = up.statusCode ?? 0;
      const respChunks: Buffer[] = [];
      res.writeHead(up.statusCode ?? 502, up.headers);
      up.on('data', (c: Buffer) => {
        respChunks.push(c);
        res.write(c);
      });
      up.on('end', () => {
        exchange.responseBody = Buffer.concat(respChunks);
        res.end();
      });
      up.on('error', () => res.destroy());
    });
    upstream.on('error', () => {
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
    upstream.end(body);
  }

  // ---------------------------------------------------------------------------
  // WebSocket
  // ---------------------------------------------------------------------------

  private onUpgrade(req: http.IncomingMessage, client: net.Socket, head: Buffer): void {
    // Every read from the relay goes to `onServerData`, a copy of at most PROXY_READ_SIZE bytes.
    let onServerData: (chunk: Buffer) => void = () => undefined;
    const readBuffer = Buffer.alloc(PROXY_READ_SIZE);
    const server = net.connect({
      port: this.relayPort,
      host: '127.0.0.1',
      writableHighWaterMark: PROXY_STREAM_HWM,
      onread: {
        buffer: readBuffer,
        callback: (n: number, buf: Uint8Array) => {
          onServerData(Buffer.from(buf.subarray(0, n)));
          return true;
        },
      },
    } as net.NetConnectOpts);
    client.setNoDelay(true);
    server.setNoDelay(true);
    const conn: HrpConn = {
      id: this.nextConn++,
      token: null,
      userId: null,
      client,
      server,
      closed: false,
      openedAt: Date.now(),
      out: { c2s: new Writer(server, client), s2c: new Writer(client, server) },
    };
    this.connections.push(conn);

    let request = `${req.method} ${req.url} HTTP/1.1\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      // No extension is negotiated, so payloads are never compressed.
      if (/^sec-websocket-extensions$/i.test(req.rawHeaders[i])) continue;
      request += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
    }
    request += '\r\n';
    server.write(request);

    const c2s = new FrameStream(
      (opcode, payload) => this.onMessage(conn, 'c2s', opcode, payload),
      raw => conn.out.c2s.write(raw),
    );
    let s2c: FrameStream | null = null;
    let s2cHead: Buffer = Buffer.alloc(0);
    const earlyClient: Buffer[] = head.length > 0 ? [Buffer.from(head)] : [];

    client.on('data', (chunk: Buffer) => {
      if (!s2c) {
        earlyClient.push(Buffer.from(chunk));
        return;
      }
      c2s.push(chunk);
    });
    onServerData = (chunk: Buffer) => {
      if (conn.closed) return;
      if (s2c) {
        s2c.push(chunk);
        return;
      }
      s2cHead = Buffer.concat([s2cHead, chunk]);
      const end = s2cHead.indexOf(HEADER_END);
      if (end < 0) return;
      const response = s2cHead.subarray(0, end + 4);
      const rest = s2cHead.subarray(end + 4);
      client.write(response);
      s2c = new FrameStream(
        (opcode, payload) => this.onMessage(conn, 's2c', opcode, payload),
        raw => conn.out.s2c.write(raw),
      );
      if (rest.length > 0) s2c.push(Buffer.from(rest));
      for (const b of earlyClient.splice(0)) c2s.push(b);
    };

    const teardown = () => this.closeConn(conn);
    client.on('error', teardown);
    server.on('error', teardown);
    client.on('close', teardown);
    server.on('close', teardown);
  }

  private encode(msg: Outgoing): { opcode: 1 | 2; data: Buffer } {
    if (msg instanceof Uint8Array) return { opcode: 2, data: Buffer.from(msg) };
    if (typeof msg === 'string') return { opcode: 1, data: Buffer.from(msg, 'utf8') };
    return { opcode: 1, data: Buffer.from(JSON.stringify(msg), 'utf8') };
  }

  private record(conn: HrpConn, dir: Dir, opcode: 1 | 2, data: Buffer, injected: boolean): HrpMessage {
    let json: Record<string, any> | null = null;
    if (opcode === 1) {
      try {
        const v = JSON.parse(data.toString('utf8'));
        if (v && typeof v === 'object') json = v;
      } catch {
        json = null;
      }
    }
    const msg: HrpMessage = { seq: this.nextSeq++, at: Date.now(), dir, conn, opcode, data, json, injected };
    if (opcode === 1 || this.recordBinary) this.log.push(msg);
    return msg;
  }

  private onMessage(conn: HrpConn, dir: Dir, opcode: 1 | 2, payload: Buffer): void {
    let data = payload;
    const logged = this.record(conn, dir, opcode, data, false);
    let msg = logged;
    if (dir === 'c2s' && msg.json && msg.json.Authenticate && typeof msg.json.Authenticate.token === 'string') {
      conn.token = msg.json.Authenticate.token;
    }
    if (dir === 's2c' && msg.json) {
      if (msg.json.type === 'authenticated' && typeof msg.json.user_id === 'string') conn.userId = msg.json.user_id.toLowerCase();
      const strip = typeof this.stripScreenFeature === 'function' ? this.stripScreenFeature(conn) : this.stripScreenFeature;
      if (msg.json.type === 'hello' && (strip || this.screenLimitsOverride !== undefined)) {
        const hello: Record<string, unknown> = { ...msg.json };
        if (strip) {
          hello.features = Array.isArray(hello.features) ? (hello.features as unknown[]).filter(f => f !== 'screen/1') : hello.features;
          delete hello.screen_limits;
        } else {
          hello.screen_limits = this.screenLimitsOverride;
        }
        data = Buffer.from(JSON.stringify(hello));
        msg = { ...msg, data, json: hello };
      }
    }
    for (const rule of this.rules[dir]) {
      let r: RuleResult;
      try {
        r = rule(msg);
      } catch {
        r = undefined;
      }
      if (r === undefined) continue;
      if (r === 'drop') return;
      const frames = r.send.map(o => this.encode(o));
      const write = () => {
        for (const f of frames) conn.out[dir].write(encodeFrame(f.opcode, f.data, dir === 'c2s'));
      };
      if (r.delayMs && r.delayMs > 0) this.later(r.delayMs, write);
      else write();
      return;
    }
    conn.out[dir].write(encodeFrame(opcode, data, dir === 'c2s'), () => {
      logged.forwardedAt = Date.now();
    });
  }
}

/** The message type: `type` of a relay message, the variant name of a client message, or SCREEN_UP / SCREEN_DOWN. */
export function typeOf(m: HrpMessage): string {
  if (m.opcode === 2) return m.dir === 'c2s' ? 'SCREEN_UP' : 'SCREEN_DOWN';
  const j = m.json;
  if (!j) return '';
  if (typeof j.type === 'string') return j.type;
  const mt = j.message_type;
  if (typeof mt === 'string') return mt;
  if (mt && typeof mt === 'object') return Object.keys(mt)[0] ?? '';
  if (j.Authenticate) return 'Authenticate';
  return '';
}

/** The body of a client message (`message_type.<Variant>`), or null. */
export function clientBody(m: HrpMessage): Record<string, any> | null {
  const mt = m.json?.message_type;
  if (!mt || typeof mt !== 'object') return null;
  const v = Object.values(mt)[0];
  return v && typeof v === 'object' ? (v as Record<string, any>) : null;
}

export function screenUp(m: HrpMessage): ScreenUpMessage | null {
  return m.opcode === 2 && m.dir === 'c2s' && m.data.length > 0 ? decodeScreenUp(new Uint8Array(m.data)) : null;
}

export function screenDown(m: HrpMessage): ScreenDownMessage | null {
  return m.opcode === 2 && m.dir === 's2c' && m.data.length > 0 ? decodeScreenDown(new Uint8Array(m.data)) : null;
}
