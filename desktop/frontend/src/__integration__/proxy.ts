/**
 * A TCP proxy between the test clients and the relay (SPEC-02 §10.1, §10.3).
 *
 * It records every byte that crosses it, so the regression tests can scan the
 * "captured traffic" for keys and names, and it can play the malicious relay
 * (A1) for WebSocket frames: inject a frame into one client's socket, or drop
 * a frame the relay sent.
 *
 * The relay runs with `--no-tls`, so HTTP bodies cross in the clear. The
 * proxy keeps the HTTP bytes of each connection as one stream per direction,
 * so a secret that straddles two TCP reads (certain inside a 1 MiB body) is
 * still found by a scan. WebSocket frames from clients are masked (RFC 6455
 * §5.3), so the proxy parses frames in both directions and records each
 * message's unmasked payload whole (fragments joined); a scan of the raw bytes
 * alone would miss a key inside a client frame. The relay negotiates no
 * extensions, so payloads are never compressed.
 */

import net from 'node:net';

export interface WsFrame {
  /** Order across all connections. */
  readonly seq: number;
  readonly dir: 'c2s' | 's2c';
  readonly opcode: number;
  readonly payload: Buffer;
}

export interface ProxyConnection {
  readonly id: number;
  /** True once the first request turned out to be a WebSocket upgrade. */
  isWs: boolean;
  /** Raw HTTP bytes from the client, in order (a WebSocket's upgrade request included). */
  readonly httpC2s: Buffer[];
  /** Raw HTTP bytes from the relay, in order (a WebSocket's 101 answer included). */
  readonly httpS2c: Buffer[];
  /** Unmasked WebSocket messages, fragments joined, both directions. */
  readonly frames: WsFrame[];
  /** The token of the WebSocket `Authenticate` frame, once seen. */
  token: string | null;
  readonly client: net.Socket;
  readonly server: net.Socket;
}

/** Decides whether the relay's text frame reaches the client (A1 withholding). */
export type ServerFrameFilter = (conn: ProxyConnection, frame: Record<string, unknown>) => 'forward' | 'drop';

const HEADER_END = Buffer.from('\r\n\r\n');

/** One complete frame at the start of `buf`, or null when more bytes are needed. */
function parseFrame(buf: Buffer): { fin: boolean; opcode: number; payload: Buffer; length: number } | null {
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

/** An unmasked server-to-client text frame. */
export function textFrame(text: string): Buffer {
  const payload = Buffer.from(text, 'utf8');
  let header: Buffer;
  if (payload.length < 126) {
    header = Buffer.from([0x81, payload.length]);
  } else if (payload.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  return Buffer.concat([header, payload]);
}

/**
 * Parses one direction of a WebSocket connection after its handshake and
 * hands every frame to `onFrame`, which forwards or drops it.
 */
class FrameStream {
  private pending: Buffer = Buffer.alloc(0);
  private message: Buffer[] = [];
  private messageOpcode = 0;

  constructor(
    private readonly onFrame: (raw: Buffer, opcode: number, payload: Buffer, message: Buffer | null) => void,
  ) {}

  push(chunk: Buffer): void {
    this.pending = this.pending.length === 0 ? chunk : Buffer.concat([this.pending, chunk]);
    for (;;) {
      const f = parseFrame(this.pending);
      if (!f) return;
      const raw = this.pending.subarray(0, f.length);
      this.pending = this.pending.subarray(f.length);
      let complete: Buffer | null = null;
      if (f.opcode === 0x1 || f.opcode === 0x2) {
        this.message = [f.payload];
        this.messageOpcode = f.opcode;
        if (f.fin) complete = f.payload;
      } else if (f.opcode === 0x0) {
        this.message.push(f.payload);
        if (f.fin) complete = Buffer.concat(this.message);
      }
      this.onFrame(Buffer.from(raw), complete ? this.messageOpcode : f.opcode, f.payload, complete);
    }
  }
}

export class RecordingProxy {
  private serverSocket: net.Server | null = null;
  private nextId = 1;
  private nextSeq = 1;
  readonly connections: ProxyConnection[] = [];
  /** A1 withholding: the relay's text frames pass through this filter. */
  serverFrameFilter: ServerFrameFilter | null = null;
  /**
   * WebSocket handshakes whose 101 answer negotiated an extension. A
   * compressed payload would hide a leak from the scans, so tests expect 0.
   */
  extensionsNegotiated = 0;
  port = 0;

  constructor(private readonly targetPort: number) {}

  get baseUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  async start(): Promise<void> {
    this.serverSocket = net.createServer(client => this.accept(client));
    await new Promise<void>(resolve => this.serverSocket!.listen(0, '127.0.0.1', resolve));
    this.port = (this.serverSocket.address() as net.AddressInfo).port;
  }

  async close(): Promise<void> {
    for (const c of this.connections) {
      c.client.destroy();
      c.server.destroy();
    }
    await new Promise<void>(resolve => (this.serverSocket ? this.serverSocket.close(() => resolve()) : resolve()));
  }

  /** WebSocket connections authenticated with `token`. */
  socketsOf(token: string): ProxyConnection[] {
    return this.connections.filter(c => c.isWs && c.token === token && !c.client.destroyed);
  }

  /** A1 injection: write a text frame to every live WebSocket of `token`'s holder. */
  inject(token: string, frame: Record<string, unknown>): number {
    const conns = this.socketsOf(token);
    for (const c of conns) {
      const text = JSON.stringify(frame);
      c.frames.push({ seq: this.nextSeq++, dir: 's2c', opcode: 1, payload: Buffer.from(text, 'utf8') });
      c.client.write(textFrame(text));
    }
    return conns.length;
  }

  /** Close every live WebSocket of `token`'s holder, as a network failure would. */
  cutSockets(token: string): void {
    for (const c of this.socketsOf(token)) {
      c.client.destroy();
      c.server.destroy();
    }
  }

  /**
   * Every recorded byte sequence, for leak scans: per connection, the HTTP
   * bytes of each direction joined into one buffer (so nothing is split at a
   * TCP read boundary), and each WebSocket message's unmasked payload whole.
   */
  capturedChunks(): Buffer[] {
    const out: Buffer[] = [];
    for (const c of this.connections) {
      if (c.httpC2s.length > 0) out.push(Buffer.concat(c.httpC2s));
      if (c.httpS2c.length > 0) out.push(Buffer.concat(c.httpS2c));
      for (const f of c.frames) out.push(f.payload);
    }
    return out;
  }

  /** A position in the frame order; frames recorded later have a greater `seq`. */
  mark(): number {
    return this.nextSeq;
  }

  /** The JSON text frames that crossed in one direction since `since` (a `mark()`), in order. */
  jsonFrames(dir: 'c2s' | 's2c', since = 0): Array<{ conn: ProxyConnection; frame: Record<string, unknown> }> {
    const out: Array<{ seq: number; conn: ProxyConnection; frame: Record<string, unknown> }> = [];
    for (const c of this.connections) {
      for (const f of c.frames) {
        if (f.dir !== dir || f.opcode !== 1 || f.seq < since) continue;
        try {
          const v = JSON.parse(f.payload.toString('utf8'));
          if (v && typeof v === 'object') out.push({ seq: f.seq, conn: c, frame: v });
        } catch {
          // not JSON
        }
      }
    }
    return out.sort((a, b) => a.seq - b.seq).map(({ conn, frame }) => ({ conn, frame }));
  }

  private accept(client: net.Socket): void {
    const server = net.connect(this.targetPort, '127.0.0.1');
    const conn: ProxyConnection = {
      id: this.nextId++,
      isWs: false,
      httpC2s: [],
      httpS2c: [],
      frames: [],
      token: null,
      client,
      server,
    };
    this.connections.push(conn);

    // HTTP/1.1 keep-alive: undici may send the WebSocket handshake on a pooled
    // connection after ordinary requests, so requests are delimited (headers,
    // then Content-Length body bytes) until one of them upgrades.
    let c2sBuf: Buffer = Buffer.alloc(0);
    let bodyRemaining = 0;
    let awaiting101 = false;
    let s2cHead: Buffer = Buffer.alloc(0);
    let c2sFrames: FrameStream | null = null;
    let s2cFrames: FrameStream | null = null;

    // Only complete data messages are recorded, each with its whole payload.
    const record = (frameDir: 'c2s' | 's2c', opcode: number, message: Buffer | null) => {
      if (message && (opcode === 0x1 || opcode === 0x2)) conn.frames.push({ seq: this.nextSeq++, dir: frameDir, opcode, payload: message });
    };

    const startClientFrames = (initial: Buffer) => {
      c2sFrames = new FrameStream((_raw, opcode, _payload, message) => {
        record('c2s', opcode, message);
        if (message && opcode === 0x1) {
          try {
            const v = JSON.parse(message.toString('utf8'));
            if (v && typeof v === 'object' && v.Authenticate && typeof v.Authenticate.token === 'string') conn.token = v.Authenticate.token;
          } catch {
            // not JSON
          }
        }
      });
      if (initial.length > 0) c2sFrames.push(initial);
    };

    const scanRequests = () => {
      for (;;) {
        if (bodyRemaining > 0) {
          const take = Math.min(bodyRemaining, c2sBuf.length);
          c2sBuf = c2sBuf.subarray(take);
          bodyRemaining -= take;
          if (bodyRemaining > 0) return;
        }
        const end = c2sBuf.indexOf(HEADER_END);
        if (end < 0) return;
        const head = c2sBuf.subarray(0, end + 4).toString('latin1');
        c2sBuf = c2sBuf.subarray(end + 4);
        if (/^GET \/ws[ ?]/.test(head) && /\r\nupgrade:\s*websocket/i.test(head)) {
          conn.isWs = true;
          awaiting101 = true;
          startClientFrames(Buffer.from(c2sBuf));
          c2sBuf = Buffer.alloc(0);
          return;
        }
        const cl = /\r\ncontent-length:\s*(\d+)/i.exec(head);
        bodyRemaining = cl ? Number(cl[1]) : 0;
      }
    };

    client.on('data', (chunk: Buffer) => {
      server.write(chunk);
      if (c2sFrames) {
        (c2sFrames as FrameStream).push(chunk);
        return;
      }
      conn.httpC2s.push(Buffer.from(chunk));
      c2sBuf = c2sBuf.length === 0 ? Buffer.from(chunk) : Buffer.concat([c2sBuf, chunk]);
      scanRequests();
    });

    server.on('data', (chunk: Buffer) => {
      if (s2cFrames) {
        (s2cFrames as FrameStream).push(chunk);
        return;
      }
      if (!awaiting101) {
        conn.httpS2c.push(Buffer.from(chunk));
        client.write(chunk);
        return;
      }
      s2cHead = Buffer.concat([s2cHead, chunk]);
      const end = s2cHead.indexOf(HEADER_END);
      if (end < 0) return;
      const head = s2cHead.subarray(0, end + 4);
      const rest = s2cHead.subarray(end + 4);
      if (/\r\nsec-websocket-extensions:/i.test(head.toString('latin1'))) this.extensionsNegotiated++;
      conn.httpS2c.push(Buffer.from(head));
      client.write(head);
      s2cFrames = new FrameStream((raw, opcode, _payload, message) => {
        let verdict: 'forward' | 'drop' = 'forward';
        if (message && opcode === 0x1 && this.serverFrameFilter) {
          try {
            const v = JSON.parse(message.toString('utf8'));
            if (v && typeof v === 'object') verdict = this.serverFrameFilter(conn, v);
          } catch {
            // not JSON: forward
          }
        }
        if (verdict === 'forward') {
          record('s2c', opcode, message);
          client.write(raw);
        }
      });
      if (rest.length > 0) s2cFrames.push(Buffer.from(rest));
    });

    const teardown = () => {
      client.destroy();
      server.destroy();
    };
    client.on('error', teardown);
    server.on('error', teardown);
    client.on('close', () => server.end());
    server.on('close', () => client.end());
  }
}
