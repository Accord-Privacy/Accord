// @vitest-environment node
/**
 * SPEC-02 send orchestration: T-6, T-7, T-8 (h), T-12, T-13, T-14 (the
 * mismatch half), T-15, T-16, T-47, T-49, T-52 and the regression replays
 * RG-C090, RG-C192 and RG-C193.
 *
 * Sealing is real: Sender Keys and the Double Ratchet through the production
 * sealer (`attachments/sealer.ts`), and A256GCM-STREAM64K through
 * `format.ts`. A test peer decrypts the captured frames. The relay is a fake
 * transport that records every upload body, deletion and frame.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { decodeWireBase64, encodeBase64 } from './base64';
import {
  PendingSendManager,
  PAIRING_TIMEOUT_MS,
  RESOLUTION_DEADLINE_MS,
  UPLOAD_NETWORK_RETRIES,
  estimateEnvelopeBytes,
  type ConversationSealer,
  type HistoryPage,
  type PendingEvent,
  type PendingView,
  type SendInput,
  type StagedSource,
} from './send';
import { createConversationSealer } from './sealer';
import { parseEnvelope, readCacheValue, MAX_ENVELOPE_BYTES, type DescriptorFields } from './envelope';
import { blobLength, CLIENT_MAX_BLOB_BYTES, openAttachment, padme } from './format';
import { decodeMessage, PLACEHOLDER_TEXT } from './decode';
import { AttachmentStore } from './store';
import { ENVELOPE_PREFIX, utf8ByteLength } from '../e2ee/plaintext';
import {
  E2EEManager,
  SenderKeyStore,
  buildDistributionMessage,
  decryptChannelMessage,
  generateIdentityKeyPair,
  generateOneTimePreKeys,
  generateSignedPreKey,
  isSenderKeyEnvelope,
  parseDistributionMessage,
} from '../e2ee';
import type { SealedPayload } from '../e2ee/sealed';
import type { ChannelSendOptions } from '../ws';
import type { UploadAttachmentResponse } from '../types';

const ORIGIN = 'https://relay.example';
const X = '7c9e6679-7425-40de-944b-e07fc1f90ae7'; // node channel
const Y = '0b6e5a1c-3d2f-4e8a-9c7b-1a2b3c4d5e6f'; // another node channel
const D = 'd1d1d1d1-0000-4000-8000-000000000001'; // DM channel
const ME = '11111111-1111-4111-8111-111111111111';
const ALICE = '22222222-2222-4222-8222-222222222222';

const enc = new TextEncoder();
const dec = new TextDecoder();

let uuidCounter = 0;
function nextUuid(): string {
  uuidCounter += 1;
  return `aaaaaaaa-0000-4000-8000-${uuidCounter.toString(16).padStart(12, '0')}`;
}

function last<T>(xs: readonly T[]): T {
  return xs[xs.length - 1];
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

function b64url(bytes: Uint8Array): string {
  return encodeBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bytesOf(n: number, seed: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + seed) & 0xff;
  return b;
}

/** A Blob that records every read (slice, arrayBuffer, stream, text). */
class SpyBlob extends Blob {
  reads = 0;
  failOnRead = false;
  override slice(...args: Parameters<Blob['slice']>): Blob {
    this.reads++;
    if (this.failOnRead) throw new Error('read failed');
    return super.slice(...args);
  }
  override arrayBuffer(): Promise<ArrayBuffer> {
    this.reads++;
    return super.arrayBuffer();
  }
  override stream(): ReturnType<Blob['stream']> {
    this.reads++;
    return super.stream();
  }
  override text(): Promise<string> {
    this.reads++;
    return super.text();
  }
}

/** A file-like object of any size whose every read is recorded; never readable. */
function hugeFile(size: number): { file: Blob; reads: () => number } {
  let reads = 0;
  const fake = {
    size,
    type: 'application/octet-stream',
    slice: () => { reads++; throw new Error('must not read'); },
    arrayBuffer: () => { reads++; throw new Error('must not read'); },
    stream: () => { reads++; throw new Error('must not read'); },
    text: () => { reads++; throw new Error('must not read'); },
  };
  return { file: fake as unknown as Blob, reads: () => reads };
}

function staged(bytes: Uint8Array, name: string, type = 'application/pdf'): StagedSource & { spy: SpyBlob; plain: Uint8Array } {
  const spy = new SpyBlob([bytes as Uint8Array<ArrayBuffer>]);
  return { file: spy, name, type, spy, plain: bytes };
}

interface Frame {
  channelId: string;
  sealed: SealedPayload;
  options: ChannelSendOptions;
}

// ---------------------------------------------------------------------------
// Worlds: a real sender with Sender Keys and the Double Ratchet, and a peer
// ---------------------------------------------------------------------------

function freshManager(): E2EEManager {
  const m = new E2EEManager();
  m.initializeWithKeys(generateIdentityKeyPair(), generateSignedPreKey(), generateOneTimePreKeys(4));
  return m;
}

class World {
  readonly myKeys = new SenderKeyStore();
  readonly peerKeys = new SenderKeyStore();
  readonly me = freshManager();
  readonly peer = freshManager();
  bootstrapOk = true;
  bundleOk = true;
  legacyCalls = 0;
  legacyOptIn = false;
  readonly sealer: ConversationSealer;

  constructor(withSenderKey = true) {
    if (withSenderKey) this.distribute();
    this.sealer = createConversationSealer({
      e2ee: () => this.me,
      senderKeys: () => this.myKeys,
      bootstrapSenderKey: (channelId) => {
        if (!this.bootstrapOk) return false;
        this.myKeys.getOrCreateMyKey(channelId);
        this.distribute(channelId);
        return true;
      },
      fetchBundle: async () => (this.bundleOk ? this.peer.getPreKeyBundle() : undefined),
      persistSenderKeys: () => {},
      legacyText: () => (this.legacyOptIn ? async (_ch, text) => {
        this.legacyCalls++;
        return encodeBase64(enc.encode(`legacy:${text}`));
      } : null),
    });
  }

  private distribute(channelId = X): void {
    const sk = this.myKeys.getOrCreateMyKey(channelId);
    this.peerKeys.setPeerKey(channelId, ME, parseDistributionMessage(buildDistributionMessage(channelId, sk)).state);
  }

  private readonly opened = new Map<string, string>();

  /**
   * The peer decrypts a captured frame (Sender Keys or Double Ratchet). A
   * byte-identical resend is the same ciphertext, so it is opened once.
   */
  open(frame: Frame): string {
    const known = this.opened.get(frame.sealed.wire);
    if (known !== undefined) return known;
    let plaintext: string;
    if (frame.sealed.scheme === 'sk') plaintext = decryptChannelMessage(this.peerKeys, frame.channelId, ME, frame.sealed.wire);
    else if (frame.sealed.scheme === 'dr') plaintext = this.peer.decryptEnvelope(ME, dec.decode(decodeWireBase64(frame.sealed.wire)!));
    else throw new Error('legacy frame');
    this.opened.set(frame.sealed.wire, plaintext);
    return plaintext;
  }
}

class Relay {
  readonly uploads: { channelId: string; body: Uint8Array; id: string }[] = [];
  readonly deletes: string[] = [];
  readonly frames: Frame[] = [];
  handOff = true;
  /** Per-id DELETE answers; default 204. */
  readonly deleteStatus = new Map<string, 204 | 404 | 409>();
  history: HistoryPage[] = [{ items: [], hasMore: false }];
  uploadImpl: ((channelId: string, body: Uint8Array) => UploadAttachmentResponse | Error) | null = null;

  async upload(channelId: string, blob: Blob): Promise<UploadAttachmentResponse> {
    const body = new Uint8Array(await blob.arrayBuffer());
    if (this.uploadImpl) {
      const r = this.uploadImpl(channelId, body);
      if (r instanceof Error) throw r;
      this.uploads.push({ channelId, body, id: r.attachment_id });
      return r;
    }
    const id = nextUuid();
    this.uploads.push({ channelId, body, id });
    return {
      attachment_id: id,
      blob_size: body.length,
      blob_sha256: hex(sha256(body)),
      pending_expires_at: Math.floor(Date.now() / 1000) + 3600,
    };
  }
}

interface Setup {
  world: World;
  relay: Relay;
  cache: Map<string, unknown>;
  mgr: PendingSendManager;
  events: PendingEvent[];
  limits: { available: boolean; maxBlobBytes: number | null };
}

function setup(opts: { world?: World; sleep?: (ms: number) => Promise<void> } = {}): Setup {
  const world = opts.world ?? new World();
  const relay = new Relay();
  const cache = new Map<string, unknown>();
  const limits = { available: true, maxBlobBytes: null as number | null };
  const mgr = new PendingSendManager({
    transport: {
      upload: (ch, blob) => relay.upload(ch, blob),
      deleteAttachment: async (id) => {
        relay.deletes.push(id);
        return relay.deleteStatus.get(id) ?? 204;
      },
      sendFrame: (channelId, sealed, options) => {
        relay.frames.push({ channelId, sealed, options });
        return { handedOff: relay.handOff, messageId: nextUuid() };
      },
      history: async (_ch, before) => relay.history[before ? Number(before) : 0] ?? { items: [], hasMore: false },
    },
    sealer: world.sealer,
    cache: { put: r => { cache.set(r.message_id, r); } },
    ownUserId: () => ME,
    origin: () => ORIGIN,
    limits: () => limits,
    sleep: opts.sleep,
  });
  const events: PendingEvent[] = [];
  mgr.subscribe(e => events.push(e));
  return { world, relay, cache, mgr, events, limits };
}

async function send(s: Setup, input: Partial<SendInput> & { files?: StagedSource[] }) {
  const prepared = await s.mgr.prepare({
    conversation: input.conversation ?? { kind: 'channel', channelId: X },
    body: input.body ?? '',
    files: input.files ?? [],
    options: input.options,
  });
  if (!prepared.ok) return { prepared, started: null };
  return { prepared, started: await s.mgr.start(prepared.send) };
}

function lastView(s: Setup, id: string): PendingView | null {
  for (let i = s.events.length - 1; i >= 0; i--) {
    const e = s.events[i];
    if ((e.type === 'updated' || e.type === 'paired') && e.view.id === id) return e.view;
  }
  return null;
}

function descriptorsOf(plaintext: string): DescriptorFields[] {
  const read = parseEnvelope(plaintext);
  if (!read || read.status !== 'valid') throw new Error('not a valid envelope');
  return read.envelope.attachments.map(a => {
    if (!a.usable) throw new Error('unusable descriptor');
    return a.descriptor;
  });
}

/** Every recorded request as bytes: frames as JSON, uploads as bodies plus their channel. */
function wireHaystacks(relay: Relay): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (const f of relay.frames) out.push(enc.encode(JSON.stringify({ c: f.channelId, w: f.sealed.wire, o: f.options })));
  for (const u of relay.uploads) {
    out.push(u.body);
    out.push(enc.encode(`/channels/${u.channelId}/attachments`));
  }
  for (const d of relay.deletes) out.push(enc.encode(`/attachments/${d}`));
  return out;
}

function indexOfBytes(hay: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

/** No request contains the secret raw, or in base64, base64url or hex. */
function expectAbsent(relay: Relay, secret: Uint8Array, label: string): void {
  const forms = [secret, enc.encode(encodeBase64(secret)), enc.encode(b64url(secret)), enc.encode(hex(secret))];
  for (const hay of wireHaystacks(relay)) {
    for (const f of forms) expect(indexOfBytes(hay, f), label).toBe(-1);
  }
}

beforeEach(() => {
  vi.useRealTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------

describe('T-6 (REQ-6): three files, decrypted by a test peer', () => {
  for (const kind of ['sk', 'dr'] as const) {
    it(`builds one v1 envelope bound to the channel (${kind === 'sk' ? 'Sender Keys' : 'Double Ratchet'})`, async () => {
      const s = setup();
      const files = [staged(bytesOf(10, 1), 'a.txt', 'text/plain'), staged(bytesOf(70_000, 2), 'b.bin', ''), staged(bytesOf(5, 3), 'c.png', 'image/png')];
      const conversation = kind === 'sk' ? { kind: 'channel' as const, channelId: X } : { kind: 'dm' as const, channelId: D, peerId: ALICE };
      const { started } = await send(s, { conversation, body: 'three files', files });
      expect(started).toMatchObject({ kind: 'started' });
      expect(s.relay.frames).toHaveLength(1);
      const frame = s.relay.frames[0];
      expect(frame.sealed.scheme).toBe(kind);
      const plaintext = s.world.open(frame);
      expect(plaintext.startsWith(ENVELOPE_PREFIX)).toBe(true);
      const read = parseEnvelope(plaintext);
      expect(read?.status).toBe('valid');
      if (read?.status !== 'valid') return;
      expect(read.envelope.channelId).toBe(conversation.channelId);
      expect(read.envelope.body).toBe('three files');
      const ds = descriptorsOf(plaintext);
      expect(ds.map(d => d.blobId)).toEqual(s.relay.uploads.map(u => u.id));
      expect(frame.options.attachmentIds).toEqual(s.relay.uploads.map(u => u.id));
      expect(ds.map(d => d.mime)).toEqual(['text/plain', 'application/octet-stream', 'image/png']);
      // Each uploaded blob opens to the file under its descriptor.
      for (let i = 0; i < 3; i++) {
        expect(s.relay.uploads[i].body.length).toBe(blobLength(padme(files[i].plain.length)));
        expect(await openAttachment(s.relay.uploads[i].body, ds[i])).toEqual(files[i].plain);
      }
    });
  }

  it('refuses eleven files before any encryption or read', async () => {
    const s = setup();
    const files = Array.from({ length: 11 }, (_, i) => staged(bytesOf(4, i), `f${i}.txt`));
    const { prepared } = await send(s, { files });
    expect(prepared.ok).toBe(false);
    if (!prepared.ok) expect(prepared.error.code).toBe('too_many_files');
    expect(files.every(f => f.spy.reads === 0)).toBe(true);
    expect(s.relay.uploads).toHaveLength(0);
    expect(s.relay.frames).toHaveLength(0);
  });
});

describe('T-7 (REQ-7): only the Double Ratchet or Sender Keys, whatever the legacy settings', () => {
  it('(a) a node channel whose sender-key bootstrap fails sends no frame and no upload', async () => {
    const world = new World(false);
    world.bootstrapOk = false;
    world.legacyOptIn = true; // the legacy opt-in never applies to attachments
    const s = setup({ world });
    const file = staged(bytesOf(100, 7), 'canary-name.pdf');
    const { prepared } = await send(s, { body: 'x', files: [file] });
    expect(prepared.ok).toBe(false);
    if (!prepared.ok) expect(prepared.error.code).toBe('e2ee_unavailable');
    expect(file.spy.reads).toBe(0);
    expect(s.relay.uploads).toHaveLength(0);
    expect(s.relay.frames).toHaveLength(0);
    expect(world.legacyCalls).toBe(0);
  });

  it('(b) with a sender key the payload is a Sender Keys envelope; (c) a DM payload is a Double Ratchet envelope', async () => {
    const world = new World();
    world.legacyOptIn = true;
    const s = setup({ world });
    const file = staged(bytesOf(300, 9), 'canary-name.pdf');
    await send(s, { body: 'body canary', files: [file] });
    await send(s, { conversation: { kind: 'dm', channelId: D, peerId: ALICE }, body: 'dm canary', files: [staged(bytesOf(30, 4), 'canary-name.pdf')] });
    expect(s.relay.frames.map(f => f.sealed.scheme)).toEqual(['sk', 'dr']);
    expect(isSenderKeyEnvelope(s.relay.frames[0].sealed.wire)).toBe(true);
    const drJson = JSON.parse(dec.decode(decodeWireBase64(s.relay.frames[1].sealed.wire)!));
    expect(['x3dh', 'dr']).toContain(drJson.t);
    expect(world.legacyCalls).toBe(0);

    // Neither the key nor the name appears in any request, in any encoding.
    for (const frame of s.relay.frames) {
      for (const d of descriptorsOf(world.open(frame))) {
        expectAbsent(s.relay, d.key, 'key');
        expectAbsent(s.relay, d.noncePrefix, 'nonce prefix');
      }
    }
    expectAbsent(s.relay, enc.encode('canary-name.pdf'), 'name');
    expectAbsent(s.relay, enc.encode('body canary'), 'body');
  });

  it('(d) no sealing path takes an envelope with attachments under the legacy key', async () => {
    const world = new World(false);
    world.bootstrapOk = false;
    world.legacyOptIn = true;
    const envelope = '{"type":"accord.content","v":1,"channel_id":"' + X + '","attachments":[]}';
    await expect(world.sealer.seal({ kind: 'channel', channelId: X }, envelope, 'attachments')).rejects.toThrow();
    await expect(world.sealer.seal({ kind: 'channel', channelId: X }, envelope, 'text')).rejects.toThrow();
    expect(world.legacyCalls).toBe(0);
    // Plain text may use the explicit opt-in; it is never E2EE but never plaintext either.
    const sealed = await world.sealer.seal({ kind: 'channel', channelId: X }, 'hello', 'text');
    expect(sealed.scheme).toBe('legacy');
  });
});

describe('T-12 (REQ-12): no file is read before encryption is known to be possible', () => {
  it('a DM with no session and a failing bundle fetch reads nothing and uploads nothing', async () => {
    const world = new World();
    world.bundleOk = false;
    const s = setup({ world });
    const files = [staged(bytesOf(50, 1), 'a.pdf'), staged(bytesOf(60, 2), 'b.pdf')];
    const { prepared } = await send(s, { conversation: { kind: 'dm', channelId: D, peerId: ALICE }, body: 'hi', files });
    expect(prepared.ok).toBe(false);
    if (!prepared.ok) expect(prepared.error.text).toMatch(/end-to-end encryption is unavailable/);
    expect(files.every(f => f.spy.reads === 0)).toBe(true);
    expect(s.relay.uploads).toHaveLength(0);
    expect(s.relay.frames).toHaveLength(0);
  });
});

describe('T-13 (REQ-13) and RG-C192: a read failure aborts the whole message', () => {
  it('sealing throws on file 2 of 3: no further POST, file 1 deleted, no frame, nothing in plaintext', async () => {
    const s = setup();
    const f1 = staged(bytesOf(40, 1), 'secret-one.pdf');
    const f2 = staged(bytesOf(40, 2), 'secret-two.pdf');
    const f3 = staged(bytesOf(40, 3), 'secret-three.pdf');
    f2.spy.failOnRead = true;
    const { started } = await send(s, { body: 'b', files: [f1, f2, f3] });
    expect(started).toMatchObject({ kind: 'aborted', error: { code: 'encrypt_failed' } });
    expect(s.relay.uploads).toHaveLength(1);
    expect(s.relay.deletes).toEqual([s.relay.uploads[0].id]);
    expect(s.relay.frames).toHaveLength(0);
    expect(f3.spy.reads).toBe(0);
    // The temporary message is gone; the caller keeps the staged files.
    expect(s.events.some(e => e.type === 'removed')).toBe(true);
    expect(s.mgr.listChannel(X)).toHaveLength(0);
    for (const f of [f1, f2, f3]) {
      expectAbsent(s.relay, f.plain, 'plaintext');
      expectAbsent(s.relay, enc.encode(f.name), 'name');
    }
  });

  it('a read failure on the first file uploads nothing at all', async () => {
    const s = setup();
    const f1 = staged(bytesOf(40, 1), 'x.pdf');
    f1.spy.failOnRead = true;
    const { started } = await send(s, { body: 'b', files: [f1] });
    expect(started?.kind).toBe('aborted');
    expect(s.relay.uploads).toHaveLength(0);
    expect(s.relay.frames).toHaveLength(0);
  });
});

describe('T-14 (REQ-14): the relay\'s size and hash are checked', () => {
  it('a wrong blob_sha256 deletes the pending upload, retries once, then fails', async () => {
    const s = setup();
    s.relay.uploadImpl = (_ch, body) => ({
      attachment_id: nextUuid(),
      blob_size: body.length,
      blob_sha256: '00'.repeat(32),
      pending_expires_at: Math.floor(Date.now() / 1000) + 3600,
    });
    const { started } = await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    expect(started).toMatchObject({ kind: 'aborted', error: { code: 'upload_corrupted' } });
    expect(s.relay.uploads).toHaveLength(2);
    expect(s.relay.deletes).toEqual(s.relay.uploads.map(u => u.id));
    expect(s.relay.frames).toHaveLength(0);
  });

  it('a wrong blob_size is a mismatch too', async () => {
    const s = setup();
    let first = true;
    s.relay.uploadImpl = (_ch, body) => {
      const r = {
        attachment_id: nextUuid(),
        blob_size: first ? body.length + 1 : body.length,
        blob_sha256: hex(sha256(body)),
        pending_expires_at: Math.floor(Date.now() / 1000) + 3600,
      };
      first = false;
      return r;
    };
    const { started } = await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    expect(started?.kind).toBe('started');
    expect(s.relay.deletes).toEqual([s.relay.uploads[0].id]);
    expect(s.relay.frames[0].options.attachmentIds).toEqual([s.relay.uploads[1].id]);
  });
});

describe('T-15 (REQ-15): pending states, claim failures and abandoning', () => {
  it('no echo: "sending", then "unconfirmed" after 30 s', async () => {
    vi.useFakeTimers();
    const s = setup();
    const { started } = await send(s, { body: 'hello' });
    const id = (started as { id: string }).id;
    expect(lastView(s, id)?.status).toBe('sending');
    vi.advanceTimersByTime(PAIRING_TIMEOUT_MS - 1);
    expect(lastView(s, id)?.status).toBe('sending');
    vi.advanceTimersByTime(1);
    expect(lastView(s, id)?.status).toBe('unconfirmed');
  });

  it('an echo with the matching payload and attachment_ids pairs, in a channel that is not open', async () => {
    const s = setup();
    const { started } = await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    const id = (started as { id: string }).id;
    const frame = s.relay.frames[0];
    const relayId = nextUuid();
    const paired = s.mgr.pairLiveEcho({ channelId: X, messageId: relayId, senderId: ME, payload: frame.sealed.wire }, { attachment_ids: frame.options.attachmentIds });
    expect(paired?.id).toBe(id);
    expect(last(s.events)).toMatchObject({ type: 'paired', messageId: relayId });
    const record = readCacheValue(s.cache.get(relayId), relayId);
    expect(record.kind).toBe('record');
    if (record.kind === 'record') {
      expect(record.record).toMatchObject({ source: 'own', channel_id: X, sender_id: ME, message_id: relayId, origin: ORIGIN });
      expect(record.record.wire_sha256).toBe(encodeBase64(sha256(decodeWireBase64(frame.sealed.wire)!)));
      expect(record.record.plaintext).toBe(s.world.open(frame));
    }
  });

  const RETRYABLE = ['unavailable', 'slow_mode', 'internal'];
  for (const reason of ['unavailable', 'slow_mode', 'internal', 'forbidden', 'blocked', 'allowlist', 'invalid']) {
    it(`attachment_claim_failed "${reason}": failed, ${RETRYABLE.includes(reason) ? 'with' : 'without'} Retry`, async () => {
      vi.useFakeTimers();
      const s = setup();
      const { started } = await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')], options: { expiresAt: Math.floor(Date.now() / 1000) + 3600 } });
      const id = (started as { id: string }).id;
      const ids = s.relay.frames[0].options.attachmentIds!;
      expect(s.mgr.onClaimFailed({ reason, attachment_ids: [...ids], retry_after: 3 })).toBe(true);
      const view = lastView(s, id)!;
      expect(view.status).toBe('failed');
      expect(view.failure?.retryable).toBe(RETRYABLE.includes(reason));
      if (reason === 'slow_mode') {
        expect(view.failure?.text).toBe('Slow mode: sending in 3 s');
        await vi.advanceTimersByTimeAsync(3000);
        // Resent by itself, byte for byte (REQ-47 (i)), with the same ids.
        expect(s.relay.frames).toHaveLength(2);
        expect(s.relay.frames[1].sealed).toBe(s.relay.frames[0].sealed);
        expect(s.relay.frames[1].options).toEqual(s.relay.frames[0].options);
        expect(lastView(s, id)?.status).toBe('sending');
      } else {
        await vi.advanceTimersByTimeAsync(10_000);
        expect(s.relay.frames).toHaveLength(1);
      }
      if (!RETRYABLE.includes(reason)) {
        await s.mgr.retry(id);
        expect(s.relay.frames).toHaveLength(1);
        expect(s.relay.uploads).toHaveLength(1);
      }
    });
  }

  it('no echo: resolution runs 10 minutes after the send', async () => {
    vi.useFakeTimers();
    const s = setup();
    const { started } = await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    const id = (started as { id: string }).id;
    const ids = [...s.relay.frames[0].options.attachmentIds!];
    await vi.advanceTimersByTimeAsync(RESOLUTION_DEADLINE_MS - 1);
    expect(lastView(s, id)?.status).toBe('unconfirmed');
    expect(s.relay.deletes).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => expect(lastView(s, id)?.status).toBe('failed'));
    expect(s.relay.deletes).toEqual(ids);
  });

  it('a slow_mode auto-resend with no echo is resolved 10 minutes after the resend', async () => {
    vi.useFakeTimers();
    const s = setup();
    const { started } = await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    const id = (started as { id: string }).id;
    const ids = [...s.relay.frames[0].options.attachmentIds!];
    s.mgr.onClaimFailed({ reason: 'slow_mode', attachment_ids: [...ids], retry_after: 3 });
    await vi.advanceTimersByTimeAsync(3000);
    expect(s.relay.frames).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(PAIRING_TIMEOUT_MS);
    expect(lastView(s, id)?.status).toBe('unconfirmed');
    await vi.advanceTimersByTimeAsync(RESOLUTION_DEADLINE_MS - PAIRING_TIMEOUT_MS - 1);
    expect(s.relay.deletes).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => expect(lastView(s, id)?.status).toBe('failed'));
    expect(s.relay.deletes).toEqual(ids);
    expect(lastView(s, id)?.failure?.retryable).toBe(true);
  });

  it('a claim failure for another message\'s ids changes nothing', async () => {
    const s = setup();
    const { started } = await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    const id = (started as { id: string }).id;
    expect(s.mgr.onClaimFailed({ reason: 'forbidden', attachment_ids: [nextUuid()] })).toBe(false);
    expect(s.mgr.onClaimFailed({ reason: 'forbidden' })).toBe(false);
    expect(lastView(s, id)?.status).toBe('sending');
  });

  it('abandoning a failed send deletes its pending uploads', async () => {
    const s = setup();
    const { started } = await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf'), staged(bytesOf(30, 2), 'b.pdf')] });
    const id = (started as { id: string }).id;
    const ids = [...s.relay.frames[0].options.attachmentIds!];
    s.mgr.onClaimFailed({ reason: 'forbidden', attachment_ids: ids });
    expect(await s.mgr.abandon(id)).toBe(true);
    expect(s.relay.deletes).toEqual(ids);
    expect(last(s.events)).toMatchObject({ type: 'removed', id });
    expect(s.mgr.get(id)).toBeNull();
  });
});

describe('T-16 (REQ-16): limits are enforced before any read', () => {
  it('eleven files are refused without being read', async () => {
    const s = setup();
    const files = Array.from({ length: 11 }, () => hugeFile(10));
    const { prepared } = await send(s, { files: files.map((f, i) => ({ file: f.file, name: `${i}` })) });
    expect(prepared.ok).toBe(false);
    expect(files.every(f => f.reads() === 0)).toBe(true);
  });

  it('a relay advertising 10 GiB cannot raise the client limit of 100 MiB', async () => {
    const s = setup();
    s.limits.maxBlobBytes = 10 * 1024 ** 3;
    const f = hugeFile(150 * 1024 ** 2);
    const { prepared } = await send(s, { files: [{ file: f.file, name: 'big.bin' }] });
    expect(prepared.ok).toBe(false);
    if (!prepared.ok) {
      expect(prepared.error.code).toBe('file_too_large');
      expect(prepared.error.fileIndexes).toEqual([0]);
      expect(prepared.error.text).toContain('100 MiB');
    }
    expect(f.reads()).toBe(0);
  });

  it('a relay advertising 5 MiB refuses a 6 MiB file', async () => {
    const s = setup();
    s.limits.maxBlobBytes = 5 * 1024 ** 2;
    const f = hugeFile(6 * 1024 ** 2);
    const { prepared } = await send(s, { files: [{ file: f.file, name: 'six.bin' }] });
    expect(prepared.ok).toBe(false);
    expect(f.reads()).toBe(0);
  });

  it('the largest file whose padded blob fits CLIENT_MAX_BLOB_BYTES passes the preflight', async () => {
    const s = setup();
    // padme(104857600) = 104857600, whose blob is 1600 tags too large.
    let size = CLIENT_MAX_BLOB_BYTES - 1600 * 16;
    while (blobLength(padme(size)) > CLIENT_MAX_BLOB_BYTES) size -= 1;
    const f = hugeFile(size);
    const { prepared } = await s.mgr.prepare({ conversation: { kind: 'channel', channelId: X }, body: '', files: [{ file: f.file, name: 'max.bin' }] }).then(p => ({ prepared: p }));
    expect(prepared.ok).toBe(true);
    expect(f.reads()).toBe(0);
  });

  it('a relay without attachments/2 disables attachment sending (REQ-17)', async () => {
    const s = setup();
    s.limits.available = false;
    const f = hugeFile(10);
    const { prepared } = await send(s, { files: [{ file: f.file, name: 'a' }] });
    expect(prepared.ok).toBe(false);
    if (!prepared.ok) expect(prepared.error.text).toBe('This relay must be updated to send end-to-end encrypted attachments');
    expect(f.reads()).toBe(0);
    // Text still goes out.
    const text = await send(s, { body: 'just text' });
    expect(text.started?.kind).toBe('started');
  });
});

describe('T-52 (REQ-52): exact envelope size before any read', () => {
  it('a body of 8,192 double quotes with one attachment is refused (its escaped form alone exceeds 16 KiB)', async () => {
    const s = setup();
    const f = hugeFile(10);
    const { prepared } = await send(s, { body: '"'.repeat(8192), files: [{ file: f.file, name: 'a.txt' }] });
    expect(prepared.ok).toBe(false);
    if (!prepared.ok) expect(prepared.error.text).toBe('Message too long: shorten the text or attach fewer files');
    expect(f.reads()).toBe(0);
  });

  it('a body of 8,193 bytes is refused', async () => {
    const s = setup();
    const f = hugeFile(10);
    const { prepared } = await send(s, { body: 'a'.repeat(8193), files: [{ file: f.file, name: 'a.txt' }] });
    expect(prepared.ok).toBe(false);
    expect(f.reads()).toBe(0);
  });

  it('ten files with 255-byte names: the computed size equals the size of the envelope sent', async () => {
    const s = setup();
    const name = 'n'.repeat(251) + '.pdf';
    const files = Array.from({ length: 10 }, (_, i) => staged(bytesOf(100 + i, i), name));
    const body = 'x'.repeat(6 * 1024);
    const estimate = estimateEnvelopeBytes(X, body, files.map(f => ({ size: f.plain.length, name, mime: 'application/pdf' })));
    const { prepared, started } = await send(s, { body, files });
    expect(prepared.ok).toBe(true);
    if (prepared.ok) expect(prepared.send.estimatedEnvelopeBytes).toBe(estimate);
    expect(started?.kind).toBe('started');
    const sent = s.world.open(s.relay.frames[0]);
    expect(utf8ByteLength(sent)).toBe(estimate);
    expect(estimate).toBeLessThanOrEqual(MAX_ENVELOPE_BYTES);
  });

  it('the send fails exactly when the computed size exceeds 16 KiB', async () => {
    const s = setup();
    const name = 'n'.repeat(251) + '.pdf';
    const sizeFor = (quotes: number) => estimateEnvelopeBytes(X, '"'.repeat(quotes), Array.from({ length: 10 }, () => ({ size: 100, name, mime: 'application/pdf' })));
    let q = 0;
    while (sizeFor(q + 1) <= MAX_ENVELOPE_BYTES) q++;
    const files = () => Array.from({ length: 10 }, (_, i) => staged(bytesOf(100, i), name));
    const ok = await send(s, { body: '"'.repeat(q), files: files() });
    expect(ok.prepared.ok).toBe(true);
    const tooBig = files();
    const refused = await send(s, { body: '"'.repeat(q + 1), files: tooBig });
    expect(refused.prepared.ok).toBe(false);
    expect(tooBig.every(f => f.spy.reads === 0)).toBe(true);
  });

  it('an escape text of 9,000 bytes is refused', async () => {
    const s = setup();
    const { prepared } = await send(s, { body: ENVELOPE_PREFIX + 'x'.repeat(9000 - ENVELOPE_PREFIX.length) });
    expect(prepared.ok).toBe(false);
    expect(s.relay.frames).toHaveLength(0);
  });
});

describe('T-49 (REQ-49) and RG-C090: pairing by exact ciphertext hash', () => {
  it('two texts whose echoes arrive in reverse order each pair with their own record', async () => {
    const s = setup();
    const a = await send(s, { body: 'first' });
    const b = await send(s, { body: 'second' });
    const [fa, fb] = s.relay.frames;
    const idB = nextUuid();
    const idA = nextUuid();
    expect(s.mgr.pairLiveEcho({ channelId: X, messageId: idB, senderId: ME, payload: fb.sealed.wire })?.id).toBe((b.started as { id: string }).id);
    expect(s.mgr.pairLiveEcho({ channelId: X, messageId: idA, senderId: ME, payload: fa.sealed.wire })?.id).toBe((a.started as { id: string }).id);
    expect((s.cache.get(idA) as { plaintext: string }).plaintext).toBe('first');
    expect((s.cache.get(idB) as { plaintext: string }).plaintext).toBe('second');
  });

  it('an echo with the right payload but different attachment_ids does not pair', async () => {
    const s = setup();
    await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    const f = s.relay.frames[0];
    expect(s.mgr.pairLiveEcho({ channelId: X, messageId: nextUuid(), senderId: ME, payload: f.sealed.wire }, { attachment_ids: [nextUuid()] })).toBeNull();
    expect(s.mgr.pairLiveEcho({ channelId: X, messageId: nextUuid(), senderId: ME, payload: f.sealed.wire }, {})).toBeNull();
  });

  it('never pairs another sender, another channel, or by position', async () => {
    const s = setup();
    await send(s, { body: 'mine' });
    const f = s.relay.frames[0];
    expect(s.mgr.pairLiveEcho({ channelId: X, messageId: nextUuid(), senderId: ALICE, payload: f.sealed.wire })).toBeNull();
    expect(s.mgr.pairLiveEcho({ channelId: Y, messageId: nextUuid(), senderId: ME, payload: f.sealed.wire })).toBeNull();
    // A different own payload (an echo of something else) does not take the oldest record.
    expect(s.mgr.pairLiveEcho({ channelId: X, messageId: nextUuid(), senderId: ME, payload: encodeBase64(enc.encode('other')) })).toBeNull();
    expect(s.mgr.listChannel(X)).toHaveLength(1);
  });

  it('a replay of a paired payload under a second id does not pair and shows "Sent from another session"', async () => {
    const s = setup();
    await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    const f = s.relay.frames[0];
    const first = nextUuid();
    expect(s.mgr.pairLiveEcho({ channelId: X, messageId: first, senderId: ME, payload: f.sealed.wire }, { attachment_ids: f.options.attachmentIds })).not.toBeNull();
    const second = nextUuid();
    expect(s.mgr.pairLiveEcho({ channelId: X, messageId: second, senderId: ME, payload: f.sealed.wire }, { attachment_ids: f.options.attachmentIds })).toBeNull();
    const store = new AttachmentStore();
    const cacheAccess = { get: (id: string) => s.cache.get(id), put: () => {} };
    const decoded = await decodeMessage(
      { origin: ORIGIN, renderedChannelId: X, ownUserId: ME },
      { channelId: X, messageId: second, senderId: ME, payload: f.sealed.wire },
      { decryptors: {}, cache: cacheAccess, store },
    );
    expect(decoded.placeholder).toBe('other_session');
    expect(PLACEHOLDER_TEXT.other_session).toBe('Sent from another session; content unavailable');
    expect(store.size).toBe(0);
    // The genuine copy decodes through its record, with its attachment.
    const genuine = await decodeMessage(
      { origin: ORIGIN, renderedChannelId: X, ownUserId: ME },
      { channelId: X, messageId: first, senderId: ME, payload: f.sealed.wire },
      { decryptors: {}, cache: cacheAccess, store },
    );
    expect(genuine.verified).toBe(true);
    expect(genuine.attachmentCount).toBe(1);
  });

  it('a failed record never pairs, even with its exact payload', async () => {
    const s = setup();
    await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    const f = s.relay.frames[0];
    s.mgr.onClaimFailed({ reason: 'forbidden', attachment_ids: [...f.options.attachmentIds!] });
    expect(s.mgr.pairLiveEcho({ channelId: X, messageId: nextUuid(), senderId: ME, payload: f.sealed.wire }, { attachment_ids: f.options.attachmentIds })).toBeNull();
    expect(s.mgr.pairHistoryItem({ channelId: X, messageId: nextUuid(), senderId: ME, payload: f.sealed.wire, createdAt: 1 })).toBeNull();
  });

  it('an unconfirmed record pairs with a matching own history item, and with none other', async () => {
    vi.useFakeTimers();
    const s = setup();
    const { started } = await send(s, { body: 'later' });
    const id = (started as { id: string }).id;
    vi.advanceTimersByTime(PAIRING_TIMEOUT_MS);
    expect(lastView(s, id)?.status).toBe('unconfirmed');
    const f = s.relay.frames[0];
    expect(s.mgr.pairHistoryItem({ channelId: X, messageId: nextUuid(), senderId: ALICE, payload: f.sealed.wire, createdAt: 1 })).toBeNull();
    expect(s.mgr.pairHistoryItem({ channelId: Y, messageId: nextUuid(), senderId: ME, payload: f.sealed.wire, createdAt: 1 })).toBeNull();
    const rid = nextUuid();
    expect(s.mgr.pairHistoryItem({ channelId: X, messageId: rid, senderId: ME, payload: f.sealed.wire, createdAt: 1 })?.id).toBe(id);
    expect(s.cache.has(rid)).toBe(true);
  });

  it('T-8 (h): a text echo after a claim-failed attachment message pairs with its own record only', async () => {
    const s = setup();
    const a = await send(s, { body: 'with file', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    s.mgr.onClaimFailed({ reason: 'slow_mode', attachment_ids: [...s.relay.frames[0].options.attachmentIds!], retry_after: 60 });
    const b = await send(s, { body: 'plain text B' });
    const bFrame = s.relay.frames[1];
    const relayB = nextUuid();
    expect(s.mgr.pairLiveEcho({ channelId: X, messageId: relayB, senderId: ME, payload: bFrame.sealed.wire })?.id).toBe((b.started as { id: string }).id);
    expect(s.mgr.get((a.started as { id: string }).id)?.status).toBe('failed');
    const rec = readCacheValue(s.cache.get(relayB), relayB);
    expect(rec.kind === 'record' && rec.record.plaintext).toBe('plain text B');
    expect(s.cache.size).toBe(1);
  });

  it('RG-C090: a rejected text stays unconfirmed; a later message still pairs with itself', async () => {
    vi.useFakeTimers();
    const s = setup();
    const a = await send(s, { body: 'rejected text A' }); // the relay answers with a plain error frame
    const b = await send(s, { body: 'B' });
    const relayB = nextUuid();
    s.mgr.pairLiveEcho({ channelId: X, messageId: relayB, senderId: ME, payload: s.relay.frames[1].sealed.wire });
    vi.advanceTimersByTime(PAIRING_TIMEOUT_MS);
    expect(lastView(s, (a.started as { id: string }).id)?.status).toBe('unconfirmed');
    expect(lastView(s, (b.started as { id: string }).id)?.status).toBe('sent');
    expect([...s.cache.keys()]).toEqual([relayB]);
    // C in channel Y pairs although Y is not the open conversation.
    await send(s, { conversation: { kind: 'channel', channelId: Y }, body: 'C' });
    s.world.myKeys.getOrCreateMyKey(Y);
    const cFrame = last(s.relay.frames);
    expect(s.mgr.pairLiveEcho({ channelId: Y, messageId: nextUuid(), senderId: ME, payload: cFrame.sealed.wire })).not.toBeNull();
  });
});

describe('T-47 (REQ-47) and RG-C193: resends never carry plaintext', () => {
  const CANARY = 'body-canary-7f3c';
  const NAME = 'canary-name.pdf';

  function scenario() {
    const s = setup();
    const files = [staged(bytesOf(2000, 1), NAME), staged(bytesOf(3000, 2), NAME)];
    return { s, files };
  }

  /** Every frame is sealed, every body a blob, and no secret leaks. */
  function expectClean(s: Setup, files: { plain: Uint8Array }[]): void {
    for (const f of s.relay.frames) expect(['sk', 'dr']).toContain(f.sealed.scheme);
    for (const u of s.relay.uploads) expect([...files.map(f => blobLength(padme(f.plain.length)))]).toContain(u.body.length);
    expectAbsent(s.relay, enc.encode(CANARY), 'canary');
    expectAbsent(s.relay, enc.encode(NAME), 'name');
    for (const f of files) expectAbsent(s.relay, f.plain, 'file');
    for (const frame of s.relay.frames) {
      for (const d of descriptorsOf(s.world.open(frame))) {
        expectAbsent(s.relay, d.key, 'key');
        expectAbsent(s.relay, d.noncePrefix, 'nonce prefix');
      }
    }
  }

  const gate = { users: [ALICE], ttlSecs: 60 };

  it('(a) unavailable for one of two ids, then Retry: one new upload, rebuilt envelope, new Sender Keys iteration', async () => {
    const { s, files } = scenario();
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;
    const { started } = await send(s, { body: CANARY, files, options: { expiresAt, gate, replyTo: 'r-1' } });
    const id = (started as { id: string }).id;
    const [id1, id2] = s.relay.frames[0].options.attachmentIds!;
    s.world.open(s.relay.frames[0]);
    s.mgr.onClaimFailed({ reason: 'unavailable', attachment_ids: [id1, id2], unavailable_ids: [id1] });
    await s.mgr.retry(id);
    expect(s.relay.uploads).toHaveLength(3);
    const newId = s.relay.uploads[2].id;
    const frame = s.relay.frames[1];
    expect(frame.options.attachmentIds).toEqual([newId, id2]);
    expect(frame.options).toMatchObject({ expiresAt, gate, replyTo: 'r-1' });
    const ds = descriptorsOf(s.world.open(frame));
    expect(ds.map(d => d.blobId)).toEqual([newId, id2]);
    const iter = (w: string) => JSON.parse(dec.decode(decodeWireBase64(w)!)).iteration ?? JSON.parse(dec.decode(decodeWireBase64(w)!)).i;
    expect(iter(frame.sealed.wire)).not.toEqual(iter(s.relay.frames[0].sealed.wire));
    expect(frame.sealed.wire).not.toBe(s.relay.frames[0].sealed.wire);
    expectClean(s, files);
  });

  it('(b) the socket is closed when the frame is sent: the resend on reconnect is byte-identical', async () => {
    const { s, files } = scenario();
    s.relay.handOff = false;
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;
    const { started } = await send(s, { body: CANARY, files, options: { expiresAt, gate } });
    const id = (started as { id: string }).id;
    expect(lastView(s, id)?.statusText).toBe('Waiting for connection');
    s.relay.handOff = true;
    s.mgr.onReconnect();
    expect(s.relay.frames).toHaveLength(2);
    expect(s.relay.frames[1].sealed.wire).toBe(s.relay.frames[0].sealed.wire);
    expect(s.relay.frames[1].options).toEqual(s.relay.frames[0].options);
    expect(s.relay.uploads).toHaveLength(2);
    expectClean(s, files);
  });

  it('(c) no echo within 30 s, then Retry with every DELETE answering 204: a full rebuild', async () => {
    vi.useFakeTimers();
    const { s, files } = scenario();
    const { started } = await send(s, { body: CANARY, files, options: { gate } });
    const id = (started as { id: string }).id;
    vi.advanceTimersByTime(PAIRING_TIMEOUT_MS);
    expect(lastView(s, id)?.status).toBe('unconfirmed');
    const oldIds = [...s.relay.frames[0].options.attachmentIds!];
    await s.mgr.retry(id);
    expect(s.relay.deletes).toEqual(oldIds);
    expect(s.relay.uploads).toHaveLength(4);
    const frame = s.relay.frames[1];
    expect(frame.options.attachmentIds).toEqual([s.relay.uploads[2].id, s.relay.uploads[3].id]);
    expect(frame.options.gate).toEqual(gate);
    expectClean(s, files);
  });

  it('(d) as (c), but one DELETE answers 409: nothing is resent and the message shows sent', async () => {
    vi.useFakeTimers();
    const { s, files } = scenario();
    const { started } = await send(s, { body: CANARY, files });
    const id = (started as { id: string }).id;
    vi.advanceTimersByTime(PAIRING_TIMEOUT_MS);
    s.relay.deleteStatus.set(s.relay.frames[0].options.attachmentIds![1], 409);
    await s.mgr.retry(id);
    expect(s.relay.frames).toHaveLength(1);
    expect(s.relay.uploads).toHaveLength(2);
    expect(lastView(s, id)?.status).toBe('sent');
    // It stays open and pairs with a later history load.
    const rid = nextUuid();
    expect(s.mgr.pairHistoryItem({ channelId: X, messageId: rid, senderId: ME, payload: s.relay.frames[0].sealed.wire, createdAt: 1 })?.id).toBe(id);
  });

  it('(e) a text-only message forced to failed, then Retry: a fresh Sender Keys envelope', async () => {
    const s = setup();
    const { started } = await send(s, { body: CANARY, options: { gate } });
    const id = (started as { id: string }).id;
    s.mgr.failForTests(id, 'internal');
    await s.mgr.retry(id);
    expect(s.relay.frames).toHaveLength(2);
    expect(s.relay.frames[1].sealed.scheme).toBe('sk');
    expect(s.relay.frames[1].sealed.wire).not.toBe(s.relay.frames[0].sealed.wire);
    expect(s.world.open(s.relay.frames[1])).toBe(CANARY);
    expect(s.relay.frames[1].options.gate).toEqual(gate);
    expectAbsent(s.relay, enc.encode(CANARY), 'canary');
  });

  it('(f) as (a), but the original expiry has passed: nothing is resent', async () => {
    vi.useFakeTimers();
    const { s, files } = scenario();
    const expiresAt = Math.floor(Date.now() / 1000) + 5;
    const { started } = await send(s, { body: CANARY, files, options: { expiresAt } });
    const id = (started as { id: string }).id;
    const ids = [...s.relay.frames[0].options.attachmentIds!];
    s.mgr.onClaimFailed({ reason: 'unavailable', attachment_ids: ids, unavailable_ids: [ids[0]] });
    vi.advanceTimersByTime(6_000);
    await s.mgr.retry(id);
    expect(s.relay.frames).toHaveLength(1);
    expect(s.relay.uploads).toHaveLength(2);
    expect(lastView(s, id)?.failure).toEqual({ text: 'Expired before it could be sent', retryable: false });
  });

  it('a blob within 60 s of its pending expiry is sealed again before a byte-for-byte resend', async () => {
    vi.useFakeTimers();
    const { s, files } = scenario();
    s.relay.handOff = false;
    await send(s, { body: CANARY, files });
    vi.advanceTimersByTime((3600 - 30) * 1000);
    s.relay.handOff = true;
    s.mgr.onReconnect();
    // Not resent byte for byte: the record failed and offers Retry (REQ-47 (ii)).
    expect(s.relay.frames).toHaveLength(1);
    const id = s.mgr.listChannel(X)[0].id;
    expect(lastView(s, id)?.failure?.retryable).toBe(true);
    await s.mgr.retry(id);
    expect(s.relay.uploads).toHaveLength(4);
    expect(s.relay.frames).toHaveLength(2);
    expectClean(s, files);
  });
});

describe('upload failures (§8.1)', () => {
  it('network errors are retried three times with backoff, then the message fails with Retry', async () => {
    // The waits are injected, so the test does not race real WebCrypto
    // against fake timers.
    const sleeps: number[] = [];
    const s = setup({ sleep: async (ms) => { sleeps.push(ms); } });
    let attempts = 0;
    s.relay.uploadImpl = () => {
      attempts++;
      const e = new Error('Network error');
      e.name = 'AttachmentNetworkError';
      return e;
    };
    const { started } = await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    expect(attempts).toBe(UPLOAD_NETWORK_RETRIES + 1);
    expect(sleeps).toEqual([1000, 2000, 4000]);
    expect(s.events.some(e => e.type === 'updated' && e.view.statusText === 'Upload failed, retrying')).toBe(true);
    expect(started?.kind).toBe('started');
    const id = (started as { id: string }).id;
    expect(lastView(s, id)?.failure).toEqual({ text: 'Upload failed; Retry', retryable: true });
    s.relay.uploadImpl = null;
    await s.mgr.retry(id);
    expect(s.relay.frames).toHaveLength(1);
  });

  it('429 waits Retry-After once, saying so, then fails as "Upload limit reached"', async () => {
    const sleeps: number[] = [];
    const s = setup({ sleep: async (ms) => { sleeps.push(ms); } });
    let attempts = 0;
    s.relay.uploadImpl = () => {
      attempts++;
      return Object.assign(new Error('x'), { status: 429, reason: 'rate_limited', retryAfter: 2 });
    };
    const { started } = await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
    expect(attempts).toBe(2);
    expect(sleeps).toEqual([2000]);
    expect(s.events.some(e => e.type === 'updated' && e.view.statusText === 'Upload limit reached, retrying in 2 s')).toBe(true);
    expect(started).toMatchObject({ kind: 'aborted', error: { code: 'rate_limited', text: 'Upload limit reached' } });
  });

  for (const [status, reason, code] of [[403, 'forbidden', 'upload_forbidden'], [403, 'blocked', 'upload_blocked'], [413, 'too_large', 'upload_too_large'], [507, 'quota_exceeded', 'storage_full']] as const) {
    it(`${status} ${reason} aborts without retrying`, async () => {
      const s = setup();
      let attempts = 0;
      s.relay.uploadImpl = () => {
        attempts++;
        return Object.assign(new Error('x'), { status, reason });
      };
      const { started } = await send(s, { body: 'b', files: [staged(bytesOf(20, 1), 'a.pdf')] });
      expect(started).toMatchObject({ kind: 'aborted', error: { code } });
      expect(attempts).toBe(1);
      expect(s.relay.frames).toHaveLength(0);
    });
  }
});
