/**
 * SPEC-02 §11.2 step 4: two-client integration tests and the regression
 * replays of §10.3 that need a real relay.
 *
 * Two desktop clients (`client.ts`: the real api, ws, E2EE, send, decode,
 * store and view modules) talk to a real `accord-server` (`relay.ts`) through
 * a proxy (`proxy.ts`) that records all traffic and, where a replay needs the
 * malicious relay (A1), injects or withholds WebSocket frames. Bob owns the
 * node; Alice is a member who joined by Bob's invite (SPEC-01 §10.1). Both
 * clients run with the legacy `keyPair` null (the C024 state).
 *
 * Preconditions of §10.1 (C022, C023): every recipient-side check delivers
 * the message while the recipient is online. RG-C164 (d) replays the offline
 * and re-render variants and is expected to fail until roadmap P0 item 7.
 *
 * "Attachment UI" is decided as the views decide it (`attachments/render.ts`):
 * a rendered message shows only the store entry its own decode produced. Live
 * frames become messages as App.tsx's live handler builds them, history as
 * App.tsx's loader maps it (`TestClient.historyMessages`, which calls the same
 * `decodeHistoryItem`).
 *
 * Covered here: RG-C004-1, RG-C004-2, RG-C008 (a) to (f), RG-C024, RG-C090,
 * RG-C140 (end to end), RG-C164 (b) with the real relay's JSON, (c) and (d),
 * plus T-6, T-7 and T-36 over the real relay. The other §10.3 rows are relay
 * tests (server/tests/spec02_*.rs) or client unit tests
 * (src/attachments/regressions.test.ts and the module tests); see that file's
 * header for the full index.
 */

import { readFileSync, utimesSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import net from 'node:net';
import { once } from 'node:events';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { RelayProcess, RELAY_AVAILABLE } from './relay';
import { RecordingProxy } from './proxy';
import { TestClient, waitFor, type Received } from './client';
import { binaryNeedles, findLeaks, textNeedles } from './scan';
import { oldFileListNames, renderOldFileList } from './bbf2f17FileList';
import type { HistoryMessageFields } from '../attachments/history';
import { blobLength, sealAttachmentWithFixedKeyForVectors, sealedBytes } from '../attachments/format';
import { PLACEHOLDER_TEXT, type VerifiedDescriptor } from '../attachments/decode';
import { isSenderKeyEnvelope } from '../e2ee/senderKeys';
import type { Conversation } from '../attachments/send';

const MIB = 1024 * 1024;

/** Deterministic, non-repeating file content with a marker the scans look for. */
function fileBytes(size: number, marker: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(size);
  let x = 0x9e3779b9 ^ size;
  for (let i = 0; i < size; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out[i] = x & 0xff;
  }
  out.set(new TextEncoder().encode(marker), Math.min(64, size - marker.length));
  return out;
}

/** A PNG signature and IHDR, then filler: "the plaintext bytes of an image". */
function pngLike(size: number): Uint8Array {
  const head = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
  const out = fileBytes(size, 'png-filler');
  out.set(head.slice(0, Math.min(head.length, size)));
  return out;
}

/** The legacy channel key of `decryptFile`: SHA-256("<channel>:accord-channel-key-v1"). */
function legacyChannelKey(channelId: string): Uint8Array {
  return sha256(new TextEncoder().encode(`${channelId}:accord-channel-key-v1`));
}

async function legacyEncrypt(channelId: string, plain: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', legacyChannelKey(channelId) as Uint8Array<ArrayBuffer>, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain as Uint8Array<ArrayBuffer>));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv);
  out.set(ct, 12);
  return out;
}

/** The C004 operator attack: decrypt a stored blob with the channel-id key, IV first, as `decryptFile` did. */
async function operatorDecrypts(channelId: string, blob: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey('raw', legacyChannelKey(channelId) as Uint8Array<ArrayBuffer>, 'AES-GCM', false, ['decrypt']);
  try {
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(0, 12) }, key, blob.slice(12));
    return true;
  } catch {
    return false;
  }
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

async function blobBytes(b: Blob): Promise<Uint8Array> {
  return new Uint8Array(await new Response(b).arrayBuffer());
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

const b64bytes = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

/** A content envelope carrying `d` (as a forger who knows the descriptor would write it). */
function envelopeWith(channelId: string, body: string, d: VerifiedDescriptor, name: string): string {
  return JSON.stringify({
    type: 'accord.content', v: 1, channel_id: channelId, body,
    attachments: [{
      v: 1, blob_id: d.blobId, scheme: 'A256GCM-STREAM64K',
      key: b64bytes(d.key), nonce_prefix: b64bytes(d.noncePrefix), sha256: b64bytes(d.sha256),
      size: d.size, padded_size: d.paddedSize, name, mime: 'application/octet-stream',
    }],
  });
}

/** The status of `GET /attachments/{id}` for `client`, through the proxy (REQ-38). */
async function downloadStatus(baseUrl: string, client: TestClient, blobId: string): Promise<number> {
  const r = await fetch(`${baseUrl}/attachments/${blobId}`, { headers: { Authorization: `Bearer ${client.token}` } });
  await r.arrayBuffer().catch(() => undefined);
  return r.status;
}

interface World {
  relay: RelayProcess;
  proxy: RecordingProxy;
  alice: TestClient;
  bob: TestClient;
  nodeId: string;
  /** Node channel X. */
  channelX: string;
  /** The DM channel D between Alice and Bob. */
  dmD: string;
}

async function buildWorld(extraRelayArgs: string[] = []): Promise<World> {
  const relay = await RelayProcess.start(extraRelayArgs);
  const proxy = new RecordingProxy(relay.port);
  await proxy.start();
  const bob = await TestClient.create('bob', proxy.baseUrl);
  const alice = await TestClient.create('alice', proxy.baseUrl);
  const node = await bob.api.createNode('spec02-two-client', bob.token);
  const invite = await bob.api.createInvite(node.id, bob.token);
  await alice.api.joinNodeByInvite(invite.invite_code, alice.token);
  const channels = await bob.api.getNodeChannels(node.id, bob.token);
  const channelX = channels.find(c => (c as { channel_type?: string }).channel_type !== 'voice')?.id ?? channels[0].id;
  await alice.connect();
  await bob.connect();
  const fr = await alice.api.sendFriendRequest(bob.userId, node.id);
  await bob.api.acceptFriendRequest(fr.request_id);
  const dmD = (await alice.api.createDmChannel(bob.userId, alice.token)).id;
  alice.dmChannels.add(dmD);
  bob.dmChannels.add(dmD);
  await alice.shareSenderKey(channelX, bob);
  return { relay, proxy, alice, bob, nodeId: node.id, channelX, dmD };
}

async function teardown(w: World | undefined): Promise<void> {
  if (!w) return;
  w.alice.disconnect();
  w.bob.disconnect();
  await w.proxy.close();
  await w.relay.dispose();
}

function nodeConv(channelId: string): Conversation {
  return { kind: 'channel', channelId };
}

function dmConv(w: World): Conversation {
  return { kind: 'dm', channelId: w.dmD, peerId: w.bob.userId };
}

/** Send one file from Alice and wait until Bob holds its verified descriptor. */
async function sendFile(
  w: World,
  conv: Conversation,
  body: string,
  name: string,
  type: string,
  bytes: Uint8Array,
  options: { expiresAt?: number } = {},
): Promise<{ id: string; received: Received; descriptor: VerifiedDescriptor }> {
  const before = w.bob.received.length;
  const id = await w.alice.send(conv, body, [{ file: new Blob([bytes as Uint8Array<ArrayBuffer>]), name, type }], options);
  const sent = await w.alice.waitForStatus(id, 'sent');
  const received = await w.bob.waitForMessage(r => w.bob.received.indexOf(r) >= before && r.messageId === sent.messageId);
  const [descriptor] = w.bob.descriptorsOf(received);
  expect(descriptor, 'Bob holds a verified descriptor').toBeDefined();
  return { id, received, descriptor };
}

const suite = RELAY_AVAILABLE ? describe : describe.skip;

suite('SPEC-02 two-client integration (real relay)', () => {
  let w: World;

  beforeAll(async () => {
    // Uploads are rate limited to 10 a minute per user (RG-C160, a relay
    // test); this suite uploads more than that from one account.
    w = await buildWorld(['--attachment-gc-interval-secs', '1', '--disable-rate-limits']);
  });

  afterAll(async () => {
    await teardown(w);
  });

  it('positive control: the scans find secrets that did cross (client frames unmasked, base64-wrapped text decoded)', () => {
    const traffic = w.proxy.capturedChunks();
    // Alice's token crosses in her masked Authenticate frame and in HTTP headers.
    expect(findLeaks(traffic, textNeedles('token', w.alice.token))).toContain('token utf8');
    const authFrames = w.proxy.jsonFrames('c2s').filter(f => f.conn.token === w.alice.token && 'Authenticate' in f.frame);
    expect(authFrames.length).toBeGreaterThan(0);
    // Base64-wrapped plaintext and a raw key inside other bytes are found too.
    const key = crypto.getRandomValues(new Uint8Array(32));
    expect(findLeaks([Buffer.from(btoa('x{"name":"secret-report.pdf"}y'))], textNeedles('name', 'secret-report.pdf'))).not.toEqual([]);
    expect(findLeaks([Buffer.concat([Buffer.from('abc'), Buffer.from(key), Buffer.from('def')])], binaryNeedles('key', key))).toContain('key raw');
    expect(findLeaks([Buffer.from(`{"k":"${Buffer.from(key).toString('base64url')}"}`)], binaryNeedles('key', key))).toContain('key base64url');
  });

  it('positive control: a secret split across TCP reads, raw or inside a base64 run, is still found in the HTTP traffic', async () => {
    // A proxy in front of a sink that only reads, so the relay plays no part.
    const sink = net.createServer(sock => {
      sock.on('data', () => {});
      sock.on('error', () => {});
    });
    await new Promise<void>(resolve => sink.listen(0, '127.0.0.1', resolve));
    const proxy = new RecordingProxy((sink.address() as net.AddressInfo).port);
    await proxy.start();
    try {
      const rawSecret = `split-raw-${crypto.randomUUID()}`;
      const b64Secret = `split-b64-${crypto.randomUUID()}`;
      const wrapped = Buffer.from(`{"name":"${b64Secret}"}`).toString('base64');
      const body = Buffer.from(`raw=${rawSecret}&wrapped=${wrapped}`);
      const cutRaw = body.indexOf(rawSecret) + (rawSecret.length >> 1);
      const cutB64 = body.indexOf(wrapped) + (wrapped.length >> 1);
      const head = Buffer.from(`POST /split-control HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\n\r\n`);
      const sock = net.connect(proxy.port, '127.0.0.1');
      await once(sock, 'connect');
      sock.setNoDelay(true);
      for (const part of [head, body.subarray(0, cutRaw), body.subarray(cutRaw, cutB64), body.subarray(cutB64)]) {
        sock.write(part);
        await sleep(100);
      }
      const total = head.length + body.length;
      const conn = await waitFor('the proxy records every byte', () =>
        proxy.connections.find(c => Buffer.concat(c.httpC2s).length === total));
      sock.destroy();
      // Each secret reached the proxy split over two reads: no single read holds it.
      expect(conn.httpC2s.length).toBeGreaterThanOrEqual(3);
      expect(conn.httpC2s.some(ch => ch.includes(rawSecret) || ch.includes(wrapped))).toBe(false);
      const leaks = findLeaks(proxy.capturedChunks(), [...textNeedles('raw', rawSecret), ...textNeedles('wrapped', b64Secret)]);
      expect(leaks).toContain('raw utf8');
      expect(leaks).toContain('wrapped utf8');
      // Scanning the reads one by one, as before, misses both.
      expect(findLeaks(conn.httpC2s, [...textNeedles('raw', rawSecret), ...textNeedles('wrapped', b64Secret)])).toEqual([]);
    } finally {
      await proxy.close();
      await new Promise<void>(resolve => sink.close(() => resolve()));
    }
  });

  it('the relay advertises attachments/2 to both clients (T-44 over the wire, REQ-17)', () => {
    expect(w.alice.caps.available).toBe(true);
    expect(w.bob.caps.available).toBe(true);
  });

  for (const where of ['node channel X', 'DM channel D'] as const) {
    it(`RG-C004-1 (${where}): the operator cannot decrypt, and no key or name reaches the relay`, async () => {
      const conv = where === 'DM channel D' ? dmConv(w) : nodeConv(w.channelX);
      const channelId = conv.channelId;
      const name = 'secret-report.pdf';
      const plain = fileBytes(MIB, 'RG-C004-1-file-canary');
      const { received, descriptor } = await sendFile(w, conv, 'quarterly numbers', name, 'application/pdf', plain);

      // The message decrypted on the right path and the envelope names its channel (T-6).
      expect(received.decoded.verified).toBe(true);
      expect(received.decoded.source).toBe(where === 'DM channel D' ? 'dr' : 'sk');
      expect(received.decoded.body).toBe('quarterly numbers');
      expect(descriptor.name).toBe(name);
      // T-36 over the wire: the broadcast lists the claimed id.
      expect(received.frame.attachment_ids).toEqual([descriptor.blobId]);
      // The message shows the attachment (the views' predicate).
      expect(w.bob.shown(received.message)?.attachments).toHaveLength(1);

      // The recipient downloads and verifies it (RG-C164 (c)).
      const state = await w.bob.load(received, descriptor);
      expect(state.status).toBe('ready');
      if (state.status === 'ready') expect(equalBytes(await blobBytes(state.blob), plain)).toBe(true);

      // The operator: read the blob store, compute the channel-id key, try AES-GCM with the first 12 bytes as IV.
      const stored = new Uint8Array(readFileSync(path.join(w.relay.attachmentsDir, descriptor.blobId)));
      expect(stored.length).toBe(blobLength(descriptor.paddedSize));
      expect(await operatorDecrypts(channelId, stored)).toBe(false);

      // Scan the database, the blob store, the legacy directory, the relay's log and all traffic.
      const haystacks = [
        ...w.relay.databaseBytes(),
        ...RelayProcess.filesUnder(w.relay.attachmentsDir).map(p => readFileSync(p)),
        ...RelayProcess.filesUnder(path.join(w.relay.dir, 'data')).map(p => readFileSync(p)),
        Buffer.from(w.relay.logText()),
        ...w.proxy.capturedChunks(),
      ];
      const needles = [
        ...binaryNeedles('file key', descriptor.key),
        ...binaryNeedles('nonce prefix', descriptor.noncePrefix),
        ...textNeedles('file name', name),
        ...textNeedles('file canary', 'RG-C004-1-file-canary'),
      ];
      expect(w.proxy.extensionsNegotiated, 'no compressed WebSocket payloads').toBe(0);
      expect(findLeaks(haystacks, needles)).toEqual([]);
    });
  }

  for (const where of ['node channel X', 'DM channel D'] as const) {
    it(`RG-C004-2 (${where}): a replaced blob fails its integrity check, and nothing is previewed, saved or cached`, async () => {
      const conv = where === 'DM channel D' ? dmConv(w) : nodeConv(w.channelX);
      const plain = pngLike(150_000);
      const { received, descriptor } = await sendFile(w, conv, 'holiday', 'photo.png', 'image/png', plain);
      const blobPath = path.join(w.relay.attachmentsDir, descriptor.blobId);
      const length = blobLength(descriptor.paddedSize);
      const urlsBefore = w.bob.createdUrls.length;
      const cacheBefore = JSON.stringify([...w.bob.cacheMap.entries()]);

      // (a) another file under the channel-id key in the legacy layout (IV ‖ ciphertext ‖ tag).
      const a = await legacyEncrypt(conv.channelId, fileBytes(length - 28, 'legacy-substitute'));
      // (b) another file sealed under the true key and nonce prefix, as a colluding key holder could.
      const b = sealedBytes(await sealAttachmentWithFixedKeyForVectors(fileBytes(plain.length, 'colluder'), descriptor.key, descriptor.noncePrefix));
      // (c) the plaintext bytes of an image.
      const c = pngLike(length);
      for (const [label, substitute] of [['a', a], ['b', b], ['c', c]] as const) {
        expect(substitute.length, label).toBe(length);
        writeFileSync(blobPath, substitute);
        const state = await w.bob.load(received, descriptor);
        expect(state, label).toEqual({ status: 'error', error: 'integrity' });
      }
      expect(w.bob.createdUrls.length).toBe(urlsBefore);
      expect(JSON.stringify([...w.bob.cacheMap.entries()])).toBe(cacheBefore);
    });
  }

  it('RG-C164 (c): an image attachment appears in the message and previews after verification, in a DM and in a node channel', async () => {
    for (const conv of [nodeConv(w.channelX), dmConv(w)]) {
      const plain = pngLike(40_000);
      const { received, descriptor } = await sendFile(w, conv, '', 'tiny.png', 'image/png', plain);
      expect(received.decoded.attachmentCount).toBe(1);
      expect(w.bob.shown(received.message)?.attachments).toHaveLength(1);
      const urls = w.bob.createdUrls.length;
      const state = await w.bob.load(received, descriptor);
      expect(state.status).toBe('ready');
      if (state.status === 'ready') {
        expect(state.blob.type).toBe('image/png');
        expect(state.url).toBe(w.bob.createdUrls[urls]);
      }
    }
  });

  it('RG-C024: with keyPair null, attachments and text go out under Sender Keys and the received attachment is shown', async () => {
    const mark = w.proxy.mark();
    const textCanary = 'RG-C024-text-canary';
    const name = 'c024-notes.txt';
    const { received } = await sendFile(w, nodeConv(w.channelX), 'with a file', name, 'text/plain', fileBytes(5_000, 'RG-C024-file-canary'));
    expect(received.decoded.attachmentCount).toBe(1);
    const textId = await w.alice.send(nodeConv(w.channelX), textCanary);
    const sentText = await w.alice.waitForStatus(textId, 'sent');
    const textReceived = await w.bob.waitForMessage(r => r.messageId === sentText.messageId);
    expect(textReceived.decoded.body).toBe(textCanary);

    const frames = w.proxy.jsonFrames('c2s', mark)
      .map(f => (f.frame.message_type as Record<string, unknown> | undefined)?.ChannelMessage as Record<string, unknown> | undefined)
      .filter((m): m is Record<string, unknown> => !!m);
    expect(frames.length).toBe(2);
    for (const m of frames) expect(isSenderKeyEnvelope(String(m.encrypted_data))).toBe(true);
    expect(findLeaks(w.proxy.capturedChunks(), [
      ...textNeedles('text', textCanary),
      ...textNeedles('name', name),
      ...textNeedles('file canary', 'RG-C024-file-canary'),
    ])).toEqual([]);
  });

  it('RG-C008: re-attribution, forged own echoes, withheld DMs, forged edits and re-served history show no attachment UI', async () => {
    const { alice, bob, proxy, relay } = w;
    // Carol, another member of the node, to whom the relay attributes forged items.
    const carol = await TestClient.create('carol', proxy.baseUrl);
    const carolInvite = await bob.api.createInvite(w.nodeId, bob.token);
    await carol.api.joinNodeByInvite(carolInvite.invite_code, carol.token);

    // A DM with an attachment, which Bob caches as a `dr` record and shows.
    const dm = await sendFile(w, dmConv(w), 'dm with file', 'dm.pdf', 'application/pdf', fileBytes(3_000, 'dm'));
    const m = dm.received.messageId;
    expect(bob.cacheMap.has(m)).toBe(true);
    const dmEntry = bob.shown(dm.received.message);
    expect(dmEntry?.attachments).toHaveLength(1);

    // (a) The cached DM id re-served as another member's (Carol's) message in node channel X.
    proxy.inject(bob.token, {
      type: 'channel_message', channel_id: w.channelX, message_id: m, from: carol.userId,
      encrypted_data: dm.received.payload, is_dm: false, timestamp: Math.floor(Date.now() / 1000),
    });
    const a = await bob.waitForMessage(r => r.messageId === m && r.channelId === w.channelX);
    expect(a.decoded.attachmentCount).toBe(0);
    expect(bob.shown(a.message)).toBeNull();
    expect(bob.store.get(bob.keyOf(a))).toBeUndefined();

    // (b) A forged own echo that reuses the id with another payload.
    proxy.inject(bob.token, {
      type: 'channel_message', channel_id: w.dmD, message_id: m, from: bob.userId,
      encrypted_data: btoa('forged'), is_dm: true, timestamp: Math.floor(Date.now() / 1000),
    });
    const b = await bob.waitForMessage(r => r.messageId === m && r.senderId === bob.userId);
    expect(b.decoded.attachmentCount).toBe(0);
    expect(bob.shown(b.message)).toBeNull();
    // The genuine DM message still shows its own attachment, and only it does.
    expect(bob.shown(dm.received.message)).toBe(dmEntry);

    // (c) A DM ciphertext withheld and delivered into node channel X with is_dm set.
    let withheld: Record<string, unknown> | null = null;
    proxy.serverFrameFilter = (conn, frame) => {
      if (conn.token === bob.token && frame.type === 'channel_message' && frame.channel_id === w.dmD && !withheld) {
        withheld = frame;
        return 'drop';
      }
      return 'forward';
    };
    const id = await alice.send(dmConv(w), 'withheld', [{ file: new Blob([fileBytes(2_000, 'withheld')]), name: 'w.pdf', type: 'application/pdf' }]);
    await alice.waitForStatus(id, 'sent');
    const frame = await waitFor('the withheld frame', () => withheld);
    proxy.serverFrameFilter = null;
    proxy.inject(bob.token, { ...frame, channel_id: w.channelX, is_dm: true });
    const c = await bob.waitForMessage(r => r.messageId === frame.message_id && r.channelId === w.channelX);
    expect(c.decoded.display).toBe('placeholder');
    expect(c.decoded.placeholder).toBe('wrong_conversation');
    expect(PLACEHOLDER_TEXT.wrong_conversation).toBe('Message not verified for this conversation');
    expect(c.decoded.body).toBe('');
    expect(bob.shown(c.message)).toBeNull();
    expect(bob.store.get(bob.keyOf(c))).toBeUndefined();

    // (d) A forged message_edit carrying descriptors, aimed at a text message.
    const textId = await alice.send(nodeConv(w.channelX), 'plain text target');
    const text = await alice.waitForStatus(textId, 'sent');
    const target = await bob.waitForMessage(r => r.messageId === text.messageId);
    const editsBefore = bob.edits.length;
    proxy.inject(bob.token, {
      type: 'message_edit', channel_id: w.channelX, message_id: target.messageId, sender_id: alice.userId,
      encrypted_data: btoa(envelopeWith(w.channelX, 'forged', dm.descriptor, 'evil.exe')), edited_at: Math.floor(Date.now() / 1000),
    });
    // (e) A forged edit aimed at an attachment message.
    const attachmentTarget = await sendFile(w, nodeConv(w.channelX), 'caption', 'x.pdf', 'application/pdf', fileBytes(1_000, 'x'));
    const targetEntry = bob.shown(attachmentTarget.received.message);
    expect(targetEntry?.attachments).toHaveLength(1);
    proxy.inject(bob.token, {
      type: 'message_edit', channel_id: w.channelX, message_id: attachmentTarget.received.messageId, sender_id: alice.userId,
      encrypted_data: btoa('new caption'), edited_at: Math.floor(Date.now() / 1000),
    });
    await waitFor('both forged edits', () => bob.edits.length >= editsBefore + 2);
    for (const e of bob.edits.slice(editsBefore)) expect(e.decision.action).toBe('drop');
    expect(bob.shown(target.message)).toBeNull();
    expect(bob.store.get(bob.keyOf(target))).toBeUndefined();
    expect(bob.shown(attachmentTarget.received.message)).toBe(targetEntry);

    // (f) The relay re-serves, in channel history, the id of a message Bob
    // showed live with its attachment: as Carol's unencrypted message, then as
    // Alice's unencrypted envelope that repeats the descriptor. The store
    // still holds the verified entry; neither history message may show it.
    const x = attachmentTarget.received.messageId;
    const forgedHistory = async (channelId: string, messageId: string, senderId: string, plaintext: string): Promise<HistoryMessageFields> => {
      relay.sql('UPDATE messages SET sender_id = ?, encrypted_payload = ? WHERE id = ?', [senderId, new TextEncoder().encode(plaintext), messageId]);
      const item = (await bob.historyMessages(channelId)).find(h => h.id === messageId);
      expect(item, `history item ${messageId}`).toBeDefined();
      expect(item!.sender_id).toBe(senderId);
      return item!;
    };
    const asCarol = await forgedHistory(w.channelX, x, carol.userId, 'forged caption');
    expect(asCarol._attachmentCount).toBeUndefined();
    expect(bob.shown(asCarol)).toBeNull();
    const unencrypted = await forgedHistory(w.channelX, x, alice.userId, envelopeWith(w.channelX, 'forged caption', attachmentTarget.descriptor, 'x.pdf'));
    expect(unencrypted._attachmentsIgnored).toBe(true);
    expect(bob.shown(unencrypted)).toBeNull();
    expect(bob.store.get(bob.keyOf(attachmentTarget.received))).toBe(targetEntry);
    // (b) once the relay serves it in history: the cached DM id as Bob's own message with another payload.
    const ownEcho = await forgedHistory(w.dmD, m, bob.userId, 'forged');
    expect(ownEcho._attachmentCount).toBeUndefined();
    expect(bob.shown(ownEcho)).toBeNull();
    expect(bob.store.get(bob.keyOf(dm.received))).toBe(dmEntry);
  });

  it('RG-C164 (b): the old and the new Files panel render the real R1 legacy list (oversized and non-UTF-8 names)', async () => {
    const { alice, bob, relay, proxy } = w;
    const now = Math.floor(Date.now() / 1000);
    // Rows an older client left, written into the database as an operator could.
    const rows = [
      { id: crypto.randomUUID(), stored: new TextEncoder().encode('bGVnYWN5LXJlcG9ydA=='), served: 'bGVnYWN5LXJlcG9ydA==' },
      { id: crypto.randomUUID(), stored: new Uint8Array(5_000).fill(0x41), served: '' },
      { id: crypto.randomUUID(), stored: Uint8Array.from([0xff, 0xfe, 0x80, 0x41]), served: '' },
    ];
    for (const [i, r] of rows.entries()) {
      relay.sql(
        'INSERT INTO files (id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [r.id, w.channelX, alice.userId, r.stored, 1_040, 'hash', `./data/files/${r.id}`, now - 100 + i],
      );
    }
    try {
      const response = await fetch(`${proxy.baseUrl}/channels/${w.channelX}/files`, { headers: { Authorization: `Bearer ${bob.token}` } });
      expect(response.status).toBe(200);
      const json = (await response.json()) as Array<Record<string, unknown>>;
      const served = new Map(json.map(r => [r.id, r]));
      for (const r of rows) {
        // (a) as the clients receive it: strings, "" for the two bad names, no storage_path.
        expect(served.get(r.id)?.encrypted_filename).toBe(r.served);
        expect(served.get(r.id)).not.toHaveProperty('storage_path');
        expect(served.get(r.id)).not.toHaveProperty('content_hash');
      }
      // The bbf2f17 Files panel renders it, with "" for the two bad names.
      let markup = '';
      expect(() => { markup = renderOldFileList(json); }).not.toThrow();
      const names = oldFileListNames(markup);
      expect(names).toHaveLength(json.length);
      expect(names.sort()).toEqual(json.map(r => String(r.encrypted_filename)).sort());
      // The new panel's reader gets the same strings.
      const listed = await bob.api.listLegacyFiles(w.channelX);
      for (const r of rows) expect(listed.find(l => l.id === r.id)?.encrypted_filename).toBe(r.served);
      // Control: the bbf2f17 relay sent the stored bytes as a JSON array, which crashed that panel.
      const asBbf2f17 = json.map(r => ({ ...r, encrypted_filename: [...(rows.find(x => x.id === r.id)?.stored ?? [])] }));
      expect(() => renderOldFileList(asBbf2f17)).toThrow(TypeError);
    } finally {
      relay.sql(`DELETE FROM files WHERE id IN (${rows.map(() => '?').join(', ')})`, rows.map(r => r.id));
    }
  });

  it('RG-C090: relay-rejected messages never pair with a later echo, and pairing works in channels that are not open', async () => {
    const { alice, bob } = w;
    // A fresh channel Z with slow mode on, where Alice has not written yet.
    const channelZ = (await bob.api.createChannel(w.nodeId, 'slow', 'text', bob.token)).id;
    await alice.join(channelZ);
    await bob.join(channelZ);
    await alice.shareSenderKey(channelZ, bob);
    await bob.api.setSlowMode(channelZ, 3600, bob.token);

    // A, an attachment message. Its upload passes (no cooldown yet); while it
    // is in flight Alice's text M0 is stored, so the claim meets the cooldown:
    // attachment_claim_failed / slow_mode, and A is marked failed.
    const realUpload = alice.api.uploadAttachment.bind(alice.api);
    let m0Id = '';
    alice.api.uploadAttachment = async (...args: Parameters<typeof realUpload>) => {
      const result = await realUpload(...args);
      m0Id = await alice.send(nodeConv(channelZ), 'M0 starts the cooldown');
      await alice.waitForStatus(m0Id, 'sent');
      return result;
    };
    let aId: string;
    try {
      aId = await alice.send(nodeConv(channelZ), 'A with file', [{ file: new Blob([fileBytes(1_000, 'A')]), name: 'a.txt', type: 'text/plain' }]);
    } finally {
      alice.api.uploadAttachment = realUpload;
    }
    const aView = await alice.waitForStatus(aId, 'failed');
    expect(aView.failure?.text).toMatch(/Slow mode/);
    const claimFailure = alice.errorFrames.find(f => f.code === 'attachment_claim_failed');
    expect(claimFailure?.reason).toBe('slow_mode');
    expect(Number(claimFailure?.retry_after)).toBeGreaterThan(0);

    // A', a text message the relay rejects with a generic error frame (the
    // cooldown again; the client cannot tell it from SEND_MESSAGES denied):
    // nothing pairs it, so it never shows "sent".
    const errorsBefore = alice.errorFrames.length;
    const textAId = await alice.send(nodeConv(channelZ), "A' text");
    await waitFor('the generic rejection', () => alice.errorFrames.slice(errorsBefore).some(f => f.code !== 'attachment_claim_failed' && typeof f.error === 'string'));
    expect(alice.pending.get(textAId)?.status).toBe('sending');

    // B goes through once slow mode is off, and pairs with B only.
    await bob.api.setSlowMode(channelZ, 0, bob.token);
    const cacheBefore = new Set(alice.cacheMap.keys());
    const bId = await alice.send(nodeConv(channelZ), 'B text');
    const bView = await alice.waitForStatus(bId, 'sent');
    expect(alice.pending.get(aId)?.status).toBe('failed');
    expect(alice.pending.get(textAId)?.status).toBe('sending');
    const added = [...alice.cacheMap.keys()].filter(k => !cacheBefore.has(k));
    expect(added).toEqual([bView.messageId]);
    expect((alice.cacheMap.get(bView.messageId!) as { plaintext: string }).plaintext).toBe('B text');

    // C, in channel X while the user looks at Z: pairs as well.
    const cId = await alice.send(nodeConv(w.channelX), 'C elsewhere');
    const cView = await alice.waitForStatus(cId, 'sent');
    expect((alice.cacheMap.get(cView.messageId!) as { channel_id: string }).channel_id).toBe(w.channelX);
  });
});

suite('SPEC-02 RG-C140 end to end: attachments follow their messages (real relay)', () => {
  let w: World;

  beforeAll(async () => {
    w = await buildWorld(['--attachment-gc-interval-secs', '1']);
  });

  afterAll(async () => {
    await teardown(w);
  });

  it('expiry, purge, deletion and channel deletion remove every blob; the legacy orphan goes too', async () => {
    const { alice, bob, relay, proxy } = w;
    const now = () => Math.floor(Date.now() / 1000);
    // The expiring message has a channel of its own, so the purge of X below
    // cannot remove it: only the expiry sweep and the GC can.
    const channelE = (await bob.api.createChannel(w.nodeId, 'expiring', 'text', bob.token)).id;
    await alice.join(channelE);
    await bob.join(channelE);
    await alice.shareSenderKey(channelE, bob);
    const expiring = await sendFile(w, nodeConv(channelE), 'expiring', 'e.pdf', 'application/pdf', fileBytes(2_000, 'e'), { expiresAt: now() + 2 });
    const purged = await sendFile(w, nodeConv(w.channelX), 'purged', 'p.pdf', 'application/pdf', fileBytes(2_000, 'p'));
    const deleted = await sendFile(w, nodeConv(w.channelX), 'deleted', 'd.pdf', 'application/pdf', fileBytes(2_000, 'd'));
    const channelY = (await bob.api.createChannel(w.nodeId, 'doomed', 'text', bob.token)).id;
    await alice.join(channelY);
    await bob.join(channelY);
    await alice.shareSenderKey(channelY, bob);
    const inY = await sendFile(w, nodeConv(channelY), 'in Y', 'y.pdf', 'application/pdf', fileBytes(2_000, 'y'));
    expect(relay.blobNames().length).toBeGreaterThanOrEqual(4);

    // A legacy file in channel Y, uploaded long ago by a client older than C1.
    alice.disconnect();
    bob.disconnect();
    await relay.stop();
    const legacyId = crypto.randomUUID();
    mkdirSync(relay.legacyDir, { recursive: true });
    const legacyBlob = path.join(relay.legacyDir, legacyId);
    writeFileSync(legacyBlob, fileBytes(500, 'legacy'));
    const old = new Date(Date.now() - 20 * 60_000);
    utimesSync(legacyBlob, old, old);
    relay.sql(
      'INSERT INTO files (id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [legacyId, channelY, alice.userId, new TextEncoder().encode('bGVnYWN5'), 500, 'hash', `./data/files/${legacyId}`, now() - 3600],
    );
    await relay.restart();
    await alice.connect();
    await bob.connect();
    expect(existsSync(legacyBlob)).toBe(true);

    // Before anything is removed, every blob downloads.
    for (const x of [purged, deleted, inY]) expect(await downloadStatus(proxy.baseUrl, bob, x.descriptor.blobId)).toBe(200);

    // REQ-38: once its message has expired, the blob is refused, sweep or not.
    await waitFor('expiry', () => now() > Number(expiring.received.frame.expires_at) || undefined, 10_000);
    expect(await downloadStatus(proxy.baseUrl, bob, expiring.descriptor.blobId)).toBe(404);

    // Delete one, purge X (which does not hold the expiring message), delete channel Y.
    await alice.api.deleteMessage(deleted.received.messageId, alice.token);
    await bob.api.purgeChannelBefore(w.channelX, now() + 1);
    await bob.api.deleteChannel(channelY, bob.token);

    // The next sweep, GC and reconciliation: a restart runs all three at once.
    alice.disconnect();
    bob.disconnect();
    await relay.restart();
    await bob.connect();
    await waitFor('every blob gone', () => relay.blobNames().length === 0 || undefined, 15_000);
    expect(existsSync(legacyBlob)).toBe(false);
    for (const x of [expiring, purged, deleted, inY]) {
      expect(await downloadStatus(proxy.baseUrl, bob, x.descriptor.blobId), x.received.decoded.body).toBe(404);
    }
  });
});

suite('SPEC-02 RG-C164 (d): expected failures until roadmap P0 item 7 (C022, C023)', () => {
  let w: World;
  /** The history items the expected failures look at; set by the passing precondition test. */
  let offlineDm: HistoryMessageFields | null = null;
  let rerendered: HistoryMessageFields | null = null;

  beforeAll(async () => {
    w = await buildWorld();
  });

  afterAll(async () => {
    await teardown(w);
  });

  it('preconditions: the DM sent while Bob was offline, and the channel message he saw live, are both in his history', async () => {
    // C022: a DM with an attachment arrives while the recipient is offline.
    w.bob.disconnect();
    const id = await w.alice.send(dmConv(w), 'while offline', [{ file: new Blob([fileBytes(1_000, 'off')]), name: 'o.pdf', type: 'application/pdf' }]);
    const sent = await w.alice.waitForStatus(id, 'sent');
    await w.bob.connect();
    offlineDm = (await w.bob.historyMessages(w.dmD)).find(m => m.id === sent.messageId) ?? null;
    expect(offlineDm).not.toBeNull();

    // C023: a channel message shown live, with its attachment, then the history re-renders.
    const r = await sendFile(w, nodeConv(w.channelX), 'shown live', 'l.pdf', 'application/pdf', fileBytes(1_000, 'live'));
    expect(w.bob.shown(r.received.message)?.attachments).toHaveLength(1);
    rerendered = (await w.bob.historyMessages(w.channelX)).find(m => m.id === r.received.messageId) ?? null;
    expect(rerendered).not.toBeNull();
  });

  // Only the final assertion may fail. Without the precondition there is
  // nothing to check, and returning makes the expected failure fail loudly.
  it.fails('DM: the recipient was offline when the message arrived (C022)', () => {
    if (!offlineDm) return;
    expect(w.bob.shown(offlineDm)?.attachments).toHaveLength(1);
  });

  it.fails('node channel: history re-renders after the message was shown live (C023)', () => {
    if (!rerendered) return;
    expect(w.bob.shown(rerendered)?.attachments).toHaveLength(1);
  });
});
