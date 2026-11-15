/**
 * SPEC-02 T-48 (REQ-48): send and edit functions accept only a sealed
 * payload, `_retryPayload` is gone, and the send primitive reports whether a
 * frame left instead of dropping it silently. T-14 (REQ-14): the upload
 * request carries the blob and nothing else.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AccordWebSocket } from '../ws';
import { AccordApi } from '../api';
import type { Message } from '../types';
import { isSealedPayload, sealForChannel, sealLegacyText, type SealedPayload } from './sealed';
import { SenderKeyStore } from './senderKeys';

const X = '7c9e6679-7425-40de-944b-e07fc1f90ae7';

class MockSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSED = 3;
  readyState = MockSocket.OPEN;
  sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: ((e: { code: number }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) {
    sockets.push(this);
  }
  send(data: string) {
    this.sent.push(data);
  }
  close() {
    this.readyState = MockSocket.CLOSED;
  }
}
let sockets: MockSocket[] = [];

function connected(): { client: AccordWebSocket; socket: MockSocket } {
  const client = new AccordWebSocket('tok', 'http://relay.test');
  client.connect();
  const socket = sockets[sockets.length - 1];
  socket.onopen?.();
  socket.onmessage?.({ data: JSON.stringify({ type: 'authenticated', user_id: 'u' }) });
  socket.sent = [];
  return { client, socket };
}

function sealed(text = 'hello'): SealedPayload {
  const store = new SenderKeyStore();
  store.getOrCreateMyKey(X);
  return sealForChannel(store, X, text);
}

beforeEach(() => {
  sockets = [];
  vi.stubGlobal('WebSocket', MockSocket);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe('T-48: the sealed type', () => {
  it('does not compile with a string, and is refused at run time when forged', () => {
    const { client } = connected();
    // @ts-expect-error a plaintext string is not a sealed payload
    expect(() => client.sendChannelMessage(X, 'plain text')).toThrow(TypeError);
    // @ts-expect-error neither is an object that looks like one
    expect(() => client.sendChannelMessage(X, { wire: 'aGk=', scheme: 'sk', wireSha256: '' })).toThrow(TypeError);
    // @ts-expect-error edits too
    expect(() => client.sendEditMessage('m1', 'plain edit')).toThrow(TypeError);
    const api = new AccordApi('http://relay.test');
    // @ts-expect-error and REST edits
    void expect(api.editMessage('m1', 'u1', 'plain edit')).rejects.toThrow(TypeError);
    // @ts-expect-error `_retryPayload` no longer exists on Message
    const m: Message = { id: 'x', author: 'a', content: 'c', timestamp: 0, _retryPayload: { channelId: X, content: 'body' } };
    expect(m).toBeTruthy();
    expect(isSealedPayload({ wire: 'aGk=', scheme: 'sk', wireSha256: '' })).toBe(false);
  });

  it('only the sealing functions produce it', async () => {
    const s = sealed();
    expect(isSealedPayload(s)).toBe(true);
    expect(s.scheme).toBe('sk');
    expect(Object.isFrozen(s)).toBe(true);
    const legacy = await sealLegacyText(async t => btoa(`x${t}`), 'hello');
    expect(legacy.scheme).toBe('legacy');
    await expect(sealLegacyText(async t => btoa(t), '{"type":"accord.content","v":1,"channel_id":"' + X + '","attachments":[]}')).rejects.toThrow();
    await expect(sealLegacyText(async t => btoa(t), '\u001eaccord-call\u001e{"type":"call_hello","v":1}')).rejects.toThrow();
    // The REQ-10 escape carries only a body and is text.
    expect((await sealLegacyText(async t => btoa(t), '{"type":"accord.content","v":1,"channel_id":"' + X + '","body":"hi"}')).scheme).toBe('legacy');
  });

  it('sendChannelMessage reports a frame it could not hand over, and never queues it', () => {
    const { client, socket } = connected();
    const payload = sealed();
    const ok = client.sendChannelMessage(X, payload, { attachmentIds: ['a'], expiresAt: 5, gate: { users: ['u'], ttlSecs: 9 }, replyTo: 'r' });
    expect(ok.handedOff).toBe(true);
    const frame = JSON.parse(socket.sent[0]);
    expect(frame.message_id).toBe(ok.messageId);
    expect(frame.message_type.ChannelMessage).toEqual({
      channel_id: X, encrypted_data: payload.wire, reply_to: 'r', expires_at: 5,
      gate_users: ['u'], gate_ttl_secs: 9, attachment_ids: ['a'],
    });
    socket.readyState = MockSocket.CLOSED;
    socket.onclose?.({ code: 1006 });
    const dropped = client.sendChannelMessage(X, payload);
    expect(dropped.handedOff).toBe(false);
    expect(typeof dropped.messageId).toBe('string');
    expect(client.getQueuedMessageCount()).toBe(0);
    expect(socket.sent).toHaveLength(1);
    client.disconnect();
  });

  it('omits attachment_ids when there are none', () => {
    const { client, socket } = connected();
    client.sendChannelMessage(X, sealed());
    expect(JSON.parse(socket.sent[0]).message_type.ChannelMessage).not.toHaveProperty('attachment_ids');
    client.disconnect();
  });

  it('the generic queued send refuses message and edit frames', () => {
    const { client } = connected();
    const frame = (t: object | string) => JSON.stringify({ message_type: t, message_id: 'm', timestamp: 0 });
    expect(() => client.send(frame({ ChannelMessage: { channel_id: X, encrypted_data: 'plain' } }))).toThrow(TypeError);
    expect(() => client.send(frame({ EditMessage: { message_id: 'm', encrypted_data: 'plain' } }))).toThrow(TypeError);
    expect(() => client.send(frame('Ping'))).not.toThrow();
    client.disconnect();
  });
});

describe('T-14 (REQ-14): the upload request', () => {
  class MockXhr {
    static last: MockXhr | null = null;
    method = '';
    url = '';
    headers: Record<string, string> = {};
    body: unknown = null;
    status = 201;
    responseText = '';
    upload = { addEventListener: vi.fn() };
    private listeners: Record<string, () => void> = {};
    constructor() {
      MockXhr.last = this;
    }
    open(method: string, url: string) {
      this.method = method;
      this.url = url;
    }
    setRequestHeader(k: string, v: string) {
      this.headers[k] = v;
    }
    addEventListener(type: string, fn: () => void) {
      this.listeners[type] = fn;
    }
    getResponseHeader(name: string) {
      return name === 'Retry-After' ? '7' : null;
    }
    send(body: unknown) {
      this.body = body;
      queueMicrotask(() => this.listeners.load?.());
    }
  }

  it('POSTs the blob as octet-stream with the Bearer header and nothing else', async () => {
    vi.stubGlobal('XMLHttpRequest', MockXhr);
    const api = new AccordApi('http://relay.test');
    api.setToken('tok');
    const blob = new Blob([new Uint8Array([1, 2, 3])], { type: 'application/octet-stream' });
    const answer = { attachment_id: '6f1c2b7e-0d4a-4f53-9b8e-2a6d3c1e9f04', blob_size: 3, blob_sha256: 'ab', pending_expires_at: 9 };
    const p = api.uploadAttachment(X, blob);
    MockXhr.last!.responseText = JSON.stringify(answer);
    expect(await p).toEqual(answer);
    const xhr = MockXhr.last!;
    expect(xhr.method).toBe('POST');
    expect(xhr.url).toBe(`http://relay.test/channels/${X}/attachments`);
    expect(xhr.headers).toEqual({ 'Content-Type': 'application/octet-stream', Authorization: 'Bearer tok' });
    expect(xhr.body).toBe(blob);
  });

  it('an error answer carries its status, reason and Retry-After', async () => {
    vi.stubGlobal('XMLHttpRequest', MockXhr);
    const api = new AccordApi('http://relay.test');
    const p = api.uploadAttachment(X, new Blob(['x']));
    MockXhr.last!.status = 429;
    MockXhr.last!.responseText = JSON.stringify({ error: 'Too many', code: 429, reason: 'too_many_pending' });
    await expect(p).rejects.toMatchObject({ status: 429, reason: 'too_many_pending', retryAfter: 7 });
  });

  it('deleteAttachment checks the status before any body, so 204 is a success', async () => {
    const statuses = [204, 404, 409];
    const f = vi.fn(async () => new Response(null, { status: statuses.shift()! }));
    vi.stubGlobal('fetch', f);
    const api = new AccordApi('http://relay.test');
    expect(await api.deleteAttachment('a')).toBe(204);
    expect(await api.deleteAttachment('a')).toBe(404);
    expect(await api.deleteAttachment('a')).toBe(409);
    expect((f.mock.calls[0] as unknown as [string, RequestInit])[1].method).toBe('DELETE');
  });
});
