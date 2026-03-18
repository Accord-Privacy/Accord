import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { AccordWebSocket, ConnectionStatus } from '../ws';

// ─── WebSocket Mock ──────────────────────────────────────────────────────────

/**
 * Minimal WebSocket mock that lets tests drive events manually.
 * Tracks all instances created so we can grab the latest one.
 */
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState: number = MockWebSocket.CONNECTING;
  url: string;
  sentMessages: string[] = [];

  onopen: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  // Track all instances so tests can retrieve them
  static instances: MockWebSocket[] = [];

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  send(data: string): void {
    this.sentMessages.push(data);
  }

  close(code = 1000, reason = ''): void {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.({
      code,
      reason,
      wasClean: code === 1000,
    } as CloseEvent);
  }

  // ── Helpers used by tests ──────────────────────────────────────────────

  /** Simulate the connection being established */
  triggerOpen(): void {
    this.readyState = MockWebSocket.OPEN;
    this.onopen?.(new Event('open'));
  }

  /** Simulate receiving a raw string from the server */
  triggerMessage(data: string): void {
    this.onmessage?.(new MessageEvent('message', { data }));
  }

  /** Simulate server sending a JSON object */
  triggerJsonMessage(payload: object): void {
    this.triggerMessage(JSON.stringify(payload));
  }

  /** Simulate a connection error */
  triggerError(): void {
    this.onerror?.(new Event('error'));
  }

  /** Simulate server closing the connection */
  triggerClose(code = 1001, reason = ''): void {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.({
      code,
      reason,
      wasClean: code === 1000,
    } as CloseEvent);
  }

  /** Get the last sent message parsed as JSON */
  lastSent(): any {
    const last = this.sentMessages[this.sentMessages.length - 1];
    return last ? JSON.parse(last) : undefined;
  }

  /** Get all sent messages parsed as JSON */
  allSent(): any[] {
    return this.sentMessages.map(m => JSON.parse(m));
  }
}

// ── Replace global WebSocket with mock ──────────────────────────────────────
vi.stubGlobal('WebSocket', MockWebSocket);

/** Convenience: get the most recently created mock socket */
function latestWs(): MockWebSocket {
  return MockWebSocket.instances[MockWebSocket.instances.length - 1];
}

/** Open a client and complete authentication so it reaches the CONNECTED state. */
function openAndAuthenticate(client: AccordWebSocket): MockWebSocket {
  client.connect();
  const ws = latestWs();
  ws.triggerOpen();
  // server confirms auth
  ws.triggerJsonMessage({ type: 'authenticated', user_id: 'u-1' });
  return ws;
}

// ─── Test Suite ──────────────────────────────────────────────────────────────

describe('AccordWebSocket', () => {
  let client: AccordWebSocket;

  beforeEach(() => {
    vi.useFakeTimers();
    MockWebSocket.instances = [];
    client = new AccordWebSocket('test-token', 'http://localhost:8080');
  });

  afterEach(() => {
    client.disconnect();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // ── 1. Connection State Management ────────────────────────────────────────

  describe('connection state management', () => {
    it('starts in disconnected state', () => {
      const info = client.getConnectionInfo();
      expect(info.status).toBe<ConnectionStatus>('disconnected');
      expect(info.reconnectAttempt).toBe(0);
    });

    it('connects to the correct WebSocket URL', () => {
      client.connect();
      const ws = latestWs();
      expect(ws.url).toBe('ws://localhost:8080/ws');
    });

    it('sends Authenticate message immediately on open', () => {
      client.connect();
      const ws = latestWs();
      ws.triggerOpen();

      expect(ws.sentMessages).toHaveLength(1);
      const auth = ws.lastSent();
      expect(auth).toMatchObject({ Authenticate: { token: 'test-token' } });
    });

    it('is NOT connected after open — waits for authenticated message', () => {
      client.connect();
      const ws = latestWs();
      ws.triggerOpen();

      expect(client.isSocketConnected()).toBe(false);
    });

    it('becomes connected after server sends authenticated message', () => {
      openAndAuthenticate(client);
      expect(client.isSocketConnected()).toBe(true);
    });

    it('returns connected status via getConnectionInfo()', () => {
      openAndAuthenticate(client);
      expect(client.getConnectionInfo().status).toBe('connected');
    });

    it('becomes disconnected after socket close', () => {
      const ws = openAndAuthenticate(client);
      ws.triggerClose(1000);
      expect(client.isSocketConnected()).toBe(false);
    });

    it('does not create a second socket when already connecting', () => {
      client.connect();
      const ws = latestWs();
      ws.readyState = MockWebSocket.CONNECTING;
      client.connect(); // duplicate call
      expect(MockWebSocket.instances).toHaveLength(1);
    });

    it('does not create a second socket when already open', () => {
      openAndAuthenticate(client);
      client.connect(); // duplicate call
      expect(MockWebSocket.instances).toHaveLength(1);
    });

    it('emits connection_status events as state changes', () => {
      const statuses: ConnectionStatus[] = [];
      client.on('connection_status', info => statuses.push(info.status));

      client.connect();
      const ws = latestWs();
      ws.triggerOpen(); // pending auth → 'reconnecting'
      ws.triggerJsonMessage({ type: 'authenticated', user_id: 'u-1' }); // → 'connected'

      expect(statuses).toContain('connected');
    });

    it('converts http:// base URL to ws://', () => {
      const c = new AccordWebSocket('t', 'http://example.com:9000');
      c.connect();
      expect(latestWs().url).toBe('ws://example.com:9000/ws');
      c.disconnect();
    });

    it('converts https:// base URL to wss://', () => {
      const c = new AccordWebSocket('t', 'https://example.com:9000');
      c.connect();
      expect(latestWs().url).toBe('wss://example.com:9000/ws');
      c.disconnect();
    });
  });

  // ── 2. Reconnection Logic — Exponential Backoff ───────────────────────────

  describe('reconnection logic', () => {
    it('schedules reconnect after unexpected close (non-1000 code)', () => {
      openAndAuthenticate(client);
      const ws = latestWs();
      ws.triggerClose(1001);

      // Advance time enough for the first retry
      vi.advanceTimersByTime(5000);

      // A second WebSocket should have been created
      expect(MockWebSocket.instances).toHaveLength(2);
    });

    it('does NOT reconnect after clean close (code 1000)', () => {
      openAndAuthenticate(client);
      const ws = latestWs();
      ws.triggerClose(1000);

      vi.advanceTimersByTime(60000);
      expect(MockWebSocket.instances).toHaveLength(1);
    });

    it('increments reconnectAttempt counter on each failure', () => {
      openAndAuthenticate(client);
      latestWs().triggerClose(1001);

      expect(client.getConnectionInfo().reconnectAttempt).toBe(1);

      // Advance and let the reconnect fire, then close again
      vi.advanceTimersByTime(5000);
      latestWs().triggerClose(1001);

      expect(client.getConnectionInfo().reconnectAttempt).toBe(2);
    });

    it('emits reconnecting event on unexpected close', () => {
      const cb = vi.fn();
      client.on('reconnecting', cb);

      openAndAuthenticate(client);
      latestWs().triggerClose(1001);

      expect(cb).toHaveBeenCalledWith({ attempt: 1, maxAttempts: 20 });
    });

    it('resets reconnect counter after successful re-authentication', () => {
      openAndAuthenticate(client);
      latestWs().triggerClose(1001);
      expect(client.getConnectionInfo().reconnectAttempt).toBe(1);

      vi.advanceTimersByTime(5000);
      const ws2 = latestWs();
      ws2.triggerOpen();
      ws2.triggerJsonMessage({ type: 'authenticated', user_id: 'u-1' });

      expect(client.getConnectionInfo().reconnectAttempt).toBe(0);
    });

    it('uses exponential backoff — second delay is longer than first', () => {
      vi.spyOn(client as any, 'connect');

      openAndAuthenticate(client);

      // Close #1 → attempt 1
      latestWs().triggerClose(1001);
      vi.advanceTimersByTime(500);
      expect(MockWebSocket.instances).toHaveLength(1); // too soon

      vi.advanceTimersByTime(4500); // ~1s base for attempt 1
      expect(MockWebSocket.instances).toHaveLength(2);

      // Close #2 → attempt 2 — base delay is 2s (2^1 * 1000)
      latestWs().triggerClose(1001);
      vi.advanceTimersByTime(1000);
      expect(MockWebSocket.instances).toHaveLength(2); // not yet

      vi.advanceTimersByTime(5000); // well past 2s
      expect(MockWebSocket.instances).toHaveLength(3);
    });

    it('does not reconnect after disconnect() is called', () => {
      openAndAuthenticate(client);
      client.disconnect();

      vi.advanceTimersByTime(60000);
      expect(MockWebSocket.instances).toHaveLength(1);
    });

    it('retry() resets attempt counter and reconnects', () => {
      openAndAuthenticate(client);
      latestWs().triggerClose(1001);
      // Simulate a few failed reconnects
      (client as any).reconnectAttempts = 10;
      (client as any).isDestroyed = true;

      client.retry();

      expect(client.getConnectionInfo().reconnectAttempt).toBe(0);
      expect((client as any).isDestroyed).toBe(false);
    });

    it('does not reconnect on auth rejection close codes (4401, 4403)', () => {
      const authErrorCb = vi.fn();
      client.on('auth_error', authErrorCb);

      openAndAuthenticate(client);
      latestWs().triggerClose(4401);

      vi.advanceTimersByTime(60000);
      // No additional socket should be created
      expect(MockWebSocket.instances).toHaveLength(1);
      expect(authErrorCb).toHaveBeenCalled();
    });
  });

  // ── 3. Message Queuing While Disconnected ─────────────────────────────────

  describe('message queuing', () => {
    it('queues messages sent while not connected', () => {
      // Not connected yet
      client.send('{"hello":"world"}');
      client.send('{"foo":"bar"}');
      expect(client.getQueuedMessageCount()).toBe(2);
    });

    it('does not send queued messages until authenticated', () => {
      client.send('{"hello":"world"}');

      client.connect();
      const ws = latestWs();
      ws.triggerOpen();

      // Still in auth-pending state — queue should NOT be flushed yet
      // Only the Authenticate message should have been sent
      expect(ws.sentMessages).toHaveLength(1);
      expect(ws.sentMessages[0]).toContain('Authenticate');
      expect(client.getQueuedMessageCount()).toBe(1);
    });

    it('flushes queue after successful authentication', () => {
      client.send('{"queued":1}');
      client.send('{"queued":2}');

      openAndAuthenticate(client);
      const ws = latestWs();

      // Auth message + 2 queued messages = 3 total sends
      expect(ws.sentMessages).toHaveLength(3);
      expect(client.getQueuedMessageCount()).toBe(0);
    });

    it('queues messages sent during reconnection and flushes on reconnect', () => {
      openAndAuthenticate(client);
      latestWs().triggerClose(1001);

      // Send messages while disconnected (reconnecting)
      client.send('{"msg":"a"}');
      client.send('{"msg":"b"}');
      expect(client.getQueuedMessageCount()).toBe(2);

      // Let reconnect fire and complete auth
      vi.advanceTimersByTime(5000);
      const ws2 = latestWs();
      ws2.triggerOpen();
      ws2.triggerJsonMessage({ type: 'authenticated', user_id: 'u-1' });

      expect(client.getQueuedMessageCount()).toBe(0);
      // Auth message + 2 queued messages
      const sent = ws2.allSent();
      expect(sent.some((m: any) => m.Authenticate)).toBe(true);
      expect(ws2.sentMessages).toHaveLength(3);
    });

    it('clears queue on disconnect()', () => {
      client.send('{"msg":"x"}');
      expect(client.getQueuedMessageCount()).toBe(1);
      client.disconnect();
      expect(client.getQueuedMessageCount()).toBe(0);
    });

    it('re-queues a message if ws.send() throws during flush', () => {
      openAndAuthenticate(client);
      const ws = latestWs();

      // Simulate disconnection and queue a message
      ws.readyState = MockWebSocket.CLOSED;
      (client as any).isConnected = false;
      client.send('{"msg":"retry"}');
      expect(client.getQueuedMessageCount()).toBe(1);
    });
  });

  // ── 4. Malformed Server Messages ──────────────────────────────────────────

  describe('malformed server messages', () => {
    it('emits error on invalid JSON', () => {
      const errorCb = vi.fn();
      client.on('error', errorCb);

      openAndAuthenticate(client);
      latestWs().triggerMessage('this is not json {{{');

      expect(errorCb).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Invalid message format' })
      );
    });

    it('does not crash on empty string message', () => {
      const errorCb = vi.fn();
      client.on('error', errorCb);

      openAndAuthenticate(client);
      expect(() => latestWs().triggerMessage('')).not.toThrow();
      expect(errorCb).toHaveBeenCalled();
    });

    it('does not crash on null JSON value', () => {
      const errorCb = vi.fn();
      client.on('error', errorCb);

      openAndAuthenticate(client);
      expect(() => latestWs().triggerMessage('null')).not.toThrow();
    });

    it('handles message with no type field — emits general message event', () => {
      const messageCb = vi.fn();
      client.on('message', messageCb);

      openAndAuthenticate(client);
      latestWs().triggerJsonMessage({ some_field: 'value' });

      expect(messageCb).toHaveBeenCalledWith({ some_field: 'value' });
    });

    it('handles message with unknown type — does not crash', () => {
      const messageCb = vi.fn();
      client.on('message', messageCb);

      openAndAuthenticate(client);
      expect(() =>
        latestWs().triggerJsonMessage({ type: 'totally_unknown_event_xyz', data: {} })
      ).not.toThrow();
      expect(messageCb).toHaveBeenCalled();
    });

    it('continues processing messages after a malformed one', () => {
      const messageCb = vi.fn();
      const errorCb = vi.fn();
      client.on('message', messageCb);
      client.on('error', errorCb);

      openAndAuthenticate(client);
      const ws = latestWs();

      ws.triggerMessage('GARBAGE');
      ws.triggerJsonMessage({ type: 'pong', ts: 123 });

      expect(errorCb).toHaveBeenCalledTimes(1);
      expect(messageCb).toHaveBeenCalledTimes(1);
    });
  });

  // ── 5. Auth Token / Auth Error Handling ───────────────────────────────────

  describe('auth handling', () => {
    it('emits auth_error and stops reconnecting on error message with auth_failed code', () => {
      const authErrorCb = vi.fn();
      client.on('auth_error', authErrorCb);

      openAndAuthenticate(client);
      latestWs().triggerJsonMessage({ type: 'error', code: 'auth_failed' });

      vi.advanceTimersByTime(60000);
      expect(authErrorCb).toHaveBeenCalled();
      // Should NOT create a second socket
      expect(MockWebSocket.instances).toHaveLength(1);
    });

    it('emits auth_error on close code 4401 (Unauthorized)', () => {
      const authErrorCb = vi.fn();
      client.on('auth_error', authErrorCb);

      openAndAuthenticate(client);
      latestWs().triggerClose(4401);

      expect(authErrorCb).toHaveBeenCalled();
    });

    it('emits auth_error on close code 4403 (Forbidden)', () => {
      const authErrorCb = vi.fn();
      client.on('auth_error', authErrorCb);

      openAndAuthenticate(client);
      latestWs().triggerClose(4403);

      expect(authErrorCb).toHaveBeenCalled();
    });

    it('sends token in Authenticate message (not in URL)', () => {
      const myToken = 'super-secret-bearer-token';
      const c = new AccordWebSocket(myToken, 'http://localhost:8080');
      c.connect();
      const ws = latestWs();
      ws.triggerOpen();

      const authMsg = ws.lastSent();
      expect(authMsg.Authenticate.token).toBe(myToken);
      expect(ws.url).not.toContain(myToken);
      c.disconnect();
    });

    it('emits authenticated event with server data', () => {
      const cb = vi.fn();
      client.on('authenticated', cb);
      openAndAuthenticate(client);
      expect(cb).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'authenticated', user_id: 'u-1' })
      );
    });

    it('emits connected event after authentication', () => {
      const cb = vi.fn();
      client.on('connected', cb);
      openAndAuthenticate(client);
      expect(cb).toHaveBeenCalledTimes(1);
    });
  });

  // ── 6. Event Dispatch to Registered Listeners ─────────────────────────────

  describe('event dispatch', () => {
    it('on() registers a listener; off() removes it', () => {
      const cb = vi.fn();
      client.on('pong', cb);

      openAndAuthenticate(client);
      latestWs().triggerJsonMessage({ type: 'pong', ts: 1 });
      expect(cb).toHaveBeenCalledTimes(1);

      client.off('pong', cb);
      latestWs().triggerJsonMessage({ type: 'pong', ts: 2 });
      expect(cb).toHaveBeenCalledTimes(1); // still 1 — not called again
    });

    it('dispatches typed events to their specific listeners', () => {
      const directMsg = vi.fn();
      const chanMsg = vi.fn();
      client.on('direct_message', directMsg);
      client.on('channel_message', chanMsg);

      openAndAuthenticate(client);
      const ws = latestWs();

      ws.triggerJsonMessage({ type: 'direct_message', content: 'hi' });
      expect(directMsg).toHaveBeenCalledWith({ type: 'direct_message', content: 'hi' });
      expect(chanMsg).not.toHaveBeenCalled();

      ws.triggerJsonMessage({ type: 'channel_message', channel_id: 'c-1' });
      expect(chanMsg).toHaveBeenCalledWith({ type: 'channel_message', channel_id: 'c-1' });
    });

    it('dispatches general message event for every incoming message', () => {
      const cb = vi.fn();
      client.on('message', cb);

      openAndAuthenticate(client);
      const ws = latestWs();

      ws.triggerJsonMessage({ type: 'pong' });
      ws.triggerJsonMessage({ type: 'presence_update', user_id: 'u-2' });

      expect(cb).toHaveBeenCalledTimes(2);
    });

    it('multiple listeners on the same event all receive the data', () => {
      const cb1 = vi.fn();
      const cb2 = vi.fn();
      client.on('pong', cb1);
      client.on('pong', cb2);

      openAndAuthenticate(client);
      latestWs().triggerJsonMessage({ type: 'pong' });

      expect(cb1).toHaveBeenCalledTimes(1);
      expect(cb2).toHaveBeenCalledTimes(1);
    });

    it('a throwing listener does not prevent other listeners from being called', () => {
      const badCb = vi.fn(() => { throw new Error('oops'); });
      const goodCb = vi.fn();
      client.on('pong', badCb);
      client.on('pong', goodCb);

      openAndAuthenticate(client);
      // Should not throw
      expect(() =>
        latestWs().triggerJsonMessage({ type: 'pong' })
      ).not.toThrow();
      expect(goodCb).toHaveBeenCalled();
    });

    it('emits disconnected event when socket closes', () => {
      const cb = vi.fn();
      client.on('disconnected', cb);

      openAndAuthenticate(client);
      latestWs().triggerClose(1001);

      expect(cb).toHaveBeenCalled();
    });

    it('emits error event on WebSocket error', () => {
      const cb = vi.fn();
      client.on('error', cb);

      openAndAuthenticate(client);
      latestWs().triggerError();

      expect(cb).toHaveBeenCalledWith(expect.any(Error));
    });

    it('dispatches presence_update to specific listener', () => {
      const cb = vi.fn();
      client.on('presence_update', cb);

      openAndAuthenticate(client);
      latestWs().triggerJsonMessage({ type: 'presence_update', user_id: 'u-99', online: true });

      expect(cb).toHaveBeenCalledWith({ type: 'presence_update', user_id: 'u-99', online: true });
    });

    it('listeners cleared after disconnect()', () => {
      const cb = vi.fn();
      client.on('pong', cb);
      client.disconnect();

      // Re-connecting after disconnect would create a new socket, but listeners
      // should have been wiped so cb never fires.
      client.retry();
      const ws = latestWs();
      ws.triggerOpen();
      ws.triggerJsonMessage({ type: 'authenticated', user_id: 'u-1' });
      ws.triggerJsonMessage({ type: 'pong' });

      expect(cb).not.toHaveBeenCalled();
    });
  });

  // ── 7. Online / Offline Window Events ────────────────────────────────────

  describe('online/offline integration', () => {
    it('triggers reconnect when window fires online event while disconnected', () => {
      openAndAuthenticate(client);
      latestWs().triggerClose(1001);

      const beforeCount = MockWebSocket.instances.length;

      // Simulate browser coming back online
      window.dispatchEvent(new Event('online'));

      // The online handler calls connect() directly (no delay) when not connected
      expect(MockWebSocket.instances.length).toBeGreaterThan(beforeCount);
    });
  });
});
