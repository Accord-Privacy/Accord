// WebSocket client with reconnection logic and event emitter pattern

import { WsMessage, WsMessageType, WsIncomingMessage } from './types';
import { isSealedPayload, type SealedPayload } from './e2ee/sealed';
import { encodeBase64 } from './attachments/base64';
import { decodeScreenDown, encodeScreenUp } from './voice/screenFrame';

/**
 * What the private send primitive reports (SPEC-02 REQ-48, shared with
 * SPEC-03 REQ-37 and SPEC-06 §6.8): whether the frame was handed to an open,
 * authenticated socket, and the envelope `message_id` it generated. A frame
 * that was not handed off is dropped, never queued.
 */
export interface SendResult {
  readonly handedOff: boolean;
  readonly messageId: string;
}

/** Optional members of a `ChannelMessage` frame. */
export interface ChannelSendOptions {
  readonly replyTo?: string;
  readonly expiresAt?: number;
  readonly gate?: { readonly users?: readonly string[]; readonly roles?: readonly string[]; readonly ttlSecs: number };
  /** The descriptor `blob_id`s of the envelope (SPEC-02 §6.5.1); omitted when empty. */
  readonly attachmentIds?: readonly string[];
}

/**
 * The relay's screen-sharing limits from `hello` (SPEC-03 §6.12.1), present
 * only when well formed: `max_sharers` an integer from 1 to 8 and
 * `max_bytes_per_second` an integer of at least 200,000.
 */
export interface ScreenLimits {
  readonly maxSharers: number;
  readonly maxBytesPerSecond: number;
}

/** The feature token of the screen-sharing relay path (SPEC-03 §6.12). */
export const SCREEN_FEATURE = 'screen/1';

/** A well-formed `SCREEN_DOWN` from the relay (SPEC-03 §6.12.2). */
export interface ScreenFragmentEvent {
  /** C, lowercase canonical. */
  readonly channelId: string;
  /** The sharer, stamped by the relay; lowercase canonical. */
  readonly from: string;
  /** The AMF1 fragment, byte for byte as the relay forwarded it. */
  readonly fragment: Uint8Array;
}

/** Parse `screen_limits` of a `hello`; null unless well formed (§6.12.1). */
export function parseScreenLimits(raw: unknown): ScreenLimits | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  const sharers = o.max_sharers;
  const rate = o.max_bytes_per_second;
  if (typeof sharers !== 'number' || !Number.isSafeInteger(sharers) || sharers < 1 || sharers > 8) return null;
  if (typeof rate !== 'number' || !Number.isSafeInteger(rate) || rate < 200_000) return null;
  return Object.freeze({ maxSharers: sharers, maxBytesPerSecond: rate });
}

/** An `ArrayBuffer` from any realm (jsdom, Node, browsers). */
function isArrayBuffer(data: unknown): data is ArrayBuffer {
  return Object.prototype.toString.call(data) === '[object ArrayBuffer]';
}

/**
 * Event names this class generates itself. A relay JSON message whose `type`
 * is one of them is not emitted under that name: `screen_fragment` comes only
 * from a well-formed binary SCREEN_DOWN (SPEC-03 §6.12.2), and the connection
 * events only from the socket's own state. (`authenticated` is handled before
 * this check.) `error` is not listed: the relay's `{"type":"error"}` frames
 * (SPEC-01 §6.3) are delivered as `error` events by design.
 */
const LOCAL_EVENTS: ReadonlySet<string> = new Set([
  'screen_fragment',
  'disconnected',
  'connected',
  'connection_status',
  'reconnecting',
  'auth_error',
  'message',
]);

// Event types for the WebSocket client
export type ConnectionStatus = 'connected' | 'disconnected' | 'reconnecting';

export interface ConnectionInfo {
  status: ConnectionStatus;
  reconnectAttempt: number;
  maxReconnectAttempts: number;
}

export interface WsEvents {
  authenticated: (data: { user_id: string }) => void;
  connected: () => void;
  disconnected: () => void;
  reconnecting: (info: { attempt: number; maxAttempts: number }) => void;
  connection_status: (info: ConnectionInfo) => void;
  message: (message: WsIncomingMessage) => void;
  error: (error: Error) => void;
  auth_error: () => void;
  hello: (data: any) => void;
  node_created: (data: any) => void;
  // SPEC-01 REQ-21, REQ-30 to REQ-34: join and leave answers, carrying
  // `request_id`, and the join-request notifications. `node_joined` is a hint
  // for the UI only (REQ-43).
  node_joined: (data: any) => void;
  join_pending: (data: any) => void;
  join_failed: (data: any) => void;
  node_left: (data: any) => void;
  leave_failed: (data: any) => void;
  join_request_created: (data: any) => void;
  join_request_denied: (data: any) => void;
  node_info: (data: any) => void;
  channel_created: (data: any) => void;
  direct_message: (data: any) => void;
  channel_message: (data: any) => void;
  message_edit: (data: any) => void;
  message_delete: (data: any) => void;
  messages_purged: (data: any) => void;
  metadata_updated: (data: any) => void;
  presence_update: (data: any) => void;
  presence_bulk: (data: any) => void;
  pong: (data: any) => void;
  voice_join: (data: any) => void;
  voice_leave: (data: any) => void;
  /** Legacy relay-readable audio from outdated clients: only legacy evidence (SPEC-03 REQ-3, REQ-4). */
  voice_packet: (data: any) => void;
  voice_speaking: (data: any) => void;
  voice_channel_joined: (data: any) => void;
  voice_channel_left: (data: any) => void;
  voice_peer_joined: (data: any) => void;
  voice_peer_left: (data: any) => void;
  voice_participants: (data: any) => void;
  voice_speaking_state: (data: any) => void;
  voice_key_exchange: (data: any) => void;
  /** An AMF1 audio frame (SPEC-03 §6.1): `{ from, channel_id, packet_data, timestamp }`. */
  srtp_voice_packet: (data: any) => void;
  /** Relay mode reports: they only drive a note (SPEC-03 REQ-41). */
  voice_mode_changed: (data: any) => void;
  voice_mode: (data: any) => void;
  // SPEC-03 §6.12.1: the screen-sharing relay messages, and §6.12.2's
  // binary SCREEN_DOWN, delivered as `screen_fragment`.
  screen_share_started: (data: any) => void;
  screen_share_stopped: (data: any) => void;
  screen_share_rejected: (data: any) => void;
  screen_watch_rejected: (data: any) => void;
  screen_keyframe_request: (data: any) => void;
  screen_watchers: (data: any) => void;
  screen_fragment: (data: ScreenFragmentEvent) => void;
  reaction_add: (data: any) => void;
  reaction_remove: (data: any) => void;
  message_pin: (data: any) => void;
  message_unpin: (data: any) => void;
  typing_start: (data: any) => void;
  read_receipt: (data: any) => void;
  bot_response: (data: any) => void;
}

type EventListener<T = any> = (data: T) => void;

/** The `message_type` object of a raw frame, if it has one. */
function messageTypeOf(raw: string): object | null {
  try {
    const frame = JSON.parse(raw) as { message_type?: unknown } | null;
    const t = frame?.message_type;
    return !!t && typeof t === 'object' ? t : null;
  } catch {
    return null;
  }
}

/** Whether a raw frame is a `ChannelMessage` or `EditMessage`. */
function carriesMessagePayload(raw: string): boolean {
  const t = messageTypeOf(raw);
  return !!t && ('ChannelMessage' in t || 'EditMessage' in t || 'DirectMessage' in t);
}

/**
 * Call traffic (SPEC-03 REQ-37): frames, call messages and screen messages
 * use the non-queuing primitive only, so nothing produced before a
 * disconnect is sent after it.
 */
const CALL_TRAFFIC = ['VoiceKeyExchange', 'SrtpVoicePacket', 'ScreenShareStart', 'ScreenShareStop', 'ScreenWatch', 'ScreenKeyframeRequest'];

function carriesCallTraffic(raw: string): boolean {
  const t = messageTypeOf(raw);
  return !!t && CALL_TRAFFIC.some(k => k in t);
}

export class AccordWebSocket {
  private ws: WebSocket | null = null;
  private token: string;
  private baseUrl: string;
  private listeners: Map<string, Set<EventListener>> = new Map();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 20;
  private reconnectDelay = 1000; // Start with 1 second
  private maxReconnectDelay = 30000; // Max 30 seconds
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  private isConnected = false;
  private isDestroyed = false;
  private pingInterval: ReturnType<typeof setInterval> | null = null;
  private connectionStatus: ConnectionStatus = 'disconnected';
  private messageQueue: string[] = [];
  private onlineHandler: (() => void) | null = null;
  private offlineHandler: (() => void) | null = null;
  // The relay's capability tokens from this socket's `hello` (SPEC-01 §6.8),
  // forgotten on disconnect. Clients test membership only.
  private features: string[] = [];
  // SPEC-03 §6.12.1: `screen_limits` of the same `hello`, when well formed.
  private limits: ScreenLimits | null = null;
  // SPEC-03 §8.4 row 3: whether this socket's `hello` has been processed.
  private helloSeen = false;

  constructor(token: string, baseUrl?: string) {
    this.token = token;
    // Derive WS URL from the provided base (or from the api module's current URL)
    const raw = baseUrl ||
      (typeof window !== 'undefined' && (window as any).__ACCORD_SERVER_URL__) ||
      import.meta.env.VITE_ACCORD_SERVER_URL ||
      'http://localhost:8080';
    this.baseUrl = String(raw).replace(/^http/, 'ws');

    // Listen for online/offline events
    if (typeof window !== 'undefined') {
      this.onlineHandler = () => {
        if (!this.isConnected && !this.isDestroyed) {
          this.reconnectAttempts = 0;
          this.connect();
        }
      };
      this.offlineHandler = () => {
        this.setConnectionStatus('disconnected');
      };
      window.addEventListener('online', this.onlineHandler);
      window.addEventListener('offline', this.offlineHandler);
    }
  }

  // Event emitter methods
  on<K extends keyof WsEvents>(event: K, listener: WsEvents[K]): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(listener as EventListener);
  }

  off<K extends keyof WsEvents>(event: K, listener: WsEvents[K]): void {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      eventListeners.delete(listener as EventListener);
    }
  }

  private emit<K extends keyof WsEvents>(event: K, data?: any): void {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      eventListeners.forEach(listener => {
        try {
          listener(data);
        } catch (error) {
          console.error(`Error in ${event} listener:`, error);
        }
      });
    }
  }

  private setConnectionStatus(status: ConnectionStatus): void {
    this.connectionStatus = status;
    this.emit('connection_status', {
      status,
      reconnectAttempt: this.reconnectAttempts,
      maxReconnectAttempts: this.maxReconnectAttempts,
    });
  }

  /**
   * The `features` of the relay's `hello` on the current socket (SPEC-01
   * §6.8); empty before the first `hello` and after a disconnect. Test
   * membership only, for example `relayFeatures().includes('admission/1')`.
   */
  relayFeatures(): readonly string[] {
    return this.features;
  }

  /**
   * The `screen_limits` of the current socket's `hello` (SPEC-03 §6.12.1),
   * or null when it was missing or malformed, before the first `hello`, and
   * after a disconnect.
   */
  screenLimits(): ScreenLimits | null {
    return this.limits;
  }

  /**
   * SPEC-03 §5.1: the current socket's `hello` listed `screen/1` with
   * well-formed `screen_limits`. Until that `hello` has been processed the
   * relay counts as not screen-capable.
   */
  isScreenCapable(): boolean {
    return this.isConnected && this.features.includes(SCREEN_FEATURE) && this.limits !== null;
  }

  /**
   * Whether the current socket's `hello` has been processed (SPEC-03 §8.4,
   * row 3): until then the client does not know what the relay offers and
   * shows screen sharing as "Not ready", not as unavailable.
   */
  helloProcessed(): boolean {
    return this.isConnected && this.helloSeen;
  }

  /** `WebSocket.bufferedAmount` of the open socket, 0 otherwise (SPEC-03 REQ-47 pacing). */
  bufferedAmount(): number {
    const n = this.ws && this.ws.readyState === WebSocket.OPEN ? this.ws.bufferedAmount : 0;
    return typeof n === 'number' && Number.isFinite(n) ? n : 0;
  }

  private forgetRelayFeatures(): void {
    this.features = [];
    this.limits = null;
    this.helloSeen = false;
  }

  getConnectionInfo(): ConnectionInfo {
    return {
      status: this.connectionStatus,
      reconnectAttempt: this.reconnectAttempts,
      maxReconnectAttempts: this.maxReconnectAttempts,
    };
  }

  // Reset reconnection and try again (for manual retry button)
  retry(): void {
    this.isDestroyed = false;
    this.reconnectAttempts = 0;
    this.reconnectDelay = 1000;
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    this.connect();
  }

  // Connection management
  connect(): void {
    if (this.isDestroyed) return;
    
    if (this.ws) {
      if (this.ws.readyState === WebSocket.CONNECTING) {
        return; // Already connecting
      }
      if (this.ws.readyState === WebSocket.OPEN) {
        return; // Already connected
      }
      // Clean up dead socket before creating a new one
      this.ws.onclose = null;
      this.ws.onerror = null;
      this.ws.onmessage = null;
      this.ws.onopen = null;
      this.ws = null;
    }

    // SECURITY NOTE: WebSocket connections authenticate via a post-connect Authenticate
    // message (not via URL query params or headers). The browser WebSocket API does not
    // support custom headers, so token-in-URL would be the only alternative — but we
    // avoid that to prevent token leakage in server/proxy access logs. Instead, the
    // token is sent as the first message after the connection opens and the server
    // validates it within a 5-second window.
    const wsUrl = `${this.baseUrl}/ws`;
    
    // A new socket has its own `hello` (SPEC-01 §6.8, SPEC-03 §6.1).
    this.forgetRelayFeatures();
    try {
      this.ws = new WebSocket(wsUrl);
      // SPEC-03 §6.12.2: binary messages arrive as ArrayBuffer, set before
      // the socket opens.
      this.ws.binaryType = 'arraybuffer';
      this.setupEventHandlers();
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      this.emit('error', new Error('Failed to create WebSocket connection'));
      this.scheduleReconnect();
    }
  }

  private setupEventHandlers(): void {
    if (!this.ws) return;

    this.ws.onopen = () => {
      // Send Authenticate message as the very first message after connection opens.
      // Server requires this within 5 seconds or it will close the connection.
      const authMsg = JSON.stringify({ Authenticate: { token: this.token } });
      try {
        this.ws!.send(authMsg);
      } catch (error) {
        console.error('Failed to send authentication message:', error);
        this.emit('error', new Error('Failed to authenticate WebSocket'));
        return;
      }

      // NOTE: We do NOT set isConnected = true here.
      // Wait for the server's "authenticated" message to confirm auth succeeded.
      // This prevents the client from thinking it's connected when auth may fail.
      this.setConnectionStatus('reconnecting'); // Still pending auth
    };

    this.ws.onmessage = (event) => {
      // SPEC-03 §6.12.2: binary messages are handled before JSON.parse. A
      // well-formed SCREEN_DOWN becomes `screen_fragment`; every other binary
      // message is dropped silently (REQ-26), never reported as an error.
      if (typeof event.data !== 'string') {
        this.handleBinary(event.data);
        return;
      }
      try {
        const message: WsIncomingMessage = JSON.parse(event.data);
        
        // Detect auth errors (token expired/invalid)
        if (message.type === 'error' && (message as any).code === 'auth_failed') {
          this.emit('auth_error');
          this.isDestroyed = true; // Stop reconnecting on auth failure
          return;
        }

        // Remember the relay's capability tokens and screen limits until the
        // socket closes.
        if (message.type === 'hello') {
          const features = (message as any).features;
          this.features = Array.isArray(features)
            ? features.filter((f: unknown): f is string => typeof f === 'string')
            : [];
          this.limits = parseScreenLimits((message as any).screen_limits);
          this.helloSeen = true;
        }

        // Handle server auth confirmation — NOW we're truly connected
        if (message.type === 'authenticated') {
          this.isConnected = true;
          this.reconnectAttempts = 0;
          this.reconnectDelay = 1000;
          this.startPingInterval();
          this.flushMessageQueue();
          this.setConnectionStatus('connected');
          this.emit('authenticated', message as any);
          this.emit('connected');
          return;
        }
        
        // Emit general message event
        this.emit('message', message);
        
        // Emit specific event based on message type, never under a name this
        // class generates itself (see LOCAL_EVENTS).
        if (typeof message.type === 'string' && message.type && !LOCAL_EVENTS.has(message.type)) {
          this.emit(message.type as keyof WsEvents, message);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
        this.emit('error', new Error('Invalid message format'));
      }
    };

    this.ws.onclose = (event) => {
      this.isConnected = false;
      this.forgetRelayFeatures();
      this.stopPingInterval();
      
      // Auth rejection from server (4401 or 4403)
      if (event.code === 4401 || event.code === 4403) {
        this.setConnectionStatus('disconnected');
        this.emit('auth_error');
        this.emit('disconnected');
        return;
      }
      
      this.emit('disconnected');
      
      if (!this.isDestroyed && event.code !== 1000) {
        // Not a normal closure, attempt reconnect
        this.setConnectionStatus('reconnecting');
        this.scheduleReconnect();
      } else {
        this.setConnectionStatus('disconnected');
      }
    };

    this.ws.onerror = (event) => {
      console.error('WebSocket error:', event);
      this.emit('error', new Error('WebSocket connection error'));
    };
  }

  /** A binary message from the relay (SPEC-03 §6.12.2). */
  private handleBinary(data: unknown): void {
    if (!this.isConnected || !isArrayBuffer(data)) return;
    const msg = decodeScreenDown(new Uint8Array(data));
    if (!msg) return;
    const ev: ScreenFragmentEvent = { channelId: msg.channelId, from: msg.from, fragment: msg.fragment };
    this.emit('screen_fragment', ev);
  }

  private scheduleReconnect(): void {
    if (this.isDestroyed || this.reconnectTimeout) return;
    
    // If browser reports offline, use a slow retry interval as fallback
    // (navigator.onLine can be unreliable — don't fully trust it)
    const isOffline = typeof navigator !== 'undefined' && !navigator.onLine;

    this.reconnectAttempts++;

    let delay: number;
    if (isOffline) {
      // Slow retry when offline — the online event listener will also trigger reconnect
      delay = 30000;
    } else {
      // Exponential backoff with jitter to prevent thundering herd
      const baseDelay = Math.min(
        this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1),
        this.maxReconnectDelay
      );
      // Add random jitter: ±25% of the base delay
      const jitter = baseDelay * 0.25 * (Math.random() * 2 - 1);
      delay = Math.max(500, baseDelay + jitter);
    }

    this.setConnectionStatus('reconnecting');
    this.emit('reconnecting', { attempt: this.reconnectAttempts, maxAttempts: this.maxReconnectAttempts });

    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = null;
      this.connect();
    }, delay);
  }

  private startPingInterval(): void {
    this.pingInterval = setInterval(() => {
      if (this.isConnected) {
        this.ping();
      }
    }, 30000); // Ping every 30 seconds
  }

  private stopPingInterval(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  // Message sending methods
  /**
   * Send one frame on the open, authenticated socket. Reports whether it was
   * handed off and never queues: a frame for a closed socket is dropped and
   * reported, so callers can resend it themselves (SPEC-02 REQ-48).
   */
  private sendMessage(messageType: WsMessageType): SendResult {
    const messageId = this.generateId();
    if (!this.isConnected || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return { handedOff: false, messageId };
    }

    const message: WsMessage = {
      message_type: messageType,
      message_id: messageId,
      timestamp: Math.floor(Date.now() / 1000),
    };

    try {
      this.ws.send(JSON.stringify(message));
      return { handedOff: true, messageId };
    } catch {
      this.emit('error', new Error('Failed to send message'));
      return { handedOff: false, messageId };
    }
  }

  // Generic send method for custom messages (queues if offline). Message and
  // edit frames never go through it: they must carry a sealed payload and
  // must not be queued (SPEC-02 REQ-48).
  send(message: string): void {
    if (carriesMessagePayload(message)) {
      throw new TypeError('message and edit frames must use sendChannelMessage or sendEditMessage');
    }
    if (carriesCallTraffic(message)) {
      throw new TypeError('call traffic must use the non-queuing voice and screen senders');
    }
    if (!this.isConnected || !this.ws) {
      // Queue message for later delivery
      this.messageQueue.push(message);
      return;
    }

    try {
      this.ws.send(message);
    } catch (error) {
      console.error('Error sending WebSocket message:', error);
      this.messageQueue.push(message);
      this.emit('error', new Error('Failed to send message'));
    }
  }

  private flushMessageQueue(): void {
    while (this.messageQueue.length > 0 && this.isConnected && this.ws) {
      const msg = this.messageQueue.shift()!;
      try {
        this.ws.send(msg);
      } catch {
        this.messageQueue.unshift(msg);
        break;
      }
    }
  }

  getQueuedMessageCount(): number {
    return this.messageQueue.length;
  }

  // Node operations
  createNode(name: string, description?: string): void {
    this.sendMessage({ CreateNode: { name, description } });
  }

  // Join a node by id (SPEC-01 REQ-21); the relay answers with exactly one
  // `node_joined`, `join_pending` or `join_failed` frame.
  joinNode(nodeId: string, opts: { inviteCode?: string; deviceFingerprintHash?: string } = {}): void {
    this.sendMessage({
      JoinNode: {
        node_id: nodeId,
        ...(opts.inviteCode ? { invite_code: opts.inviteCode } : {}),
        ...(opts.deviceFingerprintHash ? { device_fingerprint_hash: opts.deviceFingerprintHash } : {}),
      },
    });
  }

  leaveNode(nodeId: string): void {
    this.sendMessage({ LeaveNode: { node_id: nodeId } });
  }

  getNodeInfo(nodeId: string): void {
    this.sendMessage({ GetNodeInfo: { node_id: nodeId } });
  }

  // Channel operations
  createChannel(nodeId: string, name: string): void {
    this.sendMessage({ CreateChannel: { node_id: nodeId, name } });
  }

  joinChannel(channelId: string): void {
    this.sendMessage({ JoinChannel: { channel_id: channelId } });
  }

  leaveChannel(channelId: string): void {
    this.sendMessage({ LeaveChannel: { channel_id: channelId } });
  }

  // Messaging
  sendDirectMessage(_toUser: string, _encryptedData: string): void {
    throw new Error('DirectMessage is deprecated. Use DM channels with sendChannelMessage instead.');
  }

  /**
   * Send a channel or DM message. The payload must be a `SealedPayload`
   * (SPEC-02 REQ-48): only the E2EE sealing functions produce one, so no
   * plaintext can reach the relay through this call. Returns whether the
   * frame was handed to an open socket.
   */
  sendChannelMessage(channelId: string, sealed: SealedPayload, options: ChannelSendOptions = {}): SendResult {
    if (!isSealedPayload(sealed)) throw new TypeError('sendChannelMessage accepts only a sealed payload');
    const ids = options.attachmentIds && options.attachmentIds.length > 0 ? [...options.attachmentIds] : undefined;
    return this.sendMessage({
      ChannelMessage: {
        channel_id: channelId,
        encrypted_data: sealed.wire,
        reply_to: options.replyTo,
        expires_at: options.expiresAt,
        gate_users: options.gate?.users && options.gate.users.length ? [...options.gate.users] : undefined,
        gate_roles: options.gate?.roles && options.gate.roles.length ? [...options.gate.roles] : undefined,
        gate_ttl_secs: options.gate?.ttlSecs,
        attachment_ids: ids,
      },
    });
  }

  /** Send an edit. The payload must be a `SealedPayload` (SPEC-02 REQ-48). */
  sendEditMessage(messageId: string, sealed: SealedPayload): SendResult {
    if (!isSealedPayload(sealed)) throw new TypeError('sendEditMessage accepts only a sealed payload');
    return this.sendMessage({ EditMessage: { message_id: messageId, encrypted_data: sealed.wire } });
  }

  sendDeleteMessage(messageId: string): void {
    this.sendMessage({ DeleteMessage: { message_id: messageId } });
  }

  // Reactions
  addReaction(messageId: string, emoji: string): void {
    this.sendMessage({ AddReaction: { message_id: messageId, emoji } });
  }

  removeReaction(messageId: string, emoji: string): void {
    this.sendMessage({ RemoveReaction: { message_id: messageId, emoji } });
  }

  // Message pinning (admin/mod only)
  pinMessage(messageId: string): void {
    this.sendMessage({ PinMessage: { message_id: messageId } });
  }

  unpinMessage(messageId: string): void {
    this.sendMessage({ UnpinMessage: { message_id: messageId } });
  }

  // Typing indicators
  sendTypingStart(channelId: string): void {
    this.sendMessage({ TypingStart: { channel_id: channelId } });
  }

  // Voice operations
  joinVoiceChannel(channelId: string): SendResult {
    return this.sendMessage({ JoinVoiceChannel: { channel_id: channelId } });
  }

  leaveVoiceChannel(channelId: string): SendResult {
    return this.sendMessage({ LeaveVoiceChannel: { channel_id: channelId } });
  }

  getVoiceParticipants(channelId: string): SendResult {
    return this.sendMessage({ GetVoiceParticipants: { channel_id: channelId } });
  }

  sendVoiceSpeakingState(channelId: string, userId: string, speaking: boolean): void {
    this.sendMessage({ VoiceSpeakingState: { channel_id: channelId, user_id: userId, speaking } });
  }

  /**
   * One AMF1 audio frame (SPEC-03 §6.1, REQ-2): `SrtpVoicePacket` with the
   * frame as standard base64. Never queued (REQ-37): returns whether it was
   * handed to the open, authenticated socket.
   */
  sendMediaFrame(channelId: string, frame: Uint8Array): boolean {
    if (!this.isConnected) return false;
    return this.sendMessage({ SrtpVoicePacket: { channel_id: channelId, packet_data: encodeBase64(frame) } }).handedOff;
  }

  /**
   * One call message (SPEC-03 §6.3.1, REQ-1, REQ-37): `VoiceKeyExchange`
   * for exactly one target, with `sender_ssrc` and `key_generation` 0. Never
   * queued: returns whether it was handed to the open, authenticated socket.
   */
  sendCallMessage(channelId: string, targetUserId: string, wrappedKey: string): boolean {
    if (typeof targetUserId !== 'string' || targetUserId.length === 0) return false;
    if (!this.isConnected) return false;
    return this.sendMessage({
      VoiceKeyExchange: {
        channel_id: channelId,
        wrapped_key: wrappedKey,
        target_user_id: targetUserId,
        sender_ssrc: 0,
        key_generation: 0,
      },
    }).handedOff;
  }

  /**
   * One screen fragment as a binary `SCREEN_UP` (SPEC-03 §6.12.2, REQ-37):
   * sent on the open, authenticated socket of a screen-capable relay, never
   * queued. Returns whether it was handed off.
   */
  sendScreenFragment(channelId: string, fragment: Uint8Array): boolean {
    if (!this.isScreenCapable() || !this.ws || this.ws.readyState !== WebSocket.OPEN) return false;
    let bytes: Uint8Array<ArrayBuffer>;
    try {
      bytes = encodeScreenUp(channelId, fragment);
    } catch {
      return false;
    }
    try {
      this.ws.send(bytes);
      return true;
    } catch {
      return false;
    }
  }

  // SPEC-03 §6.12.1: the screen-sharing JSON messages, on the shared send
  // primitive (REQ-37), and only to a screen-capable relay: a relay without
  // `screen/1` would reject them, and nothing falls back (REQ-42).
  screenShareStart(channelId: string): SendResult {
    return this.sendScreenMessage({ ScreenShareStart: { channel_id: channelId } });
  }

  screenShareStop(channelId: string): SendResult {
    return this.sendScreenMessage({ ScreenShareStop: { channel_id: channelId } });
  }

  screenWatch(channelId: string, sharerId: string, watch: boolean): SendResult {
    return this.sendScreenMessage({ ScreenWatch: { channel_id: channelId, sharer_id: sharerId, watch } });
  }

  screenKeyframeRequest(channelId: string, sharerId: string): SendResult {
    return this.sendScreenMessage({ ScreenKeyframeRequest: { channel_id: channelId, sharer_id: sharerId } });
  }

  private sendScreenMessage(messageType: WsMessageType): SendResult {
    if (!this.isScreenCapable()) return { handedOff: false, messageId: this.generateId() };
    return this.sendMessage(messageType);
  }

  // Note: encryptedData should be base64-encoded encrypted content
  // The App component handles encryption before calling this method

  // Sender Key operations
  storeSenderKey(channelId: string, toUserId: string, payload: string): void {
    this.sendMessage({ StoreSenderKey: { channel_id: channelId, to_user_id: toUserId, payload } });
  }

  getPendingSenderKeys(): void {
    // Unit variant server-side: must serialize as a bare string, not a map
    this.sendMessage('GetPendingSenderKeys');
  }

  ackSenderKeys(ids: string[]): void {
    this.sendMessage({ AckSenderKeys: { ids } });
  }

  // Ping/Pong
  ping(): void {
    this.sendMessage('Ping');
  }

  pong(): void {
    this.sendMessage('Pong');
  }

  // Utility methods
  private generateId(): string {
    return crypto.randomUUID?.() ?? 
      'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
      });
  }

  isSocketConnected(): boolean {
    return this.isConnected;
  }

  // Cleanup
  disconnect(): void {
    this.isDestroyed = true;
    
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    
    this.stopPingInterval();
    
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }
    
    // Remove online/offline listeners
    if (typeof window !== 'undefined') {
      if (this.onlineHandler) window.removeEventListener('online', this.onlineHandler);
      if (this.offlineHandler) window.removeEventListener('offline', this.offlineHandler);
    }
    
    this.messageQueue = [];
    this.listeners.clear();
  }
}