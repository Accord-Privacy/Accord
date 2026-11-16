/**
 * One desktop client for the two-client tests (SPEC-02 §10.1): the real
 * frontend modules (api.ts, ws.ts, the E2EE manager, Sender Keys, the sealer,
 * the pending-send manager, the decode function, the attachment store and
 * views), wired exactly as App.tsx wires them, talking to the real relay
 * through the recording proxy.
 *
 * What App.tsx keeps in React state lives here in plain fields. The legacy
 * P-256 `keyPair` is null and the legacy channel-key opt-in is off, which is
 * the C024 state ("a reload after account creation leaves keyPair null"); the
 * decryptors are exactly App.tsx's, so the legacy channel key never applies.
 *
 * Sender keys travel as App.tsx sends them: Double-Ratchet-encrypted
 * distributions through the relay's `StoreSenderKey` queue, read back with
 * the key-distribution consumer rule (REQ-53).
 */

import { AccordApi } from '../api';
import { AccordWebSocket } from '../ws';
import { E2EEManager } from '../e2ee';
import type { PreKeyBundle } from '../e2ee/keys';
import { readKeyDistribution } from '../e2ee/plaintext';
import { NodeMetadataKey } from '../e2ee/metadata';
import {
  SenderKeyStore,
  buildDistributionMessage,
  decryptChannelMessage,
  isSenderKeyEnvelope,
  parseDistributionMessage,
  type SenderKeyDistributionMessage,
} from '../e2ee/senderKeys';
import { createConversationSealer } from '../attachments/sealer';
import {
  PendingSendManager,
  type Conversation,
  type PendingEvent,
  type PendingView,
  type SendOptions,
  type StagedSource,
} from '../attachments/send';
import {
  decodeEdit,
  decodeMessage,
  type DecodedMessage,
  type Decryptors,
  type EditDecision,
  type PlaintextCacheAccess,
  type VerifiedDescriptor,
} from '../attachments/decode';
import { relayOrigin } from '../attachments/envelope';
import { decodeHistoryItem, historyWireItem, type HistoryMessageFields } from '../attachments/history';
import { decodedFields } from '../attachments/messageFields';
import { attachmentEntryFor, type AttachmentBearer } from '../attachments/render';
import { AttachmentStore, type AttachmentEntry, type AttachmentKey } from '../attachments/store';
import { AttachmentViews, type AttachmentLoadState } from '../attachments/view';
import type { UploadAttachmentResponse } from '../types';

export const PASSWORD = 'integration-password-1';

const toWirePayload = (s: string) => btoa(s);
function fromWirePayload(s: string): string {
  try {
    return atob(s);
  } catch {
    return s;
  }
}
function isDoubleRatchetEnvelope(json: string): boolean {
  try {
    const env = JSON.parse(json);
    return !!env && typeof env === 'object' && (env.t === 'x3dh' || env.t === 'dr') && typeof env.ct === 'string';
  } catch {
    return false;
  }
}
function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** Poll `check` until it returns a value other than undefined/false. */
export async function waitFor<T>(what: string, check: () => T | undefined | null | false, timeoutMs = 15_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = check();
    if (v !== undefined && v !== null && v !== false) return v as T;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(50);
  }
}

/** One rendered message on the receiving side. */
export interface Received {
  readonly channelId: string;
  readonly messageId: string;
  readonly senderId: string;
  readonly payload: string;
  readonly isDm: boolean;
  readonly decoded: DecodedMessage;
  /** The `Message` fields App.tsx's live handler builds from this frame. */
  readonly message: AttachmentBearer & { readonly content: string };
  readonly frame: Record<string, unknown>;
}

export class TestClient {
  readonly api: AccordApi;
  readonly e2ee = new E2EEManager();
  readonly senderKeys = new SenderKeyStore();
  /** App.tsx's NMK store (nmkStoreRef): node id → Node Metadata Key, filled by `nmk` key distributions. */
  readonly nmks = new Map<string, NodeMetadataKey>();
  readonly store = new AttachmentStore();
  /** The own-message cache (ownMessagesRef), relay message id → §6.2.4 record or legacy string. */
  readonly cacheMap = new Map<string, unknown>();
  readonly cache: PlaintextCacheAccess;
  readonly views: AttachmentViews;
  readonly pending: PendingSendManager;
  readonly createdUrls: string[] = [];
  readonly revokedUrls: string[] = [];
  readonly received: Received[] = [];
  readonly edits: Array<{ frame: Record<string, unknown>; decision: EditDecision }> = [];
  readonly errorFrames: Array<Record<string, unknown>> = [];
  readonly pendingEvents: PendingEvent[] = [];
  readonly dmChannels = new Set<string>();
  /** The REQ-17 capability, from the hello frame and /health. */
  caps: { available: boolean; maxBlobBytes: number | null } = { available: false, maxBlobBytes: null };
  ws: AccordWebSocket | null = null;
  userId = '';
  token = '';
  publicKey = '';
  private bundleCache = new Map<string, PreKeyBundle>();

  private constructor(readonly name: string, readonly baseUrl: string) {
    this.api = new AccordApi(baseUrl);
    this.cache = {
      get: (id: string) => this.cacheMap.get(id),
      put: record => {
        this.cacheMap.set(record.message_id, record);
      },
    };
    this.views = new AttachmentViews(
      {
        download: (id, expected, signal) => this.api.downloadAttachment(id, expected, signal),
        createObjectURL: () => {
          const url = `blob:${this.baseUrl}/${this.createdUrls.length + 1}`;
          this.createdUrls.push(url);
          return url;
        },
        revokeObjectURL: url => {
          this.revokedUrls.push(url);
        },
      },
      this.store,
    );
    const sealer = createConversationSealer({
      e2ee: () => (this.e2ee.isInitialized ? this.e2ee : null),
      senderKeys: () => this.senderKeys,
      // Sender keys are created and distributed by `shareSenderKey` in these tests.
      bootstrapSenderKey: () => false,
      fetchBundle: peerId => this.peerBundle(peerId),
      persistSenderKeys: () => {},
      // The C024 state: no legacy keyPair, no opt-in.
      legacyText: () => null,
    });
    this.pending = new PendingSendManager({
      transport: {
        upload: (channelId, blob, onProgress) => this.api.uploadAttachment(channelId, blob, onProgress),
        deleteAttachment: id => this.api.deleteAttachment(id),
        sendFrame: (channelId, sealed, options) =>
          this.ws ? this.ws.sendChannelMessage(channelId, sealed, options) : { handedOff: false, messageId: '' },
        history: async (channelId, before) => {
          const page = await this.api.getChannelMessages(channelId, this.token, 50, before);
          return {
            items: (page.messages as unknown as Array<Record<string, unknown>>).map(m => ({
              messageId: String(m.id ?? ''),
              channelId: typeof m.channel_id === 'string' ? m.channel_id : '',
              senderId: typeof m.sender_id === 'string' ? m.sender_id : '',
              payload: typeof m.encrypted_payload === 'string' ? m.encrypted_payload : '',
              createdAt: typeof m.created_at === 'number' ? m.created_at : 0,
            })),
            nextCursor: page.next_cursor,
            hasMore: !!page.has_more,
          };
        },
      },
      sealer,
      cache: this.cache,
      ownUserId: () => this.userId || null,
      origin: () => this.origin,
      limits: () => this.caps,
    });
    this.pending.subscribe(e => this.pendingEvents.push(e));
  }

  get origin(): string {
    return relayOrigin(this.baseUrl)!;
  }

  /** Register a password account, log in, initialize E2EE and publish the prekey bundle. */
  static async create(name: string, baseUrl: string): Promise<TestClient> {
    const c = new TestClient(name, baseUrl);
    const pk = new Uint8Array(32);
    crypto.getRandomValues(pk);
    c.publicKey = [...pk].map(b => b.toString(16).padStart(2, '0')).join('');
    await c.api.register(c.publicKey, PASSWORD);
    const auth = await c.api.login(c.publicKey, PASSWORD);
    c.userId = auth.user_id;
    c.token = auth.token;
    c.api.setToken(auth.token);
    const bundle = c.e2ee.initialize();
    await c.api.publishKeyBundle(
      toBase64(bundle.identityKey),
      toBase64(bundle.signedPrekey),
      bundle.oneTimePrekey ? [toBase64(bundle.oneTimePrekey)] : [],
      c.token,
    );
    const caps = await c.api.relayCapabilities();
    c.caps = { available: caps.features.includes('attachments/2'), maxBlobBytes: caps.attachmentLimits?.max_blob_bytes ?? null };
    return c;
  }

  async peerBundle(peerId: string): Promise<PreKeyBundle | undefined> {
    const cached = this.bundleCache.get(peerId);
    if (cached) return cached;
    try {
      const resp = await this.api.fetchKeyBundle(peerId, this.token);
      const bundle: PreKeyBundle = {
        identityKey: fromBase64(resp.identity_key),
        signedPrekey: fromBase64(resp.signed_prekey),
        oneTimePrekey: resp.one_time_prekey ? fromBase64(resp.one_time_prekey) : undefined,
      };
      this.bundleCache.set(peerId, bundle);
      return bundle;
    } catch {
      return undefined;
    }
  }

  /** Open the WebSocket and wait for `authenticated`. */
  async connect(): Promise<void> {
    const socket = new AccordWebSocket(this.token, this.baseUrl);
    this.ws = socket;
    socket.on('channel_message', data => void this.onChannelMessage(data as unknown as Record<string, unknown>));
    socket.on('message_edit' as never, ((data: Record<string, unknown>) => void this.onEdit(data)) as never);
    socket.on('error', (err: unknown) => {
      if (!err || typeof err !== 'object' || err instanceof Error) return;
      const frame = err as Record<string, unknown>;
      this.errorFrames.push(frame);
      if (frame.code === 'attachment_claim_failed') this.pending.onClaimFailed(frame);
    });
    socket.on('sender_key_distribution' as never, ((data: Record<string, unknown>) => this.onSenderKeyDistribution(data)) as never);
    let authenticated = false;
    socket.on('authenticated', () => {
      authenticated = true;
    });
    socket.connect();
    await waitFor(`${this.name} authenticated`, () => authenticated);
    // The hello frame's features gate attachment sending (REQ-17).
    await waitFor(`${this.name} hello`, () => socket.relayFeatures().length > 0 || undefined, 5_000).catch(() => undefined);
    this.caps = { ...this.caps, available: socket.relayFeatures().includes('attachments/2') };
  }

  disconnect(): void {
    this.ws?.disconnect();
    this.ws = null;
  }

  /** App.tsx's decryptors (REQ-8): no keyPair gate, legacy key only with a keyPair (never here). */
  decryptors(opts: { doubleRatchet: boolean }): Decryptors {
    return {
      doubleRatchet: opts.doubleRatchet
        ? (senderId: string, payload: string) => {
            if (!this.e2ee.isInitialized || !senderId || senderId === this.userId) return null;
            const json = fromWirePayload(payload);
            if (!isDoubleRatchetEnvelope(json)) return null;
            return this.e2ee.decryptEnvelope(senderId, json);
          }
        : undefined,
      senderKeys: (channelId: string, senderId: string, payload: string) => {
        if (!senderId || !isSenderKeyEnvelope(payload)) return null;
        return decryptChannelMessage(this.senderKeys, channelId, senderId, payload);
      },
      // keyPair is null: the legacy channel key never applies.
      legacyChannelKey: () => null,
    };
  }

  private async onChannelMessage(data: Record<string, unknown>): Promise<void> {
    const channelId = typeof data.channel_id === 'string' ? data.channel_id : '';
    const senderId = typeof data.from === 'string' ? data.from : '';
    const messageId = typeof data.message_id === 'string' ? data.message_id : '';
    const payload = typeof data.encrypted_data === 'string' ? data.encrypted_data : '';
    if (!channelId || !messageId) return;
    if (senderId === this.userId && this.pending.pairLiveEcho({ channelId, messageId, senderId, payload }, data)) return;
    const isDm = !!data.is_dm || this.dmChannels.has(channelId);
    const decoded = await decodeMessage(
      { origin: this.origin, renderedChannelId: channelId, ownUserId: this.userId },
      { channelId, messageId, senderId, payload, editedAt: null },
      { decryptors: this.decryptors({ doubleRatchet: isDm }), cache: this.cache, store: this.store },
    );
    const message = { id: messageId, channel_id: channelId, sender_id: senderId, ...decodedFields(decoded, isDm) };
    this.received.push({ channelId, messageId, senderId, payload, isDm, decoded, message, frame: data });
  }

  /**
   * Load the newest page of a channel's history through the proxy and map it
   * exactly as App.tsx's history loader does: own items pair first (REQ-49),
   * then `decodeHistoryItem` with App's decryptor choice.
   */
  async historyMessages(channelId: string): Promise<HistoryMessageFields[]> {
    const page = await this.api.getChannelMessages(channelId, this.token, 50);
    const isDm = this.dmChannels.has(channelId);
    const out: HistoryMessageFields[] = [];
    for (const raw of page.messages as unknown[]) {
      const item = historyWireItem(raw);
      if (item.editedAt === null) {
        this.pending.pairHistoryItem({ messageId: item.messageId, channelId: item.channelId, senderId: item.senderId, payload: item.payload, createdAt: item.createdAt });
      }
      const fields = await decodeHistoryItem(raw, channelId, isDm, (wire, rendered, opts) => decodeMessage(
        { origin: this.origin, renderedChannelId: rendered, ownUserId: this.userId },
        wire,
        { decryptors: this.decryptors(opts), cache: this.cache, store: this.store },
      ));
      if (fields) out.push(fields);
    }
    return out;
  }

  /** The attachments a rendered message shows: the views' predicate (`attachments/render.ts`). */
  shown(msg: AttachmentBearer): AttachmentEntry | null {
    return attachmentEntryFor(msg, this.origin, this.store);
  }

  private async onEdit(data: Record<string, unknown>): Promise<void> {
    const channelId = typeof data.channel_id === 'string' ? data.channel_id : '';
    const messageId = typeof data.message_id === 'string' ? data.message_id : '';
    const senderId = typeof data.sender_id === 'string' ? data.sender_id : '';
    const payload = typeof data.encrypted_data === 'string' ? data.encrypted_data : '';
    const target = this.received.find(r => r.messageId === messageId && r.channelId === channelId);
    if (!target) return;
    const isDm = target.isDm;
    const decision = await decodeEdit(
      { origin: this.origin, renderedChannelId: channelId, ownUserId: this.userId },
      { channelId, messageId, senderId, payload },
      { messageId, channelId, senderId: target.senderId },
      { decryptors: this.decryptors({ doubleRatchet: isDm }), store: this.store },
    );
    this.edits.push({ frame: data, decision });
  }

  /** App.tsx's `sender_key_distribution` handler, with the REQ-53 consumer rule. */
  private onSenderKeyDistribution(data: Record<string, unknown>): void {
    const from = typeof data.from_user_id === 'string' ? data.from_user_id : '';
    const payload = typeof data.payload === 'string' ? data.payload : '';
    if (!from || !payload) return;
    try {
      const decrypted = this.e2ee.decryptEnvelope(from, fromWirePayload(payload));
      const read = readKeyDistribution(decrypted);
      if (read?.kind === 'legacy' && read.message.type === 'skdm') {
        const msg = read.message as unknown as SenderKeyDistributionMessage;
        this.senderKeys.setPeerKey(msg.ch, from, parseDistributionMessage(msg).state);
      } else if (read?.kind === 'legacy') {
        this.acceptNmkDistribution(read.message);
      }
      if (typeof data.distribution_id === 'string') this.ws?.ackSenderKeys([data.distribution_id]);
    } catch {
      // discarded silently (REQ-53)
    }
  }

  /**
   * App.tsx's `nmk` branch of both key-distribution consumers: a legacy key
   * message `{type: 'nmk', node, key}` stores that node's metadata key.
   */
  acceptNmkDistribution(message: Readonly<Record<string, unknown>>): void {
    if (message.type !== 'nmk' || typeof message.node !== 'string' || typeof message.key !== 'string' || !message.node || !message.key) return;
    const binary = atob(message.key);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    this.nmks.set(message.node, NodeMetadataKey.fromBytes(bytes));
  }

  /** The NMK store as node id → hex key, for comparing snapshots. */
  nmkSnapshot(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [node, key] of [...this.nmks].sort(([a], [b]) => a.localeCompare(b))) out[node] = Buffer.from(key.asBytes()).toString('hex');
    return out;
  }

  /** Open a channel as App.tsx does when the user selects it (`JoinChannel`). */
  async join(channelId: string): Promise<void> {
    this.ws!.joinChannel(channelId);
    await sleep(300);
  }

  /** Create this user's sender key for `channelId` and distribute it to `peer` as App.tsx does. */
  async shareSenderKey(channelId: string, peer: TestClient): Promise<void> {
    const sk = this.senderKeys.getOrCreateMyKey(channelId);
    const bundle = this.e2ee.hasSession(peer.userId) ? undefined : await this.peerBundle(peer.userId);
    const encrypted = this.e2ee.encryptEnvelope(peer.userId, JSON.stringify(buildDistributionMessage(channelId, sk)), bundle);
    this.ws!.storeSenderKey(channelId, peer.userId, toWirePayload(encrypted));
    await waitFor(`${peer.name} holds ${this.name}'s sender key`, () => peer.senderKeys.hasPeerKey(channelId, this.userId));
  }

  /** Prepare and start a send through the pending-send manager, as the composer does. */
  async send(conversation: Conversation, body: string, files: StagedSource[] = [], options: SendOptions = {}): Promise<string> {
    const prepared = await this.pending.prepare({ conversation, body, files, options });
    if (!prepared.ok) throw new Error(`send refused: ${prepared.error.code}`);
    const started = await this.pending.start(prepared.send);
    if (started.kind !== 'started') throw new Error(`send aborted: ${started.error.code}`);
    return started.id;
  }

  /** Wait until the pending send `id` reaches `status`. */
  async waitForStatus(id: string, status: PendingView['status'], timeoutMs = 15_000): Promise<PendingView> {
    try {
      return await waitFor(`${this.name} send ${status}`, () => this.statusOf(id, status), timeoutMs);
    } catch (e) {
      const v = this.pending.get(id);
      throw new Error(`${(e as Error).message}; now ${JSON.stringify({ status: v?.status, statusText: v?.statusText, failure: v?.failure })}; relay errors ${JSON.stringify(this.errorFrames.slice(-3))}`);
    }
  }

  /**
   * The view of send `id` once it has `status`. A paired record is closed and
   * leaves the manager, so "sent" is read from its `paired` event.
   */
  statusOf(id: string, status: PendingView['status']): PendingView | undefined {
    if (status === 'sent') {
      const paired = this.pendingEvents.find(e => e.type === 'paired' && e.view.id === id);
      if (paired && paired.type === 'paired') return { ...paired.view, messageId: paired.messageId };
    }
    const v = this.pending.get(id);
    return v && v.status === status ? v : undefined;
  }

  /** The first received message matching `pred`. */
  async waitForMessage(pred: (r: Received) => boolean, timeoutMs = 15_000): Promise<Received> {
    return waitFor(`${this.name} receives a message`, () => this.received.find(pred), timeoutMs);
  }

  keyOf(r: { channelId: string; messageId: string }): AttachmentKey {
    return { origin: this.origin, channelId: r.channelId, messageId: r.messageId };
  }

  /** The usable descriptors of a received message, from the attachment store. */
  descriptorsOf(r: { channelId: string; messageId: string }): VerifiedDescriptor[] {
    const entry = this.store.get(this.keyOf(r));
    if (!entry) return [];
    return entry.attachments.flatMap(a => (a.usable ? [a.descriptor] : []));
  }

  /** Download and verify one attachment through the views, as the message view does. */
  load(r: { channelId: string; messageId: string }, d: VerifiedDescriptor): Promise<AttachmentLoadState> {
    return this.views.load(this.keyOf(r), d);
  }

  /** Upload a raw blob directly (for tests that need a pending id). */
  upload(channelId: string, bytes: Uint8Array): Promise<UploadAttachmentResponse> {
    return this.api.uploadAttachment(channelId, new Blob([bytes as Uint8Array<ArrayBuffer>]));
  }
}
