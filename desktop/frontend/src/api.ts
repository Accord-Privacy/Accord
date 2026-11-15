// API client module for REST endpoints

import type { ParsedInviteLink, CustomEmoji, InviteListItem } from './types';
import { ApiError, apiErrorFromBody } from './apiError';
import { isSealedPayload, type SealedPayload } from './e2ee/sealed';
import { inviteCreateBody, type JoinResult } from './admission';
import {
  RegisterResponse,
  AuthResponse,
  CreateNodeRequest,
  NodeInfo,
  Node,
  Channel,
  MessagePaginationResponse,
  NodeMember,
  User,
  ErrorResponse,
  HealthResponse,
  LegacyFileRow,
  UploadAttachmentResponse,
  AttachmentLimits,
  UserProfile,
  UpdateProfileRequest,
  MessageReaction,
  MessageReactionsResponse,
  DmChannel,
  DmChannelsResponse,
  AuditLogResponse,
  NodeOverviewResponse,
  BatchMembersResponse,
  BatchChannelsResponse,
} from './types';

/** The answer of `GET /invites/:code/preview`. */
export interface InvitePreview {
  node_name: string;
  node_id: string;
  member_count: number;
  server_build_hash: string;
}

// Configuration - check for environment variable or use localStorage or default
function getDefaultBaseUrl(): string {
  if (typeof window !== 'undefined') {
    // Check localStorage for saved server URL
    const saved = localStorage.getItem('accord_server_url');
    if (saved) return saved;
    // Check runtime override
    if ((window as any).__ACCORD_SERVER_URL__) return (window as any).__ACCORD_SERVER_URL__;
  }
  return import.meta.env.VITE_ACCORD_SERVER_URL || 'http://localhost:8080';
}

/**
 * Detect if the frontend is being served by an Accord relay (same-origin).
 * Probes the current origin's /health endpoint.
 * Returns the origin URL if it's an Accord server, null otherwise.
 */
export async function detectSameOriginRelay(): Promise<string | null> {
  if (typeof window === 'undefined') return null;
  // Tauri webview origin serves bundled assets, never a relay
  if ('__TAURI_INTERNALS__' in window) return null;
  const origin = window.location.origin;
  // Don't probe localhost dev servers (vite default ports)
  if (origin.includes(':1420') || origin.includes(':5173') || origin.includes(':3000')) return null;
  try {
    const resp = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(3000) });
    if (resp.ok) {
      const data = await resp.json();
      if (data && (data.status === 'healthy' || data.status === 'ok')) {
        return origin;
      }
    }
  } catch {
    // Not an Accord server
  }
  return null;
}

/** No answer from the relay (connection refused, reset or aborted). */
export class AttachmentNetworkError extends Error {
  constructor() {
    super('Network error');
    this.name = 'AttachmentNetworkError';
  }
}

/** A download whose length differs from the descriptor's (REQ-20). */
export class AttachmentLengthError extends Error {
  constructor() {
    super('Attachment has the wrong length');
    this.name = 'AttachmentLengthError';
  }
}

/** A legacy route answered 410: legacy files are retired (SPEC-02 REQ-29). */
export class LegacyRetiredError extends Error {
  constructor() {
    super('Legacy uploads are no longer available');
    this.name = 'LegacyRetiredError';
  }
}

/** Upper bound on a legacy download: the old 100 MB limit plus IV and tag. */
const LEGACY_MAX_BLOB_BYTES = 104_857_600 + 28;

function parseJsonOrNull(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function errorWithRetryAfter(status: number, body: unknown, retryAfterHeader: string | null): ApiError {
  const e = apiErrorFromBody(status, body);
  if (e.retryAfter !== undefined || retryAfterHeader === null) return e;
  const seconds = Number(retryAfterHeader);
  return Number.isFinite(seconds) && seconds >= 0 ? new ApiError(e.message, e.status, e.reason, seconds) : e;
}

async function discardBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // nothing to discard
  }
}

/**
 * Read a body of exactly `expected` bytes (REQ-20): refuse a declared length
 * that differs, stop as soon as more arrives, and fail when less arrives.
 */
async function readExactly(response: Response, expected: number): Promise<Uint8Array> {
  const declared = response.headers.get('Content-Length');
  if (declared !== null && Number(declared) !== expected) {
    await discardBody(response);
    throw new AttachmentLengthError();
  }
  const out = await readUpTo(response, expected);
  if (out.length !== expected) throw new AttachmentLengthError();
  return out;
}

/** Read at most `limit` bytes, failing as soon as more arrive. */
async function readAtMost(response: Response, limit: number): Promise<Uint8Array> {
  const declared = response.headers.get('Content-Length');
  if (declared !== null && Number(declared) > limit) {
    await discardBody(response);
    throw new AttachmentLengthError();
  }
  return readUpTo(response, limit);
}

async function readUpTo(response: Response, limit: number): Promise<Uint8Array> {
  const reader = response.body?.getReader();
  if (!reader) {
    const buf = new Uint8Array(await response.arrayBuffer());
    if (buf.length > limit) throw new AttachmentLengthError();
    return buf;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      try {
        await reader.cancel();
      } catch {
        // already closed
      }
      throw new AttachmentLengthError();
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

export class AccordApi {
  private baseUrl: string;
  private _token: string | null = null;
  private _tokenRefresher: (() => Promise<string | null>) | null = null;
  private _refreshingToken: Promise<string | null> | null = null;

  constructor(baseUrl?: string) {
    this.baseUrl = (baseUrl || getDefaultBaseUrl()).replace(/\/+$/, '');
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }

  setBaseUrl(url: string) {
    this.baseUrl = url.replace(/\/+$/, '');
    localStorage.setItem('accord_server_url', url);
  }

  /** Store the auth token for use in Authorization headers on all subsequent requests. */
  setToken(token: string | null) {
    this._token = token;
  }

  getToken(): string | null {
    return this._token;
  }

  /**
   * Set a callback that will be invoked when a 401 is received.
   * The callback should re-authenticate and return the new token, or null if re-auth fails.
   */
  setTokenRefresher(refresher: (() => Promise<string | null>) | null): void {
    this._tokenRefresher = refresher;
  }

  private async refreshToken(): Promise<string | null> {
    if (!this._tokenRefresher) return null;
    // Deduplicate concurrent refresh calls
    if (!this._refreshingToken) {
      this._refreshingToken = this._tokenRefresher().finally(() => {
        this._refreshingToken = null;
      });
    }
    return this._refreshingToken;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    _isRetry = false
  ): Promise<T> {
    if (!this.baseUrl) {
      throw new Error('API base URL not set — cannot make request');
    }
    const url = `${this.baseUrl}${endpoint}`;
    
    // Build headers: always include Content-Type and merge caller-provided headers.
    // Automatically attach Authorization: Bearer header when a token is stored.
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this._token) {
      headers['Authorization'] = `Bearer ${this._token}`;
    }
    // Merge any caller-provided headers (may override the above)
    if (options.headers) {
      Object.assign(headers, options.headers);
    }

    const response = await fetch(url, {
      ...options,
      headers,
    });

    // On 401, try to refresh the token and retry once
    if (response.status === 401 && !_isRetry && this._tokenRefresher) {
      const newToken = await this.refreshToken();
      if (newToken) {
        this._token = newToken;
        return this.request<T>(endpoint, options, true);
      }
    }

    const data = await response.json();

    if (!response.ok) {
      // Keeps `error` as the message, and adds the status, `reason` and
      // `retry_after` of the relay's error body (SPEC-01 §6.2).
      throw apiErrorFromBody(response.status, data as ErrorResponse);
    }

    return data as T;
  }

  // Health check
  async health(): Promise<HealthResponse> {
    return this.request<HealthResponse>('/health');
  }

  // User registration — keypair-only, no username (legacy v1)
  async register(publicKey: string, password: string, displayName?: string): Promise<RegisterResponse> {
    return this.request<RegisterResponse>('/register', {
      method: 'POST',
      body: JSON.stringify({
        public_key: publicKey,
        password: password,
        ...(displayName ? { display_name: displayName } : {}),
      }),
    });
  }

  // User registration — username + password + device (v2)
  async registerV2(
    username: string,
    password: string,
    deviceInfo?: { fingerprint_hash: string; public_key: string; label: string },
    displayName?: string,
  ): Promise<RegisterResponse> {
    return this.request<RegisterResponse>('/register', {
      method: 'POST',
      body: JSON.stringify({
        username,
        password,
        ...(displayName ? { display_name: displayName } : {}),
        ...(deviceInfo
          ? {
              device_fingerprint_hash: deviceInfo.fingerprint_hash,
              device_public_key: deviceInfo.public_key,
              device_label: deviceInfo.label,
            }
          : {}),
      }),
    });
  }

  // User authentication — by public_key + password (legacy v1)
  async login(publicKey: string, password: string): Promise<AuthResponse> {
    return this.request<AuthResponse>('/auth', {
      method: 'POST',
      body: JSON.stringify({
        public_key: publicKey,
        password: password,
      }),
    });
  }

  // User authentication — by username + password (v2)
  async loginV2(
    username: string,
    password: string,
    deviceFingerprintHash?: string,
  ): Promise<AuthResponse> {
    return this.request<AuthResponse>('/auth', {
      method: 'POST',
      body: JSON.stringify({
        username,
        password,
        ...(deviceFingerprintHash ? { device_fingerprint_hash: deviceFingerprintHash } : {}),
      }),
    });
  }

  // Create a new Node
  async createNode(name: string, _token: string, description?: string): Promise<NodeInfo> {
    const request: CreateNodeRequest = {
      name,
      description,
    };

    return this.request<NodeInfo>(`/nodes`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Get Node information
  async getNodeInfo(nodeId: string, _token?: string): Promise<NodeInfo> {
    const url = `/nodes/${nodeId}`;
    
    return this.request<NodeInfo>(url);
  }

  // Join a Node by id (SPEC-01 REQ-20): with an invite of this node, as its
  // owner, or as a join request on a node whose policy is `request`, which the
  // relay answers with 202 `pending_approval`.
  async joinNode(
    nodeId: string,
    _token: string,
    opts: { inviteCode?: string; deviceFingerprintHash?: string } = {},
  ): Promise<JoinResult> {
    const body: Record<string, string> = {};
    if (opts.inviteCode) body.invite_code = opts.inviteCode;
    if (opts.deviceFingerprintHash) body.device_fingerprint_hash = opts.deviceFingerprintHash;
    return this.request<JoinResult>(
      `/nodes/${encodeURIComponent(nodeId)}/join`, {
        method: 'POST',
        body: Object.keys(body).length > 0 ? JSON.stringify(body) : undefined,
      }
    );
  }

  // Leave a Node
  async leaveNode(nodeId: string, _token: string): Promise<{ status: string; node_id: string }> {
    return this.request<{ status: string; node_id: string }>(
      `/nodes/${nodeId}/leave`, {
        method: 'POST',
      }
    );
  }

  // Get user's nodes
  async getUserNodes(_token: string): Promise<Node[]> {
    return this.request<Node[]>(`/nodes`);
  }

  // Get Node's channels
  async getNodeChannels(nodeId: string, _token: string): Promise<Channel[]> {
    return this.request<Channel[]>(`/nodes/${nodeId}/channels`);
  }

  // Get Node's members
  async getNodeMembers(nodeId: string, _token: string): Promise<Array<NodeMember & { user: User }>> {
    const result = await this.request<any>(`/nodes/${nodeId}/members`);
    // Server returns {members: [...]} — unwrap if needed
    if (result && result.members && Array.isArray(result.members)) return result.members;
    if (Array.isArray(result)) return result;
    return [];
  }

  // Get channel message history
  async getChannelMessages(channelId: string, _token: string, limit: number = 50, before?: string): Promise<MessagePaginationResponse> {
    let url = `/channels/${channelId}/messages?limit=${limit}`;
    if (before) {
      url += `&before=${encodeURIComponent(before)}`;
    }
    return this.request<MessagePaginationResponse>(url);
  }

  // ── Attachments (SPEC-02 §6.4) ──
  //
  // None of these use `request()`, which parses JSON before it checks the
  // status and so fails on an empty 204 (C205). Each checks the status first.
  // Every call authenticates with the Authorization header only, and no URL,
  // header or body carries a file name, MIME type or plaintext size (REQ-14).

  private authHeader(): Record<string, string> {
    return this._token ? { Authorization: `Bearer ${this._token}` } : {};
  }

  /**
   * Upload one sealed blob: `POST /channels/{id}/attachments` with an
   * `application/octet-stream` body equal to the blob (REQ-14). XHR with a
   * Blob body, for upload progress and because WebKitGTK lacks streaming
   * request bodies. Rejects with an `ApiError` for an error status (with the
   * `Retry-After` header as `retryAfter`) and with `AttachmentNetworkError`
   * when no answer arrives. A 401 refreshes the token and retries once.
   */
  async uploadAttachment(
    channelId: string,
    body: Blob,
    onProgress?: (loaded: number, total: number) => void,
    _isRetry = false,
  ): Promise<UploadAttachmentResponse> {
    const result = await new Promise<{ status: number; text: string; retryAfter: string | null }>((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.upload?.addEventListener('progress', (e) => {
        if (e.lengthComputable && onProgress) onProgress(e.loaded, e.total);
      });
      xhr.addEventListener('load', () => {
        resolve({ status: xhr.status, text: xhr.responseText, retryAfter: xhr.getResponseHeader('Retry-After') });
      });
      xhr.addEventListener('error', () => reject(new AttachmentNetworkError()));
      xhr.addEventListener('abort', () => reject(new AttachmentNetworkError()));
      xhr.addEventListener('timeout', () => reject(new AttachmentNetworkError()));
      xhr.open('POST', `${this.baseUrl}/channels/${encodeURIComponent(channelId)}/attachments`);
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      for (const [k, v] of Object.entries(this.authHeader())) xhr.setRequestHeader(k, v);
      xhr.send(body);
    });

    if (result.status === 401 && !_isRetry && this._tokenRefresher) {
      const newToken = await this.refreshToken();
      if (newToken) {
        this._token = newToken;
        return this.uploadAttachment(channelId, body, onProgress, true);
      }
    }
    if (result.status === 201 || result.status === 200) {
      const parsed = parseJsonOrNull(result.text) as Partial<UploadAttachmentResponse> | null;
      if (!parsed
        || typeof parsed.attachment_id !== 'string'
        || typeof parsed.blob_size !== 'number'
        || typeof parsed.blob_sha256 !== 'string'
        || typeof parsed.pending_expires_at !== 'number') {
        throw new ApiError('Invalid upload response', result.status, 'bad_response');
      }
      return {
        attachment_id: parsed.attachment_id,
        blob_size: parsed.blob_size,
        blob_sha256: parsed.blob_sha256,
        pending_expires_at: parsed.pending_expires_at,
      };
    }
    throw errorWithRetryAfter(result.status, parseJsonOrNull(result.text), result.retryAfter);
  }

  /**
   * Download one blob, `GET /attachments/{id}` (REQ-20). Aborts before reading
   * the body when the declared `Content-Length` differs from `expectedLength`,
   * and while reading as soon as more than `expectedLength` bytes arrive.
   * A body shorter than `expectedLength` fails too. Returns the received bytes
   * unverified: only `openAttachment` may release them (REQ-5).
   */
  async downloadAttachment(attachmentId: string, expectedLength: number, signal?: AbortSignal, _isRetry = false): Promise<Uint8Array> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/attachments/${encodeURIComponent(attachmentId)}`, {
        headers: this.authHeader(),
        cache: 'no-store',
        signal,
      });
    } catch (e) {
      if (signal?.aborted) throw e;
      throw new AttachmentNetworkError();
    }
    if (response.status === 401 && !_isRetry && this._tokenRefresher) {
      await discardBody(response);
      const newToken = await this.refreshToken();
      if (newToken) {
        this._token = newToken;
        return this.downloadAttachment(attachmentId, expectedLength, signal, true);
      }
    }
    if (response.status !== 200) {
      await discardBody(response);
      throw new ApiError(`HTTP ${response.status}`, response.status);
    }
    return readExactly(response, expectedLength);
  }

  /**
   * Delete one of this user's pending uploads, `DELETE /attachments/{id}`.
   * Returns the status: 204 (deleted), 404 (gone, or not this user's) or 409
   * (claimed by a stored message). Rejects with `AttachmentNetworkError`
   * when no answer arrives and with `ApiError` for any other status.
   */
  async deleteAttachment(attachmentId: string, _isRetry = false): Promise<204 | 404 | 409> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/attachments/${encodeURIComponent(attachmentId)}`, {
        method: 'DELETE',
        headers: this.authHeader(),
      });
    } catch {
      throw new AttachmentNetworkError();
    }
    await discardBody(response);
    if (response.status === 401 && !_isRetry && this._tokenRefresher) {
      const newToken = await this.refreshToken();
      if (newToken) {
        this._token = newToken;
        return this.deleteAttachment(attachmentId, true);
      }
    }
    if (response.status === 204 || response.status === 200) return 204;
    if (response.status === 404 || response.status === 409) return response.status;
    throw new ApiError(`HTTP ${response.status}`, response.status);
  }

  /**
   * The relay's capability tokens and attachment limits from `GET /health`
   * (SPEC-01 §6.8, SPEC-02 §6.4.6). Clients test `features` for membership.
   */
  async relayCapabilities(): Promise<{ features: string[]; attachmentLimits: AttachmentLimits | null }> {
    const response = await fetch(`${this.baseUrl}/health`, { cache: 'no-store' });
    if (!response.ok) {
      await discardBody(response);
      throw new ApiError(`HTTP ${response.status}`, response.status);
    }
    const data = (await response.json()) as Partial<HealthResponse> | null;
    const features = Array.isArray(data?.features) ? data!.features.filter((f): f is string => typeof f === 'string') : [];
    const l = data?.attachment_limits;
    const attachmentLimits = l && typeof l.max_blob_bytes === 'number' && typeof l.max_per_message === 'number'
      ? { max_blob_bytes: l.max_blob_bytes, max_per_message: l.max_per_message }
      : null;
    return { features, attachmentLimits };
  }

  // ── Legacy files (SPEC-02 §6.4.4, §6.4.5; read-only until retirement) ──

  /**
   * One page of a channel's legacy files, newest first. Rejects with
   * `LegacyRetiredError` on 410. Names come back as strings ("" when the
   * relay has none); rows of any other shape are dropped.
   */
  async listLegacyFiles(channelId: string, opts: { limit?: number; before?: string } = {}): Promise<LegacyFileRow[]> {
    const q = new URLSearchParams();
    if (opts.limit !== undefined) q.set('limit', String(opts.limit));
    if (opts.before !== undefined) q.set('before', opts.before);
    const qs = q.toString();
    const response = await this.legacyFetch(`/channels/${encodeURIComponent(channelId)}/files${qs ? `?${qs}` : ''}`, 'GET');
    const data = await response.json().catch(() => null);
    if (!Array.isArray(data)) return [];
    const rows: LegacyFileRow[] = [];
    for (const r of data as Array<Record<string, unknown>>) {
      if (!r || typeof r !== 'object' || typeof r.id !== 'string') continue;
      rows.push({
        id: r.id,
        channel_id: typeof r.channel_id === 'string' ? r.channel_id : channelId,
        uploader_id: typeof r.uploader_id === 'string' ? r.uploader_id : '',
        encrypted_filename: typeof r.encrypted_filename === 'string' ? r.encrypted_filename : '',
        file_size_bytes: typeof r.file_size_bytes === 'number' ? r.file_size_bytes : 0,
        created_at: typeof r.created_at === 'number' ? r.created_at : 0,
      });
    }
    return rows;
  }

  /** Download a legacy blob (IV ‖ ciphertext ‖ tag). Rejects with `LegacyRetiredError` on 410. */
  async downloadLegacyFile(fileId: string): Promise<Uint8Array> {
    const response = await this.legacyFetch(`/files/${encodeURIComponent(fileId)}`, 'GET');
    return readAtMost(response, LEGACY_MAX_BLOB_BYTES);
  }

  /** Delete a legacy file. Rejects with `LegacyRetiredError` on 410. */
  async deleteLegacyFile(fileId: string): Promise<void> {
    const response = await this.legacyFetch(`/files/${encodeURIComponent(fileId)}`, 'DELETE');
    await discardBody(response);
  }

  private async legacyFetch(endpoint: string, method: 'GET' | 'DELETE', _isRetry = false): Promise<Response> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${endpoint}`, { method, headers: this.authHeader(), cache: 'no-store' });
    } catch {
      throw new AttachmentNetworkError();
    }
    if (response.status === 401 && !_isRetry && this._tokenRefresher) {
      await discardBody(response);
      const newToken = await this.refreshToken();
      if (newToken) {
        this._token = newToken;
        return this.legacyFetch(endpoint, method, true);
      }
    }
    if (response.status === 410) {
      await discardBody(response);
      throw new LegacyRetiredError();
    }
    if (!response.ok) {
      const body = await response.json().catch(() => null);
      throw apiErrorFromBody(response.status, body);
    }
    return response;
  }

  // Create a new channel in a node
  async createChannel(nodeId: string, name: string, channelType: string, _token: string, topic?: string, parentId?: string): Promise<Channel> {
    const request: Record<string, unknown> = {
      name,
      channel_type: channelType,
    };
    if (topic) request.topic = topic;
    if (parentId) request.parent_id = parentId;

    return this.request<Channel>(`/nodes/${nodeId}/channels`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Update a channel (topic, name, etc.)
  async updateChannel(channelId: string, updates: { topic?: string; name?: string }, _token: string): Promise<Channel> {
    return this.request<Channel>(`/channels/${channelId}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  }

  // Delete a channel
  async deleteChannel(channelId: string, _token: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/channels/${channelId}`, {
      method: 'DELETE',
    });
  }

  // Generate an invite for a node
  async createInvite(nodeId: string, _token: string): Promise<{ invite_code: string; expires_at?: number }> {
    return this.request<{ invite_code: string; expires_at?: number }>(
      `/nodes/${nodeId}/invites`, {
        method: 'POST',
      }
    );
  }

  // Kick a member from a node
  async kickMember(nodeId: string, userId: string, _token: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(
      `/nodes/${nodeId}/members/${userId}`, {
        method: 'DELETE',
      }
    );
  }

  // Get user profile
  async getUserProfile(userId: string, _token?: string): Promise<UserProfile> {
    const url = `/users/${userId}/profile`;
    
    return this.request<UserProfile>(url);
  }

  // Update own profile
  async updateProfile(profile: UpdateProfileRequest, _token: string): Promise<UserProfile> {
    return this.request<UserProfile>(`/users/me/profile`, {
      method: 'PATCH',
      body: JSON.stringify(profile),
    });
  }

  // Preview an invite (public, no auth required) at `baseUrl`, without
  // probing. Errors carry the relay's `reason` (404 invite_invalid, 410
  // invite_expired / invite_exhausted, 429 rate_limited with retry_after).
  private async fetchInvitePreview(baseUrl: string, inviteCode: string): Promise<InvitePreview> {
    const url = `${baseUrl}/invites/${encodeURIComponent(inviteCode)}/preview`;
    const res = await fetch(url);
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: 'Request failed' }));
      throw apiErrorFromBody(res.status, body);
    }
    return res.json();
  }

  // Preview an invite (public, no auth required) — hits a specific relay URL
  async previewInvite(relayUrl: string, inviteCode: string): Promise<InvitePreview> {
    // Probe the relay URL to find the working scheme (http vs https)
    let workingUrl = relayUrl;
    try {
      workingUrl = await probeServerUrl(relayUrl);
    } catch { /* fall through to try original */ }
    return this.fetchInvitePreview(workingUrl, inviteCode);
  }

  // Preview an invite on this client's relay. The desktop uses it to learn
  // the invite's node id, from which it derives the node-scoped device
  // fingerprint it sends with the redemption (SPEC-01 REQ-43, §6.9).
  async previewInviteHere(inviteCode: string): Promise<InvitePreview> {
    return this.fetchInvitePreview(this.baseUrl, inviteCode);
  }

  // Join a Node via invite code (SPEC-01 REQ-19). The relay answers
  // {status: "joined", node_id, node_name}; refusals carry a `reason`.
  async joinNodeByInvite(
    inviteCode: string,
    _token: string,
    opts: { deviceFingerprintHash?: string } = {},
  ): Promise<JoinResult> {
    return this.request<JoinResult>(`/invites/${encodeURIComponent(inviteCode)}/join`, {
      method: 'POST',
      body: opts.deviceFingerprintHash
        ? JSON.stringify({ device_fingerprint_hash: opts.deviceFingerprintHash })
        : undefined,
    });
  }

  // Get invites for a node (admission authority only). Reads `invite_code`
  // and `current_uses`; older relays without the `code`/`uses` aliases send
  // those fields too.
  async getNodeInvites(nodeId: string, _token: string): Promise<InviteListItem[]> {
    const result = await this.request<any>(
      `/nodes/${nodeId}/invites`
    );
    // Server returns {invites: [...]} — unwrap if needed
    const raw: any[] = result && Array.isArray(result.invites)
      ? result.invites
      : Array.isArray(result) ? result : [];
    return raw.map((invite) => ({
      id: String(invite.id ?? ''),
      invite_code: String(invite.invite_code ?? invite.code ?? ''),
      created_at: Number(invite.created_at ?? 0),
      max_uses: typeof invite.max_uses === 'number' ? invite.max_uses : null,
      current_uses: Number(invite.current_uses ?? invite.uses ?? 0),
      expires_at: typeof invite.expires_at === 'number' ? invite.expires_at : null,
      created_by: typeof invite.created_by === 'string' ? invite.created_by : undefined,
    }));
  }

  // Create an invite with options. `expiresHours` may be fractional (0.5 =
  // 30 minutes). Relays that list `admission/1` in `features` get
  // `expires_in_seconds`; older relays get whole `expires_in_hours`, rounded
  // up (SPEC-01 REQ-43).
  async createInviteWithOptions(
    nodeId: string,
    _token: string,
    maxUses?: number,
    expiresHours?: number,
    relayFeatures?: readonly string[],
  ): Promise<{ id?: string; invite_code: string; expires_at?: number | null }> {
    const body = inviteCreateBody(maxUses, expiresHours, relayFeatures);
    return this.request<{ id?: string; invite_code: string; expires_at?: number | null }>(
      `/nodes/${nodeId}/invites`, {
        method: 'POST',
        body: Object.keys(body).length > 0 ? JSON.stringify(body) : undefined,
      }
    );
  }

  // Revoke an invite by its id (DELETE /invites/:id, SPEC-01 REQ-38).
  async revokeInvite(inviteId: string, _token: string): Promise<{ status: string; invite_id: string }> {
    return this.request<{ status: string; invite_id: string }>(
      `/invites/${encodeURIComponent(inviteId)}`, {
        method: 'DELETE',
      }
    );
  }

  // Search messages in a node
  async searchMessages(nodeId: string, query: string, _token: string, filters?: {
    channelId?: string;
    authorId?: string;
    before?: number;
    after?: number;
    limit?: number;
  }): Promise<{ 
    results: Array<{
      message_id: string;
      channel_id: string; 
      channel_name: string;
      sender_id: string;
      sender_public_key_hash: string;
      created_at: number;
      encrypted_payload: string;
    }>;
    total_count: number;
    note?: string;
  }> {
    let url = `/nodes/${nodeId}/search?q=${encodeURIComponent(query)}`;
    if (filters?.channelId) url += `&channel=${encodeURIComponent(filters.channelId)}`;
    if (filters?.authorId) url += `&author=${encodeURIComponent(filters.authorId)}`;
    if (filters?.before) url += `&before=${filters.before}`;
    if (filters?.after) url += `&after=${filters.after}`;
    if (filters?.limit) url += `&limit=${filters.limit}`;
    return this.request<{ 
      results: Array<{
        message_id: string;
        channel_id: string; 
        channel_name: string;
        sender_id: string;
        sender_public_key_hash: string;
        created_at: number;
        encrypted_payload: string;
      }>;
      total_count: number;
      note?: string;
    }>(url);
  }

  /**
   * Edit a message over REST. The payload must be a `SealedPayload` (SPEC-02
   * REQ-48), so no plaintext edit can reach the relay.
   */
  async editMessage(
    messageId: string,
    userId: string,
    sealed: SealedPayload,
  ): Promise<{ success: boolean }> {
    if (!isSealedPayload(sealed)) throw new TypeError('editMessage accepts only a sealed payload');
    return this.request<{ success: boolean }>(`/messages/${messageId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        user_id: userId,
        encrypted_data: sealed.wire,
      }),
    });
  }

  // Delete a message
  async deleteMessage(messageId: string, _token: string): Promise<{ success: boolean }> {
    return this.request<{ success: boolean }>(
      `/messages/${messageId}`, {
        method: 'DELETE',
      }
    );
  }

  /**
   * Retroactively purge a channel's messages older than `before` (unix seconds).
   * Backs the "wipe-old" path when disappearing messages is first enabled.
   */
  async purgeChannelBefore(channelId: string, before: number): Promise<{ success: boolean; removed: number }> {
    return this.request<{ success: boolean; removed: number }>(
      `/channels/${channelId}/purge_before`, {
        method: 'POST',
        body: JSON.stringify({ before }),
      }
    );
  }

  // Get message thread (replies to a message)
  async getMessageThread(messageId: string, _token: string): Promise<MessagePaginationResponse> {
    return this.request<MessagePaginationResponse>(
      `/messages/${messageId}/thread`
    );
  }

  // Get message reactions
  async getMessageReactions(messageId: string, _token: string): Promise<MessageReactionsResponse> {
    return this.request<MessageReactionsResponse>(
      `/messages/${messageId}/reactions`
    );
  }

  // Add reaction to message
  async addReaction(messageId: string, emoji: string, _token: string): Promise<{ success: boolean; reactions: MessageReaction[] }> {
    return this.request<{ success: boolean; reactions: MessageReaction[] }>(
      `/messages/${messageId}/reactions/${encodeURIComponent(emoji)}`, {
        method: 'PUT',
      }
    );
  }

  // Remove reaction from message
  async removeReaction(messageId: string, emoji: string, _token: string): Promise<{ success: boolean; reactions: MessageReaction[] }> {
    return this.request<{ success: boolean; reactions: MessageReaction[] }>(
      `/messages/${messageId}/reactions/${encodeURIComponent(emoji)}`, {
        method: 'DELETE',
      }
    );
  }

  // Pin a message (admin/mod only)
  async pinMessage(messageId: string, _token: string): Promise<{ success: boolean; message: string }> {
    return this.request<{ success: boolean; message: string }>(
      `/messages/${messageId}/pin`, {
        method: 'PUT',
      }
    );
  }

  // Unpin a message (admin/mod only)
  async unpinMessage(messageId: string, _token: string): Promise<{ success: boolean; message: string }> {
    return this.request<{ success: boolean; message: string }>(
      `/messages/${messageId}/pin`, {
        method: 'DELETE',
      }
    );
  }

  // Get pinned messages for a channel
  async getPinnedMessages(channelId: string, _token: string): Promise<{ pinned_messages: any[] }> {
    return this.request<{ pinned_messages: any[] }>(
      `/channels/${channelId}/pins`
    );
  }

  // Friend operations (friendship is required to open a new DM channel)

  async sendFriendRequest(toUserId: string, nodeId: string): Promise<{ status: string; request_id: string }> {
    return this.request<{ status: string; request_id: string }>(
      `/friends/request`, {
        method: 'POST',
        body: JSON.stringify({ to_user_id: toUserId, node_id: nodeId }),
      }
    );
  }

  async acceptFriendRequest(requestId: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(
      `/friends/accept`, {
        method: 'POST',
        body: JSON.stringify({ request_id: requestId }),
      }
    );
  }

  async rejectFriendRequest(requestId: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(
      `/friends/reject`, {
        method: 'POST',
        body: JSON.stringify({ request_id: requestId }),
      }
    );
  }

  /** Friendships as {user_a_hash, user_b_hash} pairs (match against member public_key_hash). */
  async listFriends(): Promise<Array<{ user_a_hash: string; user_b_hash: string }>> {
    const result = await this.request<any>(`/friends`);
    return Array.isArray(result?.friends) ? result.friends : [];
  }

  async listFriendRequests(): Promise<Array<{ id: string; from_user_id: string; to_user_id: string; node_id: string; status: string }>> {
    const result = await this.request<any>(`/friends/requests`);
    return Array.isArray(result?.requests) ? result.requests : [];
  }

  // Direct Message operations

  // Create or get DM channel with a user
  async createDmChannel(targetUserId: string, _token: string): Promise<DmChannel> {
    return this.request<DmChannel>(
      `/dm/${targetUserId}`, {
        method: 'POST',
      }
    );
  }

  // Get user's DM channels list
  async getDmChannels(_token: string): Promise<DmChannelsResponse> {
    return this.request<DmChannelsResponse>(
      `/dm`
    );
  }

  // Block a user
  async blockUser(userId: string, _token: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(
      `/users/${userId}/block`, { method: 'POST' }
    );
  }

  // Unblock a user
  async unblockUser(userId: string, _token: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(
      `/users/${userId}/block`, { method: 'DELETE' }
    );
  }

  // Get blocked users list
  async getBlockedUsers(_token: string): Promise<{ blocked_users: Array<{ user_id: string; created_at: number }> }> {
    return this.request<{ blocked_users: Array<{ user_id: string; created_at: number }> }>(
      `/api/blocked-users`
    );
  }

  // Mark channel as read up to a message
  async markChannelRead(channelId: string, messageId: string, _token: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(
      `/channels/${channelId}/read`, {
        method: 'POST',
        body: JSON.stringify({ message_id: messageId }),
      }
    );
  }

  // Get Node audit log (admin/mod only)
  async getNodeAuditLog(
    nodeId: string,
    _token: string,
    limit: number = 50,
    beforeId?: string
  ): Promise<AuditLogResponse> {
    const params = new URLSearchParams({
      limit: limit.toString(),
    });
    
    if (beforeId) {
      params.append('before', beforeId);
    }

    return this.request<AuditLogResponse>(
      `/nodes/${nodeId}/audit-log?${params.toString()}`
    );
  }

  // Get Node roles
  async getRoles(nodeId: string, _token: string): Promise<any[]> {
    const result = await this.request<any>(`/nodes/${nodeId}/roles`);
    if (result && Array.isArray(result.roles)) return result.roles;
    if (Array.isArray(result)) return result;
    return [];
  }

  // Create a role
  async createRole(nodeId: string, _token: string, data: { name: string; color?: string; hoist?: boolean; permissions?: number; mentionable?: boolean }): Promise<any> {
    return this.request<any>(`/nodes/${nodeId}/roles`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Update a role
  async updateRole(nodeId: string, roleId: string, _token: string, data: { name?: string; color?: string | null; hoist?: boolean; permissions?: number; mentionable?: boolean; position?: number }): Promise<any> {
    return this.request<any>(`/nodes/${nodeId}/roles/${roleId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  // Delete a role
  async deleteRole(nodeId: string, roleId: string, _token: string): Promise<any> {
    return this.request<any>(`/nodes/${nodeId}/roles/${roleId}`, {
      method: 'DELETE',
    });
  }

  // Get member's roles
  async getMemberRoles(nodeId: string, userId: string, _token: string): Promise<any[]> {
    const result = await this.request<any>(`/nodes/${nodeId}/members/${userId}/roles`);
    if (result && Array.isArray(result.roles)) return result.roles;
    if (Array.isArray(result)) return result;
    return [];
  }

  // Assign a role to a member
  async assignMemberRole(nodeId: string, userId: string, roleId: string, _token: string): Promise<any> {
    return this.request<any>(`/nodes/${nodeId}/members/${userId}/roles/${roleId}`, {
      method: 'PUT',
    });
  }

  // Remove a role from a member
  async removeMemberRole(nodeId: string, userId: string, roleId: string, _token: string): Promise<any> {
    return this.request<any>(`/nodes/${nodeId}/members/${userId}/roles/${roleId}`, {
      method: 'DELETE',
    });
  }

  // Import Discord template
  async importDiscordTemplate(nodeId: string, templateCode: string, _token: string): Promise<any> {
    return this.request<any>(`/nodes/${nodeId}/import-discord-template`, {
      method: 'POST',
      body: JSON.stringify({ template_code: templateCode }),
    });
  }

  // Update node settings (PATCH /nodes/:id)
  async updateNode(nodeId: string, data: { name?: string; description?: string }, _token: string): Promise<any> {
    return this.request<any>(`/nodes/${nodeId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  // Upload node icon
  async uploadNodeIcon(nodeId: string, file: File, token: string): Promise<{ status: string; icon_hash: string }> {
    const formData = new FormData();
    formData.append('icon', file);
    const authToken = token || this._token;
    const headers: Record<string, string> = {};
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
    const response = await fetch(`${this.baseUrl}/nodes/${nodeId}/icon`, {
      method: 'PUT',
      headers,
      body: formData,
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || `HTTP ${response.status}`);
    }
    return response.json();
  }

  // Get node icon URL
  getNodeIconUrl(nodeId: string): string {
    return `${this.baseUrl}/nodes/${nodeId}/icon`;
  }

  // Upload user avatar
  async uploadUserAvatar(file: File, token: string): Promise<{ status: string; avatar_hash: string }> {
    const formData = new FormData();
    formData.append('avatar', file);
    const authToken = token || this._token;
    const headers: Record<string, string> = {};
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
    const response = await fetch(`${this.baseUrl}/users/me/avatar`, {
      method: 'PUT',
      headers,
      body: formData,
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || `HTTP ${response.status}`);
    }
    return response.json();
  }

  // Get user avatar URL
  getUserAvatarUrl(userId: string): string {
    return `${this.baseUrl}/users/${userId}/avatar`;
  }

  // Publish E2EE prekey bundle
  async publishKeyBundle(
    identityKey: string,
    signedPrekey: string,
    oneTimePrekeys: string[],
    _token: string,
  ): Promise<{ status: string; one_time_prekeys_stored: number }> {
    return this.request(`/keys/bundle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identity_key: identityKey,
        signed_prekey: signedPrekey,
        one_time_prekeys: oneTimePrekeys,
      }),
    });
  }

  // Fetch a user's E2EE prekey bundle
  async fetchKeyBundle(
    targetUserId: string,
    _token: string,
  ): Promise<{ user_id: string; identity_key: string; signed_prekey: string; one_time_prekey?: string }> {
    return this.request(`/keys/bundle/${targetUserId}`);
  }

  // ── Encrypted metadata (NMK blobs — relay stores opaquely) ──

  // Fetch a node's encrypted metadata bundle (member only)
  async fetchEncryptedMetadata(
    nodeId: string,
  ): Promise<import('./e2ee/metadata').EncryptedMetadataBundle> {
    return this.request(`/api/nodes/${nodeId}/metadata/encrypted`);
  }

  // Bulk-update a node's encrypted metadata (admin/moderator only).
  // Values are base64 NMK blobs from NodeMetadataKey.encryptToBase64().
  async updateEncryptedMetadata(
    nodeId: string,
    update: {
      node?: { encrypted_name?: string; encrypted_description?: string; encrypted_settings?: string };
      channels?: Record<string, string>;
      categories?: Record<string, string>;
    },
  ): Promise<{ success: boolean }> {
    return this.request(`/api/nodes/${nodeId}/metadata/encrypted`, {
      method: 'PUT',
      body: JSON.stringify(update),
    });
  }

  // ── Moderation endpoints ──

  // Set slow mode for a channel
  async setSlowMode(channelId: string, seconds: number, _token: string): Promise<any> {
    return this.request(`/channels/${channelId}/slow-mode`, {
      method: 'PUT',
      body: JSON.stringify({ seconds }),
    });
  }

  // Get slow mode for a channel
  async getSlowMode(channelId: string, _token: string): Promise<{ slow_mode_seconds: number }> {
    return this.request(`/channels/${channelId}/slow-mode`);
  }

  // Auto-mod word filtering is client-side (see retention.ts) and distributed via
  // the NMK-encrypted node settings blob — the relay has no auto-mod endpoints.

  // ── Bot API v2 ──

  async listBots(nodeId: string): Promise<any[]> {
    const result = await this.request<any>(`/api/nodes/${nodeId}/bots`);
    if (result && Array.isArray(result.bots)) return result.bots;
    if (Array.isArray(result)) return result;
    return [];
  }

  async installBot(nodeId: string, manifest: any, webhookUrl: string): Promise<any> {
    return this.request<any>(`/api/nodes/${nodeId}/bots`, {
      method: 'POST',
      body: JSON.stringify({ manifest, webhook_url: webhookUrl }),
    });
  }

  async uninstallBot(nodeId: string, botId: string): Promise<any> {
    return this.request<any>(`/api/nodes/${nodeId}/bots/${encodeURIComponent(botId)}`, {
      method: 'DELETE',
    });
  }

  async getBotCommands(nodeId: string, botId: string): Promise<any[]> {
    const result = await this.request<any>(`/api/nodes/${nodeId}/bots/${encodeURIComponent(botId)}/commands`);
    if (result && Array.isArray(result.commands)) return result.commands;
    if (Array.isArray(result)) return result;
    return [];
  }

  async invokeCommand(nodeId: string, botId: string, command: string, params: Record<string, any>, channelId: string): Promise<any> {
    return this.request<any>(`/api/nodes/${nodeId}/bots/${encodeURIComponent(botId)}/invoke`, {
      method: 'POST',
      body: JSON.stringify({ command, params, channel_id: channelId }),
    });
  }

  // ── Custom Emoji endpoints ──

  // List custom emojis for a node
  async listCustomEmojis(nodeId: string): Promise<CustomEmoji[]> {
    const result = await this.request<any>(`/nodes/${nodeId}/emojis`);
    if (result && Array.isArray(result.emojis)) return result.emojis;
    if (Array.isArray(result)) return result;
    return [];
  }

  // Upload a custom emoji
  async uploadEmoji(nodeId: string, name: string, file: File, token: string): Promise<CustomEmoji> {
    const formData = new FormData();
    formData.append('image', file);
    formData.append('name', name);
    const authToken = token || this._token;
    const headers: Record<string, string> = {};
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
    const response = await fetch(`${this.baseUrl}/nodes/${nodeId}/emojis`, {
      method: 'POST',
      headers,
      body: formData,
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || `HTTP ${response.status}`);
    }
    return response.json();
  }

  // Delete a custom emoji
  async deleteEmoji(nodeId: string, emojiId: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(`/nodes/${nodeId}/emojis/${emojiId}`, {
      method: 'DELETE',
    });
  }

  // Get emoji image URL by content hash
  getEmojiUrl(contentHash: string): string {
    return `${this.baseUrl}/api/emojis/${contentHash}`;
  }

  // ── Batch API endpoints ──

  // Get full node overview (info + channels + members + roles) in a single call
  async getNodeOverview(nodeId: string): Promise<NodeOverviewResponse> {
    return this.request<NodeOverviewResponse>(`/api/nodes/${nodeId}/overview`);
  }

  // Get all members with roles and online status in a single call
  async getMembersBatch(nodeId: string): Promise<BatchMembersResponse> {
    return this.request<BatchMembersResponse>(`/api/nodes/${nodeId}/members/batch`);
  }

  // Get all channels with permissions and unread counts in a single call
  async getChannelsBatch(nodeId: string): Promise<BatchChannelsResponse> {
    return this.request<BatchChannelsResponse>(`/api/nodes/${nodeId}/channels/batch`);
  }

  // Batch reorder channels (position + category changes)
  async reorderChannels(nodeId: string, channels: { id: string; position: number; category_id: string | null }[]): Promise<void> {
    await this.request<void>(`/nodes/${nodeId}/channels/reorder`, {
      method: 'PUT',
      body: JSON.stringify({ channels }),
    });
  }

  // Test server connectivity
  async testConnection(): Promise<boolean> {
    try {
      await this.health();
      return true;
    } catch {
      return false;
    }
  }
}

// Compact invite encoding — base64url of host:port to obscure relay address
function encodeRelayHost(host: string): string {
  return btoa(host).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeRelayHost(encoded: string): string {
  let b64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return atob(b64);
}

export function generateInviteLink(host: string, inviteCode: string): string {
  return `accord://${encodeRelayHost(host)}/${inviteCode}`;
}

/** Infer http vs https from host:port — ports 443/8443 get https, others http */
function inferScheme(host: string): 'https' | 'http' {
  const portMatch = host.match(/:(\d+)$/);
  if (portMatch) {
    const port = parseInt(portMatch[1], 10);
    if (port === 443) return 'https';
    // 8443 could be either — probeServerUrl will try both
    // Default to http for local/dev servers
    return 'http';
  } else {
    // No explicit port — assume https for production domains
    return 'https';
  }
  return 'http';
}

/**
 * Normalize a user-provided server address into a full URL.
 * If the input already has a protocol prefix (http:// or https://), respect it.
 * Otherwise, infer the scheme from the port.
 */
export function normalizeServerUrl(input: string): string {
  const trimmed = input.trim().replace(/\/+$/, '');
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }
  return `${inferScheme(trimmed)}://${trimmed}`;
}

/**
 * Try to connect to a server URL. Attempts the given URL first,
 * then falls back to the opposite scheme if it fails.
 * Returns the working URL or throws with a descriptive error.
 */
export async function probeServerUrl(url: string): Promise<string> {
  const tryHealth = async (candidate: string): Promise<boolean> => {
    try {
      const resp = await fetch(`${candidate}/health`, {
        signal: AbortSignal.timeout(8000),
      });
      if (resp.ok) {
        const data = await resp.json();
        return data && (data.status === 'healthy' || data.status === 'ok');
      }
      return false;
    } catch {
      return false;
    }
  };

  // Try the URL as given
  if (await tryHealth(url)) return url;

  // Try the opposite scheme as fallback
  let fallback: string;
  if (url.startsWith('https://')) {
    fallback = url.replace(/^https:\/\//, 'http://');
  } else if (url.startsWith('http://')) {
    fallback = url.replace(/^http:\/\//, 'https://');
  } else {
    throw new Error(`Connection failed: Could not reach server at ${url}`);
  }

  if (await tryHealth(fallback)) return fallback;

  // Both failed — try to give a helpful error
  try {
    await fetch(`${url}/health`, { signal: AbortSignal.timeout(5000) });
  } catch (e: any) {
    const msg = e?.message || '';
    if (msg.includes('Failed to fetch') || msg.includes('NetworkError')) {
      throw new Error(`Connection refused — server at ${url} is not reachable. Check the address and ensure the server is running.`);
    }
    if (msg.includes('SSL') || msg.includes('certificate') || msg.includes('ERR_CERT')) {
      throw new Error(`SSL/TLS error connecting to ${url}. The server may be using plain HTTP — try http:// instead of https://.`);
    }
    throw new Error(`Connection failed: ${msg}`);
  }
  throw new Error(`Server at ${url} is not responding as an Accord relay. Check the address.`);
}

// Invite link parser
// Supports:
//   accord://BASE64HOST/CODE (new compact format)
//   accord://host:port/invite/CODE (legacy)
//   https://host:port/invite/CODE
export function parseInviteLink(input: string): ParsedInviteLink | null {
  const trimmed = input.trim();

  // Try new compact format: accord://BASE64/CODE
  const compactMatch = trimmed.match(/^accord:\/\/([A-Za-z0-9_+/=-]+)\/([^/?#]+)$/);
  if (compactMatch) {
    try {
      const relayHost = decodeRelayHost(compactMatch[1]);
      // Verify it looks like host:port (contains a dot or colon)
      if (relayHost.includes('.') || relayHost.includes(':')) {
        return {
          relayHost,
          relayUrl: normalizeServerUrl(relayHost),
          inviteCode: compactMatch[2],
        };
      }
    } catch { /* not valid base64, try other formats */ }
  }

  // Try legacy accord:// scheme: accord://host:port/invite/CODE
  const accordMatch = trimmed.match(/^accord:\/\/([^/]+)\/invite\/([^/?#]+)/);
  if (accordMatch) {
    const relayHost = accordMatch[1];
    return {
      relayHost,
      relayUrl: normalizeServerUrl(relayHost),
      inviteCode: accordMatch[2],
    };
  }

  // Try http(s):// scheme
  const httpMatch = trimmed.match(/^(https?):\/\/([^/]+)\/invite\/([^/?#]+)/);
  if (httpMatch) {
    const scheme = httpMatch[1];
    const relayHost = httpMatch[2];
    return {
      relayHost,
      relayUrl: `${scheme}://${relayHost}`,
      inviteCode: httpMatch[3],
    };
  }

  return null;
}

// Multi-relay credential helpers
export function getRelayKeys(relayHost: string): { publicKey: string; privateKeyJwk: string } | null {
  const raw = localStorage.getItem(`accord_keys_${relayHost}`);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

export function storeRelayKeys(relayHost: string, publicKey: string, privateKeyJwk: string) {
  localStorage.setItem(`accord_keys_${relayHost}`, JSON.stringify({ publicKey, privateKeyJwk }));
}

export function getRelayToken(relayHost: string): string | null {
  return localStorage.getItem(`accord_token_${relayHost}`);
}

export function storeRelayToken(relayHost: string, token: string) {
  localStorage.setItem(`accord_token_${relayHost}`, token);
}

export function getRelayUserId(relayHost: string): string | null {
  return localStorage.getItem(`accord_user_${relayHost}`);
}

export function storeRelayUserId(relayHost: string, userId: string) {
  localStorage.setItem(`accord_user_${relayHost}`, userId);
}

// Default API instance
export const api = new AccordApi();

// Export functions for backward compatibility
export const createNode = api.createNode.bind(api);
export const getNodeInfo = api.getNodeInfo.bind(api);
export const joinNode = api.joinNode.bind(api);
export const getUserNodes = api.getUserNodes.bind(api);
export const getNodeChannels = api.getNodeChannels.bind(api);
export const getNodeMembers = api.getNodeMembers.bind(api);
export const getChannelMessages = api.getChannelMessages.bind(api);
export const createChannel = api.createChannel.bind(api);
export const deleteChannel = api.deleteChannel.bind(api);
export const createInvite = api.createInvite.bind(api);
export const kickMember = api.kickMember.bind(api);
export const getUserProfile = api.getUserProfile.bind(api);
export const updateProfile = api.updateProfile.bind(api);
export const joinNodeByInvite = api.joinNodeByInvite.bind(api);
export const getNodeInvites = api.getNodeInvites.bind(api);
export const createInviteWithOptions = api.createInviteWithOptions.bind(api);
export const revokeInvite = api.revokeInvite.bind(api);
export const testConnection = api.testConnection.bind(api);
export const searchMessages = api.searchMessages.bind(api);
export const getMessageThread = api.getMessageThread.bind(api);
export const createDmChannel = api.createDmChannel.bind(api);
export const getDmChannels = api.getDmChannels.bind(api);
export const getNodeAuditLog = api.getNodeAuditLog.bind(api);
