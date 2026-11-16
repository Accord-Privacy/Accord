// TypeScript types matching the server models

// User and authentication types
export interface User {
  id: string;
  /** SHA-256 hash of public key (hex). Primary relay-level identifier. */
  public_key_hash: string;
  public_key: string;
  created_at: number;
  /** Display name is a client-side / per-Node concept, not stored at relay level */
  display_name?: string;
}

export interface AuthToken {
  token: string;
  user_id: string;
  expires_at: number;
}

export interface RegisterRequest {
  public_key: string;
  password: string;
}

export interface RegisterResponse {
  user_id: string;
  message: string;
  device_id?: string;
}

export interface AuthRequest {
  public_key: string;
  password: string;
}

export interface AuthResponse {
  token: string;
  user_id: string;
  expires_at: number;
  device_id?: string;
}

/** Device identity from Tauri hardware fingerprint */
export interface DeviceIdentity {
  device_fingerprint_hash: string;
  device_public_key: string;
  device_label: string;
}

/** V2 registration request — username + password + device */
export interface RegisterRequestV2 {
  username: string;
  password: string;
  display_name?: string;
  device_fingerprint_hash?: string;
  device_public_key?: string;
  device_label?: string;
}

/** V2 auth request — username + password */
export interface AuthRequestV2 {
  username: string;
  password: string;
  device_fingerprint_hash?: string;
}

// Node types
export interface Node {
  id: string;
  name: string;
  owner_id: string;
  description?: string;
  created_at: number;
  icon_hash?: string;
  /** `invite` (default) or `request` (SPEC-01 REQ-29). */
  join_policy?: 'invite' | 'request';
}

export interface NodeMember {
  node_id: string;
  user_id: string;
  public_key_hash: string;
  role: 'admin' | 'moderator' | 'member';
  joined_at: number;
  profile?: UserProfile;
  status?: PresenceStatus;
}

export interface NodeInfo {
  id: string;
  name: string;
  owner_id: string;
  description?: string;
  created_at: number;
  members: NodeMember[];
  channel_count: number;
}

export interface CreateNodeRequest {
  name: string;
  description?: string;
}

// Channel types
export interface Channel {
  id: string;
  name: string;
  node_id: string;
  members: string[];
  created_at: number;
  channel_type?: 'text' | 'voice' | 'category' | number;
  parent_id?: string | null;
  position?: number;
  topic?: string | null;
  nsfw?: boolean;
  icon_emoji?: string | null;
  unread_count?: number;
}

// Role types
export interface Role {
  id: string;
  node_id: string;
  name: string;
  color?: string | null;
  position: number;
  permissions: number;
  hoist: boolean;
  mentionable: boolean;
  created_at: number;
}

export interface CreateChannelRequest {
  name: string;
  channel_type: string;
}

// WebSocket message types
export type WsMessageType =
  | { CreateNode: { name: string; description?: string } }
  // SPEC-01 REQ-21: the optional invite and node-scoped device fingerprint
  // (64 lowercase hex characters) follow the rules of POST /nodes/:id/join.
  | { JoinNode: { node_id: string; invite_code?: string; device_fingerprint_hash?: string } }
  | { LeaveNode: { node_id: string } }
  | { GetNodeInfo: { node_id: string } }
  | { JoinChannel: { channel_id: string } }
  | { LeaveChannel: { channel_id: string } }
  | { CreateChannel: { node_id: string; name: string } }
  | { DirectMessage: { to_user: string; encrypted_data: string } }
  | { ChannelMessage: { channel_id: string; encrypted_data: string; reply_to?: string; expires_at?: number; gate_users?: string[]; gate_roles?: string[]; gate_ttl_secs?: number; attachment_ids?: string[] } }
  | { EditMessage: { message_id: string; encrypted_data: string } }
  | { DeleteMessage: { message_id: string } }
  | { AddReaction: { message_id: string; emoji: string } }
  | { RemoveReaction: { message_id: string; emoji: string } }
  | { PinMessage: { message_id: string } }
  | { UnpinMessage: { message_id: string } }
  | { TypingStart: { channel_id: string } }
  | { StoreSenderKey: { channel_id: string; to_user_id: string; payload: string } }
  | 'GetPendingSenderKeys'
  | { AckSenderKeys: { ids: string[] } }
  | { JoinVoiceChannel: { channel_id: string } }
  | { LeaveVoiceChannel: { channel_id: string } }
  | { GetVoiceParticipants: { channel_id: string } }
  | { VoiceSpeakingState: { channel_id: string; user_id: string; speaking: boolean } }
  // SPEC-03 §6.1: a call message for exactly one target (REQ-1); the ssrc
  // and generation fields are always 0.
  | { VoiceKeyExchange: { channel_id: string; wrapped_key: string; target_user_id: string; sender_ssrc: number; key_generation: number } }
  // SPEC-03 §6.1: one AMF1 audio frame, standard base64 (the name is historical).
  | { SrtpVoicePacket: { channel_id: string; packet_data: string } }
  // SPEC-03 §6.12.1: screen sharing on a relay that lists `screen/1`.
  | { ScreenShareStart: { channel_id: string } }
  | { ScreenShareStop: { channel_id: string } }
  | { ScreenWatch: { channel_id: string; sharer_id: string; watch: boolean } }
  | { ScreenKeyframeRequest: { channel_id: string; sharer_id: string } }
  | 'Ping'
  | 'Pong';

export interface WsMessage {
  message_type: WsMessageType;
  message_id: string;
  timestamp: number;
}

// Incoming WebSocket message types
export interface WsIncomingMessage {
  type: string;
  [key: string]: any;
}

// Read receipt WebSocket message
export interface ReadReceiptMessage {
  type: 'read_receipt';
  user_id: string;
  channel_id: string;
  message_id: string;
  timestamp: number;
}

// Read receipt for display (who read up to which message)
export interface ReadReceipt {
  user_id: string;
  message_id: string;
  timestamp: number;
}

export interface PresenceUpdateMessage {
  type: 'presence_update';
  user_id: string;
  status: PresenceStatus;
}

// User profile types
export interface UserProfile {
  user_id: string;
  display_name: string;
  avatar_url?: string;
  bio?: string;
  status: PresenceStatus;
  custom_status?: string;
  banner_color?: string;
  banner_url?: string;
  activity?: string;
  updated_at: number;
}

export enum PresenceStatus {
  Online = 'online',
  Idle = 'idle',
  DND = 'dnd',
  Offline = 'offline',
}

export interface UpdateProfileRequest {
  display_name?: string;
  avatar_url?: string;
  bio?: string;
  status?: PresenceStatus;
  custom_status?: string;
  banner_color?: string;
  banner_url?: string;
}

// Error response
export interface ErrorResponse {
  error: string;
  code: number;
  /** Machine-readable reason (SPEC-01 §6.4), on routes that send one. */
  reason?: string;
  /** Seconds to wait, with `rate_limited`. */
  retry_after?: number;
}

// Health check response
export interface HealthResponse {
  status: string;
  version: string;
  uptime_seconds: number;
  /** Relay capability tokens (SPEC-01 §6.8); test membership only. */
  features?: string[];
  /** When the relay began enforcing admission, Unix seconds (SPEC-01 REQ-42). */
  admission_since?: number | null;
  /** Present when `features` holds `attachments/2` (SPEC-02 §6.4.6). */
  attachment_limits?: AttachmentLimits;
}

/** An invite as `GET /nodes/:id/invites` lists it (SPEC-01 §6.2). */
export interface InviteListItem {
  id: string;
  invite_code: string;
  created_at: number;
  max_uses: number | null;
  current_uses: number;
  expires_at: number | null;
  created_by?: string;
}

// App state types
export interface AppState {
  isAuthenticated: boolean;
  user?: User;
  token?: string;
  nodes: NodeInfo[];
  activeNode?: string;
  activeChannel?: string;
  messages: Message[];
  isConnected: boolean;
}

/**
 * Delivery status of an own message (SPEC-02 REQ-49, §8.1). `sent` only after
 * the relay's echo or a history item pairs with the pending send;
 * `unconfirmed` when nothing paired within 30 s.
 */
export type MessageDeliveryStatus = 'sending' | 'unconfirmed' | 'sent' | 'delivered' | 'read' | 'failed';

/** Why an own message failed, and what the user can do about it (SPEC-02 §8.1). */
export interface MessageFailure {
  /** Text shown next to the message. */
  readonly text: string;
  /** Whether Retry is offered; Delete is always offered. */
  readonly retryable: boolean;
}

/**
 * A placeholder shown instead of a body (SPEC-02 §8.2): the plaintext could
 * not be shown, and nothing else of it is rendered.
 */
export type MessagePlaceholder =
  | 'invalid_format'
  | 'newer_version'
  | 'wrong_conversation'
  | 'edited_unverified'
  | 'other_session';

export interface Message {
  id: string;
  author: string;
  content: string;
  time?: string;
  channel_id?: string;
  timestamp: number;
  edited_at?: number;
  pinned_at?: number;
  pinned_by?: string;
  /** Disappearing messages: expiry as unix seconds. Undefined = keep forever. */
  expires_at?: number;
  /** Read-gated expiry: message only starts its expiry timer once required readers have seen it. */
  read_gated?: boolean;
  /** Read-gated duration (seconds): how long after THIS device reads it before its copy vanishes. */
  gate_ttl_secs?: number;
  /** Local per-recipient expiry: unix seconds at which THIS device drops its copy (read time + duration). */
  local_expires_at?: number;
  isEncrypted?: boolean;
  e2eeType?: 'double-ratchet' | 'symmetric' | 'sender-keys' | 'none';
  reactions?: MessageReaction[];
  reply_to?: string;
  replied_message?: RepliedMessage;
  reply_count?: number;
  // No `files`, `attachments` or `attachment_ids`: attachment state lives only
  // in the attachment store, which only the decode function writes (SPEC-02
  // REQ-51). Leaving the field out lets the type checker enforce that.
  sender_public_key_hash?: string;
  sender_id?: string;
  display_name?: string;
  /** Delivery status for own messages (SPEC-02 REQ-49). */
  _status?: MessageDeliveryStatus;
  /**
   * The id of this message's pending-send record (`attachments/send.ts`).
   * Retry and Delete act on that record, which alone holds what a resend
   * needs; a `Message` never holds a payload to resend (SPEC-02 REQ-48).
   */
  _pendingId?: string;
  /** Status text while sending, for example "Waiting for connection". */
  _statusText?: string;
  /** Set when `_status` is `failed`. */
  _failure?: MessageFailure;
  /** Set when the decode function showed a placeholder instead of a body. */
  _placeholder?: MessagePlaceholder;
  /** An untrusted envelope carried descriptors that were ignored (SPEC-02 §8.2). */
  _attachmentsIgnored?: boolean;
  /**
   * How many attachments the message carries: decoded ones (whose state is in
   * the attachment store) or, for an own pending send, staged ones. A count
   * only; descriptors never live on a `Message` (REQ-51).
   */
  _attachmentCount?: number;
  /**
   * The opaque `ref` of the attachment-store entry this message's own decode
   * produced. Views show attachments only when the entry under the message's
   * key still has this ref, its sender and its count (`attachments/render.ts`),
   * so a later decode under the same id never lends its attachments to this
   * message, and this message never shows an entry it did not produce.
   */
  _attachmentRef?: number;
}

export interface RepliedMessage {
  id: string;
  sender_id: string;
  sender_public_key_hash: string;
  encrypted_payload: string;
  created_at: number;
  content?: string; // Decrypted content for display
}

export interface MessageReaction {
  emoji: string;
  count: number;
  users: string[];
  created_at: number;
}

export interface MessageReactionsResponse {
  reactions: MessageReaction[];
}

// Message pagination response from server
export interface MessagePaginationResponse {
  messages: Message[];
  has_more: boolean;
  next_cursor?: string;
}

// File types

/**
 * One row of the legacy file list, `GET /channels/{id}/files` (SPEC-02
 * §6.4.5). Legacy files were encrypted under a key the relay can compute, so
 * every field is relay-controlled: the name may be empty (shown as "(name
 * unavailable)") and the uploader is only what the relay reports (REQ-27).
 */
export interface LegacyFileRow {
  id: string;
  channel_id: string;
  uploader_id: string;
  /** Base64 of the legacy-encrypted name, or "" when the relay has none. */
  encrypted_filename: string;
  file_size_bytes: number;
  created_at: number;
}

/** What `POST /channels/{id}/attachments` answers with 201 (SPEC-02 §6.4.1). */
export interface UploadAttachmentResponse {
  attachment_id: string;
  blob_size: number;
  /** Lowercase hex SHA-256 computed by the relay. */
  blob_sha256: string;
  /** Unix seconds. */
  pending_expires_at: number;
}

/** The relay's attachment limits from `GET /health` (SPEC-02 §6.4.6); interface guidance only. */
export interface AttachmentLimits {
  max_blob_bytes: number;
  max_per_message: number;
}

export interface UploadProgress {
  loaded: number;
  total: number;
  percentage: number;
}

// Voice channel types
export interface VoiceState {
  channelId: string | null;
  isConnected: boolean;
  isMuted: boolean;
  isDeafened: boolean;
  outputVolume: number;
  connectedUsers: VoiceUser[];
  isCapturingAudio: boolean;
  vadThreshold: number;
  isSpeaking: boolean;
}

export interface VoiceUser {
  userId: string;
  displayName: string;
  isSpeaking: boolean;
  audioLevel: number;
  isMuted?: boolean;
}

// Voice WebSocket messages (incoming from server)
export interface VoiceJoinMessage {
  type: 'voice_join';
  channel_id: string;
  user_id: string;
  public_key_hash?: string;
}

export interface VoiceLeaveMessage {
  type: 'voice_leave';
  channel_id: string;
  user_id: string;
}

export interface VoiceSpeakingMessage {
  type: 'voice_speaking';
  channel_id: string;
  user_id: string;
  speaking: boolean;
}

// Reaction WebSocket messages
export interface ReactionAddMessage {
  type: 'reaction_add';
  message_id: string;
  channel_id: string;
  user_id: string;
  emoji: string;
  reactions: MessageReaction[];
  timestamp: number;
}

export interface ReactionRemoveMessage {
  type: 'reaction_remove';
  message_id: string;
  channel_id: string;
  user_id: string;
  emoji: string;
  reactions: MessageReaction[];
  timestamp: number;
}

// Message pinning WebSocket messages
export interface MessagePinMessage {
  type: 'message_pin';
  message_id: string;
  channel_id: string;
  pinned_by: string;
  timestamp: number;
}

export interface MessageUnpinMessage {
  type: 'message_unpin';
  message_id: string;
  channel_id: string;
  unpinned_by: string;
  timestamp: number;
}

// Typing indicator messages
export interface TypingStartMessage {
  type: 'typing_start';
  channel_id: string;
  user_id: string;
  public_key_hash: string;
  timestamp: number;
}

export interface TypingUser {
  user_id: string;
  displayName: string;
  startedAt: number;
}

// Direct Message types
export interface DmChannel {
  id: string;
  user1_id: string;
  user2_id: string;
  created_at: number;
}

export interface DmChannelWithInfo {
  id: string;
  user1_id: string;
  user2_id: string;
  other_user: User;
  other_user_profile: UserProfile;
  last_message?: Message;
  unread_count: number;
  created_at: number;
}

export interface DmChannelsResponse {
  dm_channels: DmChannelWithInfo[];
}

// Invite link types
export interface ParsedInviteLink {
  relayHost: string;   // e.g. "192.168.1.100:8080"
  relayUrl: string;    // e.g. "http://192.168.1.100:8080"
  inviteCode: string;  // e.g. "abc123def"
}

// Bot API v2 types

export interface BotCommandParam {
  name: string;
  type: string;
  required: boolean;
  default?: any;
  description?: string;
}

export interface BotCommand {
  name: string;
  description: string;
  params: BotCommandParam[];
}

export interface BotManifest {
  bot_id: string;
  name: string;
  icon?: string;
  description?: string;
  commands: BotCommand[];
}

export interface InstalledBot {
  bot_id: string;
  name: string;
  icon?: string;
  description?: string;
  commands: BotCommand[];
  installed_at: number;
  invocation_count: number;
}

export interface ActionButton {
  label: string;
  command?: string;
  params?: Record<string, any>;
  params_prompt?: string[];
}

export interface FieldEntry {
  name: string;
  value: string;
  inline?: boolean;
}

export interface EmbedSection {
  type: 'text' | 'grid' | 'image' | 'actions' | 'divider' | 'fields' | 'progress' | 'code' | 'input';
  // text
  text?: string;
  // grid
  columns?: string[];
  rows?: string[][];
  // image
  url?: string;
  alt?: string;
  // actions
  buttons?: ActionButton[];
  // fields
  fields?: FieldEntry[];
  // progress
  label?: string;
  value?: number;
  max?: number;
  // code
  code?: string;
  language?: string;
  // input
  name?: string;
  placeholder?: string;
  command?: string;
}

export interface BotResponseContent {
  type: 'text' | 'embed';
  text?: string;
  title?: string;
  sections?: EmbedSection[];
}

export interface BotResponseMessage {
  type: 'bot_response';
  bot_id: string;
  bot_name: string;
  bot_icon?: string;
  invocation_id: string;
  channel_id: string;
  content: BotResponseContent;
  timestamp: number;
  signature_valid?: boolean;
}

// Batch API response types

export interface BatchMemberEntry {
  user_id: string;
  display_name: string;
  avatar_url?: string;
  roles: Array<{ id: string; name: string; color?: string | null; position: number; hoist?: boolean }>;
  online: boolean;
  status: string;
  custom_status?: string;
  joined_at: number;
  node_role: 'admin' | 'moderator' | 'member';
}

export interface BatchChannelEntry {
  id: string;
  name: string;
  node_id: string;
  category_id?: string | null;
  category_name?: string | null;
  position?: number;
  permission_overrides?: Array<{ role_id: string; allow: number; deny: number }>;
  unread_count?: number;
  channel_type?: string;
}

export interface BatchMembersResponse {
  members: BatchMemberEntry[];
  roles: Role[];
}

export interface BatchChannelsResponse {
  channels: BatchChannelEntry[];
}

export interface NodeOverviewResponse {
  node: NodeInfo;
  channels: BatchChannelEntry[];
  members: BatchMemberEntry[];
  roles: Role[];
}

// Custom emoji types
export interface CustomEmoji {
  id: string;
  node_id: string;
  name: string;
  uploaded_by: string;
  content_hash: string;
  created_at: string;
}

// Audit log types
export interface AuditLogEntry {
  id: string;
  node_id: string;
  actor_id: string;
  actor_public_key_hash: string;
  action: string;
  target_type: string;
  target_id?: string;
  details?: string;
  created_at: number;
}

export interface AuditLogResponse {
  entries: AuditLogEntry[];
  has_more: boolean;
  next_cursor?: string;
}
