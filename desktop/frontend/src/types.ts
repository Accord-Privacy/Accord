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
}

export interface AuthRequest {
  public_key: string;
  password: string;
}

export interface AuthResponse {
  token: string;
  user_id: string;
  expires_at: number;
}

// Node types
export interface Node {
  id: string;
  name: string;
  owner_id: string;
  description?: string;
  created_at: number;
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
  channel_type?: 'text' | 'voice';
}

export interface CreateChannelRequest {
  name: string;
  channel_type: string;
}

// WebSocket message types
export type WsMessageType =
  | { CreateNode: { name: string; description?: string } }
  | { JoinNode: { node_id: string } }
  | { LeaveNode: { node_id: string } }
  | { GetNodeInfo: { node_id: string } }
  | { JoinChannel: { channel_id: string } }
  | { LeaveChannel: { channel_id: string } }
  | { CreateChannel: { node_id: string; name: string } }
  | { DirectMessage: { to_user: string; encrypted_data: string } }
  | { ChannelMessage: { channel_id: string; encrypted_data: string; reply_to?: string } }
  | { EditMessage: { message_id: string; encrypted_data: string } }
  | { DeleteMessage: { message_id: string } }
  | { AddReaction: { message_id: string; emoji: string } }
  | { RemoveReaction: { message_id: string; emoji: string } }
  | { PinMessage: { message_id: string } }
  | { UnpinMessage: { message_id: string } }
  | { TypingStart: { channel_id: string } }
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
}

// Error response
export interface ErrorResponse {
  error: string;
  code: number;
}

// Health check response
export interface HealthResponse {
  status: string;
  version: string;
  uptime_seconds: number;
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
  isEncrypted?: boolean;
  reactions?: MessageReaction[];
  reply_to?: string;
  replied_message?: RepliedMessage;
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
export interface FileMetadata {
  id: string;
  encrypted_filename: string;
  file_size_bytes: number;
  created_at: number;
  uploader_id: string;
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

export interface VoicePacketMessage {
  type: 'voice_packet';
  channel_id: string;
  user_id: string;
  data: string; // base64 encoded audio data
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
