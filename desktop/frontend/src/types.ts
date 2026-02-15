// TypeScript types matching the server models

// User and authentication types
export interface User {
  id: string;
  username: string;
  public_key: string;
  created_at: number;
}

export interface AuthToken {
  token: string;
  user_id: string;
  expires_at: number;
}

export interface RegisterRequest {
  username: string;
  publicKey: string;
}

export interface RegisterResponse {
  user_id: string;
  message: string;
}

export interface AuthRequest {
  username: string;
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
  role: 'admin' | 'moderator' | 'member';
  joined_at: number;
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
  | { ChannelMessage: { channel_id: string; encrypted_data: string } }
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
  isEncrypted?: boolean;
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