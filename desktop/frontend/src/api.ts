// API client module for REST endpoints

import type { ParsedInviteLink } from './types';
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
  FileMetadata,
  UserProfile,
  UpdateProfileRequest,
  MessageReaction,
  MessageReactionsResponse,
  DmChannel,
  DmChannelsResponse,
  AuditLogResponse,
} from './types';

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

export class AccordApi {
  private baseUrl: string;
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
    const url = `${this.baseUrl}${endpoint}`;
    
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    });

    // On 401, try to refresh the token and retry once
    if (response.status === 401 && !_isRetry && this._tokenRefresher) {
      const newToken = await this.refreshToken();
      if (newToken) {
        // Replace token in the endpoint URL and retry
        const refreshedEndpoint = endpoint.replace(/([?&])token=[^&]*/, `$1token=${encodeURIComponent(newToken)}`);
        return this.request<T>(refreshedEndpoint, options, true);
      }
    }

    const data = await response.json();

    if (!response.ok) {
      const error = data as ErrorResponse;
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return data as T;
  }

  // Health check
  async health(): Promise<HealthResponse> {
    return this.request<HealthResponse>('/health');
  }

  // User registration — keypair-only, no username
  async register(publicKey: string, password: string): Promise<RegisterResponse> {
    return this.request<RegisterResponse>('/register', {
      method: 'POST',
      body: JSON.stringify({
        public_key: publicKey,
        password: password,
      }),
    });
  }

  // User authentication — by public_key + password
  async login(publicKey: string, password: string): Promise<AuthResponse> {
    return this.request<AuthResponse>('/auth', {
      method: 'POST',
      body: JSON.stringify({
        public_key: publicKey,
        password: password,
      }),
    });
  }

  // Create a new Node
  async createNode(name: string, token: string, description?: string): Promise<NodeInfo> {
    const request: CreateNodeRequest = {
      name,
      description,
    };

    return this.request<NodeInfo>(`/nodes?token=${encodeURIComponent(token)}`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Get Node information
  async getNodeInfo(nodeId: string, token?: string): Promise<NodeInfo> {
    const url = token 
      ? `/nodes/${nodeId}?token=${encodeURIComponent(token)}`
      : `/nodes/${nodeId}`;
    
    return this.request<NodeInfo>(url);
  }

  // Join a Node
  async joinNode(nodeId: string, token: string): Promise<{ status: string; node_id: string }> {
    return this.request<{ status: string; node_id: string }>(
      `/nodes/${nodeId}/join?token=${encodeURIComponent(token)}`,
      {
        method: 'POST',
      }
    );
  }

  // Leave a Node
  async leaveNode(nodeId: string, token: string): Promise<{ status: string; node_id: string }> {
    return this.request<{ status: string; node_id: string }>(
      `/nodes/${nodeId}/leave?token=${encodeURIComponent(token)}`,
      {
        method: 'POST',
      }
    );
  }

  // Get user's nodes
  async getUserNodes(token: string): Promise<Node[]> {
    return this.request<Node[]>(`/nodes?token=${encodeURIComponent(token)}`);
  }

  // Get Node's channels
  async getNodeChannels(nodeId: string, token: string): Promise<Channel[]> {
    return this.request<Channel[]>(`/nodes/${nodeId}/channels?token=${encodeURIComponent(token)}`);
  }

  // Get Node's members
  async getNodeMembers(nodeId: string, token: string): Promise<Array<NodeMember & { user: User }>> {
    const result = await this.request<any>(`/nodes/${nodeId}/members?token=${encodeURIComponent(token)}`);
    // Server returns {members: [...]} — unwrap if needed
    if (result && result.members && Array.isArray(result.members)) return result.members;
    if (Array.isArray(result)) return result;
    return [];
  }

  // Get channel message history
  async getChannelMessages(channelId: string, token: string, limit: number = 50, before?: string): Promise<MessagePaginationResponse> {
    let url = `/channels/${channelId}/messages?limit=${limit}&token=${encodeURIComponent(token)}`;
    if (before) {
      url += `&before=${encodeURIComponent(before)}`;
    }
    return this.request<MessagePaginationResponse>(url);
  }

  // Upload file to channel
  async uploadFile(
    channelId: string, 
    file: File, 
    token: string, 
    encryptedFilename?: string,
    onProgress?: (loaded: number, total: number) => void
  ): Promise<{ file_id: string; message: string }> {
    const formData = new FormData();
    formData.append('file', file);
    if (encryptedFilename) {
      formData.append('encrypted_filename', encryptedFilename);
    }

    const xhr = new XMLHttpRequest();
    
    return new Promise((resolve, reject) => {
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable && onProgress) {
          onProgress(e.loaded, e.total);
        }
      });

      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            const response = JSON.parse(xhr.responseText);
            resolve(response);
          } catch (e) {
            reject(new Error('Invalid JSON response'));
          }
        } else {
          try {
            const error = JSON.parse(xhr.responseText);
            reject(new Error(error.error || `HTTP ${xhr.status}`));
          } catch (e) {
            reject(new Error(`Upload failed with status ${xhr.status}`));
          }
        }
      });

      xhr.addEventListener('error', () => {
        reject(new Error('Upload failed'));
      });

      xhr.open('POST', `${this.baseUrl}/channels/${channelId}/files?token=${encodeURIComponent(token)}`);
      xhr.send(formData);
    });
  }

  // Download file by ID
  async downloadFile(fileId: string, token: string): Promise<ArrayBuffer> {
    const response = await fetch(`${this.baseUrl}/files/${fileId}?token=${encodeURIComponent(token)}`);
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `HTTP ${response.status}`);
    }
    
    return response.arrayBuffer();
  }

  // List files in channel
  async getChannelFiles(channelId: string, token: string): Promise<FileMetadata[]> {
    return this.request<FileMetadata[]>(`/channels/${channelId}/files?token=${encodeURIComponent(token)}`);
  }

  // Delete file by ID  
  async deleteFile(fileId: string, token: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/files/${fileId}?token=${encodeURIComponent(token)}`, {
      method: 'DELETE',
    });
  }

  // Create a new channel in a node
  async createChannel(nodeId: string, name: string, channelType: string, token: string): Promise<Channel> {
    const request = {
      name,
      channel_type: channelType,
    };

    return this.request<Channel>(`/nodes/${nodeId}/channels?token=${encodeURIComponent(token)}`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Delete a channel
  async deleteChannel(channelId: string, token: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/channels/${channelId}?token=${encodeURIComponent(token)}`, {
      method: 'DELETE',
    });
  }

  // Generate an invite for a node
  async createInvite(nodeId: string, token: string): Promise<{ invite_code: string; expires_at?: number }> {
    return this.request<{ invite_code: string; expires_at?: number }>(
      `/nodes/${nodeId}/invites?token=${encodeURIComponent(token)}`,
      {
        method: 'POST',
      }
    );
  }

  // Kick a member from a node
  async kickMember(nodeId: string, userId: string, token: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(
      `/nodes/${nodeId}/members/${userId}?token=${encodeURIComponent(token)}`,
      {
        method: 'DELETE',
      }
    );
  }

  // Get user profile
  async getUserProfile(userId: string, token?: string): Promise<UserProfile> {
    const url = token 
      ? `/users/${userId}/profile?token=${encodeURIComponent(token)}`
      : `/users/${userId}/profile`;
    
    return this.request<UserProfile>(url);
  }

  // Update own profile
  async updateProfile(profile: UpdateProfileRequest, token: string): Promise<UserProfile> {
    return this.request<UserProfile>(`/users/me/profile?token=${encodeURIComponent(token)}`, {
      method: 'PATCH',
      body: JSON.stringify(profile),
    });
  }

  // Join a Node via invite code
  async joinNodeByInvite(inviteCode: string, token: string): Promise<NodeInfo> {
    return this.request<NodeInfo>(`/invites/${inviteCode}/join?token=${encodeURIComponent(token)}`, {
      method: 'POST',
    });
  }

  // Get invites for a node (admin/mod only)
  async getNodeInvites(nodeId: string, token: string): Promise<Array<{ code: string; created_at: number; max_uses?: number; expires_at?: number; uses: number }>> {
    const result = await this.request<any>(
      `/nodes/${nodeId}/invites?token=${encodeURIComponent(token)}`
    );
    // Server returns {invites: [...]} — unwrap if needed
    if (result && result.invites && Array.isArray(result.invites)) return result.invites;
    if (Array.isArray(result)) return result;
    return [];
  }

  // Create an invite with options
  async createInviteWithOptions(nodeId: string, token: string, maxUses?: number, expiresHours?: number): Promise<{ invite_code: string; expires_at?: number }> {
    const body: any = {};
    if (maxUses !== undefined) body.max_uses = maxUses;
    if (expiresHours !== undefined) body.expires_hours = expiresHours;

    return this.request<{ invite_code: string; expires_at?: number }>(
      `/nodes/${nodeId}/invites?token=${encodeURIComponent(token)}`,
      {
        method: 'POST',
        body: Object.keys(body).length > 0 ? JSON.stringify(body) : undefined,
      }
    );
  }

  // Revoke an invite
  async revokeInvite(nodeId: string, inviteCode: string, token: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(
      `/nodes/${nodeId}/invites/${inviteCode}?token=${encodeURIComponent(token)}`,
      {
        method: 'DELETE',
      }
    );
  }

  // Search messages in a node
  async searchMessages(nodeId: string, query: string, token: string, channelId?: string): Promise<{ 
    results: Array<{
      message_id: string;
      channel_id: string; 
      channel_name: string;
      sender_id: string;
      sender_public_key_hash: string;
      timestamp: number;
    }>;
    note?: string;
  }> {
    let url = `/nodes/${nodeId}/search?q=${encodeURIComponent(query)}&token=${encodeURIComponent(token)}`;
    if (channelId) {
      url += `&channel=${encodeURIComponent(channelId)}`;
    }
    return this.request<{ 
      results: Array<{
        message_id: string;
        channel_id: string; 
        channel_name: string;
        sender_id: string;
        sender_public_key_hash: string;
        timestamp: number;
      }>;
      note?: string;
    }>(url);
  }

  // Edit a message
  async editMessage(
    messageId: string,
    userId: string,
    encryptedData: string
  ): Promise<{ success: boolean }> {
    return this.request<{ success: boolean }>(`/messages/${messageId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        user_id: userId,
        encrypted_data: encryptedData,
      }),
    });
  }

  // Delete a message
  async deleteMessage(messageId: string, token: string): Promise<{ success: boolean }> {
    return this.request<{ success: boolean }>(
      `/messages/${messageId}?token=${encodeURIComponent(token)}`,
      {
        method: 'DELETE',
      }
    );
  }

  // Get message thread (replies to a message)
  async getMessageThread(messageId: string, token: string): Promise<MessagePaginationResponse> {
    return this.request<MessagePaginationResponse>(
      `/messages/${messageId}/thread?token=${encodeURIComponent(token)}`
    );
  }

  // Get message reactions
  async getMessageReactions(messageId: string, token: string): Promise<MessageReactionsResponse> {
    return this.request<MessageReactionsResponse>(
      `/messages/${messageId}/reactions?token=${encodeURIComponent(token)}`
    );
  }

  // Add reaction to message
  async addReaction(messageId: string, emoji: string, token: string): Promise<{ success: boolean; reactions: MessageReaction[] }> {
    return this.request<{ success: boolean; reactions: MessageReaction[] }>(
      `/messages/${messageId}/reactions/${encodeURIComponent(emoji)}?token=${encodeURIComponent(token)}`,
      {
        method: 'PUT',
      }
    );
  }

  // Remove reaction from message
  async removeReaction(messageId: string, emoji: string, token: string): Promise<{ success: boolean; reactions: MessageReaction[] }> {
    return this.request<{ success: boolean; reactions: MessageReaction[] }>(
      `/messages/${messageId}/reactions/${encodeURIComponent(emoji)}?token=${encodeURIComponent(token)}`,
      {
        method: 'DELETE',
      }
    );
  }

  // Pin a message (admin/mod only)
  async pinMessage(messageId: string, token: string): Promise<{ success: boolean; message: string }> {
    return this.request<{ success: boolean; message: string }>(
      `/messages/${messageId}/pin?token=${encodeURIComponent(token)}`,
      {
        method: 'PUT',
      }
    );
  }

  // Unpin a message (admin/mod only)
  async unpinMessage(messageId: string, token: string): Promise<{ success: boolean; message: string }> {
    return this.request<{ success: boolean; message: string }>(
      `/messages/${messageId}/pin?token=${encodeURIComponent(token)}`,
      {
        method: 'DELETE',
      }
    );
  }

  // Get pinned messages for a channel
  async getPinnedMessages(channelId: string, token: string): Promise<{ pinned_messages: any[] }> {
    return this.request<{ pinned_messages: any[] }>(
      `/channels/${channelId}/pins?token=${encodeURIComponent(token)}`
    );
  }

  // Direct Message operations

  // Create or get DM channel with a user
  async createDmChannel(targetUserId: string, token: string): Promise<DmChannel> {
    return this.request<DmChannel>(
      `/dm/${targetUserId}?token=${encodeURIComponent(token)}`,
      {
        method: 'POST',
      }
    );
  }

  // Get user's DM channels list
  async getDmChannels(token: string): Promise<DmChannelsResponse> {
    return this.request<DmChannelsResponse>(
      `/dm?token=${encodeURIComponent(token)}`
    );
  }

  // Get Node audit log (admin/mod only)
  async getNodeAuditLog(
    nodeId: string,
    token: string,
    limit: number = 50,
    beforeId?: string
  ): Promise<AuditLogResponse> {
    const params = new URLSearchParams({
      token,
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
  async getRoles(nodeId: string, token: string): Promise<any[]> {
    const result = await this.request<any>(`/nodes/${nodeId}/roles?token=${encodeURIComponent(token)}`);
    if (result && Array.isArray(result.roles)) return result.roles;
    if (Array.isArray(result)) return result;
    return [];
  }

  // Import Discord template
  async importDiscordTemplate(nodeId: string, templateCode: string, token: string): Promise<any> {
    return this.request<any>(`/nodes/${nodeId}/import-discord-template?token=${encodeURIComponent(token)}`, {
      method: 'POST',
      body: JSON.stringify({ template_code: templateCode }),
    });
  }

  // Upload node icon
  async uploadNodeIcon(nodeId: string, file: File, token: string): Promise<{ status: string; icon_hash: string }> {
    const formData = new FormData();
    formData.append('icon', file);
    const response = await fetch(`${this.baseUrl}/nodes/${nodeId}/icon?token=${encodeURIComponent(token)}`, {
      method: 'PUT',
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
    const response = await fetch(`${this.baseUrl}/users/me/avatar?token=${encodeURIComponent(token)}`, {
      method: 'PUT',
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

// Invite link parser
// Supports:
//   accord://BASE64HOST/CODE (new compact format)
//   accord://host:port/invite/CODE (legacy)
//   https://host:port/invite/CODE
export function parseInviteLink(input: string): ParsedInviteLink | null {
  const trimmed = input.trim();

  // Try new compact format: accord://BASE64/CODE
  const compactMatch = trimmed.match(/^accord:\/\/([A-Za-z0-9_-]+)\/([^/?#]+)$/);
  if (compactMatch) {
    try {
      const relayHost = decodeRelayHost(compactMatch[1]);
      // Verify it looks like host:port (contains a dot or colon)
      if (relayHost.includes('.') || relayHost.includes(':')) {
        return {
          relayHost,
          relayUrl: `http://${relayHost}`,
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
      relayUrl: `http://${relayHost}`,
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
