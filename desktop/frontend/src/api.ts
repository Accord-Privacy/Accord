// API client module for REST endpoints

import {
  RegisterRequest,
  RegisterResponse,
  AuthRequest,
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

// Configuration - check for environment variable or use localhost as default
// For cross-machine connectivity, set VITE_ACCORD_SERVER_URL in .env or environment
const DEFAULT_BASE_URL = (typeof window !== 'undefined' && (window as any).__ACCORD_SERVER_URL__) 
  || import.meta.env.VITE_ACCORD_SERVER_URL 
  || 'http://localhost:8080';

export class AccordApi {
  private baseUrl: string;

  constructor(baseUrl: string = DEFAULT_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    });

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

  // User registration
  async register(username: string, publicKey: string): Promise<RegisterResponse> {
    const request: RegisterRequest = {
      username,
      publicKey,
    };

    return this.request<RegisterResponse>('/register', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // User authentication
  async login(username: string, password: string): Promise<AuthResponse> {
    const request: AuthRequest = {
      username,
      password,
    };

    return this.request<AuthResponse>('/auth', {
      method: 'POST',
      body: JSON.stringify(request),
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
    return this.request<Array<NodeMember & { user: User }>>(`/nodes/${nodeId}/members?token=${encodeURIComponent(token)}`);
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
    return this.request<Array<{ code: string; created_at: number; max_uses?: number; expires_at?: number; uses: number }>>(
      `/nodes/${nodeId}/invites?token=${encodeURIComponent(token)}`
    );
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
      sender_username: string;
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
        sender_username: string;
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

// Default API instance
export const api = new AccordApi();

// Export functions for backward compatibility
export const register = api.register.bind(api);
export const login = api.login.bind(api);
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