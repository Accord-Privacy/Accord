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
  Message,
  NodeMember,
  User,
  ErrorResponse,
  HealthResponse,
  FileMetadata,
} from './types';

// Configuration
const DEFAULT_BASE_URL = 'http://localhost:8080';

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
  async getChannelMessages(channelId: string, token: string, limit: number = 50, before?: string): Promise<Message[]> {
    let url = `/channels/${channelId}/messages?limit=${limit}&token=${encodeURIComponent(token)}`;
    if (before) {
      url += `&before=${encodeURIComponent(before)}`;
    }
    return this.request<Message[]>(url);
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
export const testConnection = api.testConnection.bind(api);