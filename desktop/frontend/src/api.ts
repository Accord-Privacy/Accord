// API client module for REST endpoints

import {
  RegisterRequest,
  RegisterResponse,
  AuthRequest,
  AuthResponse,
  CreateNodeRequest,
  NodeInfo,
  ErrorResponse,
  HealthResponse,
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
export const testConnection = api.testConnection.bind(api);