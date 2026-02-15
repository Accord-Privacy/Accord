// WebSocket client with reconnection logic and event emitter pattern

import { WsMessage, WsMessageType, WsIncomingMessage } from './types';

// Event types for the WebSocket client
export interface WsEvents {
  connected: () => void;
  disconnected: () => void;
  message: (message: WsIncomingMessage) => void;
  error: (error: Error) => void;
  node_created: (data: any) => void;
  node_joined: (data: any) => void;
  node_left: (data: any) => void;
  node_info: (data: any) => void;
  channel_created: (data: any) => void;
  direct_message: (data: any) => void;
  channel_message: (data: any) => void;
  message_edit: (data: any) => void;
  message_delete: (data: any) => void;
  presence_update: (data: any) => void;
  pong: (data: any) => void;
  voice_join: (data: any) => void;
  voice_leave: (data: any) => void;
  voice_packet: (data: any) => void;
  voice_speaking: (data: any) => void;
  reaction_add: (data: any) => void;
  reaction_remove: (data: any) => void;
}

type EventListener<T = any> = (data: T) => void;

export class AccordWebSocket {
  private ws: WebSocket | null = null;
  private token: string;
  private baseUrl: string;
  private listeners: Map<string, Set<EventListener>> = new Map();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000; // Start with 1 second
  private maxReconnectDelay = 30000; // Max 30 seconds
  private reconnectTimeout: number | null = null;
  private isConnected = false;
  private isDestroyed = false;
  private pingInterval: number | null = null;

  constructor(token: string, baseUrl = 'ws://localhost:8080') {
    this.token = token;
    this.baseUrl = baseUrl.replace(/^http/, 'ws');
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

  // Connection management
  connect(): void {
    if (this.isDestroyed) return;
    
    if (this.ws && this.ws.readyState === WebSocket.CONNECTING) {
      return; // Already connecting
    }

    const wsUrl = `${this.baseUrl}/ws?token=${encodeURIComponent(this.token)}`;
    
    try {
      this.ws = new WebSocket(wsUrl);
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
      console.log('WebSocket connected');
      this.isConnected = true;
      this.reconnectAttempts = 0;
      this.reconnectDelay = 1000;
      
      // Start ping interval
      this.startPingInterval();
      
      this.emit('connected');
    };

    this.ws.onmessage = (event) => {
      try {
        const message: WsIncomingMessage = JSON.parse(event.data);
        console.log('Received WebSocket message:', message);
        
        // Emit general message event
        this.emit('message', message);
        
        // Emit specific event based on message type
        if (message.type) {
          this.emit(message.type as keyof WsEvents, message);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
        this.emit('error', new Error('Invalid message format'));
      }
    };

    this.ws.onclose = (event) => {
      console.log('WebSocket disconnected:', event.code, event.reason);
      this.isConnected = false;
      this.stopPingInterval();
      
      this.emit('disconnected');
      
      if (!this.isDestroyed && event.code !== 1000) {
        // Not a normal closure, attempt reconnect
        this.scheduleReconnect();
      }
    };

    this.ws.onerror = (event) => {
      console.error('WebSocket error:', event);
      this.emit('error', new Error('WebSocket connection error'));
    };
  }

  private scheduleReconnect(): void {
    if (this.isDestroyed || this.reconnectTimeout) return;
    
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      this.emit('error', new Error('Max reconnection attempts reached'));
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(
      this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1),
      this.maxReconnectDelay
    );

    console.log(`Attempting reconnect ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`);

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
  private sendMessage(messageType: WsMessageType): void {
    if (!this.isConnected || !this.ws) {
      console.warn('WebSocket not connected, cannot send message');
      return;
    }

    const message: WsMessage = {
      message_type: messageType,
      message_id: this.generateId(),
      timestamp: Math.floor(Date.now() / 1000),
    };

    try {
      this.ws.send(JSON.stringify(message));
    } catch (error) {
      console.error('Error sending WebSocket message:', error);
      this.emit('error', new Error('Failed to send message'));
    }
  }

  // Generic send method for custom messages
  send(message: string): void {
    if (!this.isConnected || !this.ws) {
      console.warn('WebSocket not connected, cannot send message');
      return;
    }

    try {
      this.ws.send(message);
    } catch (error) {
      console.error('Error sending WebSocket message:', error);
      this.emit('error', new Error('Failed to send message'));
    }
  }

  // Node operations
  createNode(name: string, description?: string): void {
    this.sendMessage({ CreateNode: { name, description } });
  }

  joinNode(nodeId: string): void {
    this.sendMessage({ JoinNode: { node_id: nodeId } });
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
  sendDirectMessage(toUser: string, encryptedData: string): void {
    this.sendMessage({ DirectMessage: { to_user: toUser, encrypted_data: encryptedData } });
  }

  sendChannelMessage(channelId: string, encryptedData: string): void {
    this.sendMessage({ ChannelMessage: { channel_id: channelId, encrypted_data: encryptedData } });
  }

  sendEditMessage(messageId: string, encryptedData: string): void {
    this.sendMessage({ EditMessage: { message_id: messageId, encrypted_data: encryptedData } });
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

  // Note: encryptedData should be base64-encoded encrypted content
  // The App component handles encryption before calling this method

  // Ping/Pong
  ping(): void {
    this.sendMessage('Ping');
  }

  pong(): void {
    this.sendMessage('Pong');
  }

  // Utility methods
  private generateId(): string {
    return Math.random().toString(36).substr(2, 9);
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
    
    this.listeners.clear();
  }
}