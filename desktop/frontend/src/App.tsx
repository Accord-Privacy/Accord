import React, { useState, useEffect, useCallback, useRef } from "react";
import { api, parseInviteLink, storeRelayToken, storeRelayUserId, getRelayToken, getRelayUserId } from "./api";
import { AccordWebSocket, ConnectionInfo } from "./ws";
import { AppState, Message, WsIncomingMessage, Node, Channel, NodeMember, User, TypingUser, TypingStartMessage, DmChannelWithInfo, ParsedInviteLink } from "./types";
import { 
  generateKeyPair, 
  exportPublicKey, 
  saveKeyToStorage, 
  loadKeyFromStorage, 
  getChannelKey, 
  encryptMessage, 
  decryptMessage, 
  clearChannelKeyCache,
  isCryptoSupported 
} from "./crypto";
import { storeToken, getToken, clearToken } from "./tokenStorage";
import { FileUploadButton, FileList, FileDropZone, FileAttachment } from "./FileManager";
import { VoiceChat } from "./VoiceChat";
import { SearchOverlay } from "./SearchOverlay";
// Removed unused imports for NodeDiscovery and NodeSettings components
import { notificationManager, NotificationPreferences } from "./notifications";
import { NotificationSettings } from "./NotificationSettings";
import { Settings } from "./Settings";

// Helper: compute SHA-256 hex hash of a string (for public key -> public_key_hash)
async function sha256Hex(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper: truncate a public key hash to a short fingerprint for display
function fingerprint(publicKeyHash: string): string {
  if (!publicKeyHash || publicKeyHash.length < 16) return publicKeyHash || 'unknown';
  return publicKeyHash.substring(0, 8) + '...' + publicKeyHash.substring(publicKeyHash.length - 8);
}

function App() {
  // Server connection state
  const [serverUrl, setServerUrl] = useState(() => 
    localStorage.getItem('accord_server_url') || 'http://localhost:8080'
  );
  const [_serverConnected, setServerConnected] = useState(false);
  const [showServerScreen, setShowServerScreen] = useState(false);
  const [serverConnecting, setServerConnecting] = useState(false);
  const [serverVersion, setServerVersion] = useState("");

  // Welcome / Invite flow state
  const [showWelcomeScreen, setShowWelcomeScreen] = useState(() => !localStorage.getItem('accord_server_url'));
  const [welcomeMode, setWelcomeMode] = useState<'choose' | 'invite' | 'admin'>('choose');
  const [inviteLinkInput, setInviteLinkInput] = useState("");
  const [parsedInvite, setParsedInvite] = useState<ParsedInviteLink | null>(null);
  const [inviteError, setInviteError] = useState("");
  const [inviteConnecting, setInviteConnecting] = useState(false);
  const [inviteRelayVersion, setInviteRelayVersion] = useState("");
  const [inviteNeedsRegister, setInviteNeedsRegister] = useState(false);
  const [invitePassword, setInvitePassword] = useState("");
  const [inviteJoining, setInviteJoining] = useState(false);

  // Authentication state
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoginMode, setIsLoginMode] = useState(true);
  const [password, setPassword] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [authError, setAuthError] = useState("");
  const [showKeyBackup, setShowKeyBackup] = useState(false);
  const [publicKeyHash, setPublicKeyHash] = useState("");

  // Encryption state
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);
  const [encryptionEnabled] = useState(isCryptoSupported());

  // App state
  const [appState, setAppState] = useState<AppState>({
    isAuthenticated: false,
    nodes: [],
    messages: [],
    isConnected: false,
  });

  const [message, setMessage] = useState("");
  const [activeChannel, setActiveChannel] = useState("# general");
  const [activeServer, setActiveServer] = useState(0);
  const [serverAvailable, setServerAvailable] = useState(false);
  const [ws, setWs] = useState<AccordWebSocket | null>(null);
  const [connectionInfo, setConnectionInfo] = useState<ConnectionInfo>({ status: 'disconnected', reconnectAttempt: 0, maxReconnectAttempts: 20 });

  // Reply state
  const [replyingTo, setReplyingTo] = useState<Message | null>(null);

  // Real data state
  const [nodes, setNodes] = useState<Node[]>([]);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [members, setMembers] = useState<Array<NodeMember & { user: User }>>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedChannelId, setSelectedChannelId] = useState<string | null>(null);

  // Message pagination state
  const [isLoadingOlderMessages, setIsLoadingOlderMessages] = useState(false);
  const [hasMoreMessages, setHasMoreMessages] = useState(true);
  const [oldestMessageCursor, setOldestMessageCursor] = useState<string | undefined>(undefined);
  const messagesContainerRef = useRef<HTMLDivElement>(null);

  // Message editing state
  const [editingMessageId, setEditingMessageId] = useState<string | null>(null);
  const [editingContent, setEditingContent] = useState("");
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<string | null>(null);

  const handleStartEdit = (messageId: string, content: string) => {
    setEditingMessageId(messageId);
    setEditingContent(content);
  };

  // Role-based permission state
  const [userRoles, setUserRoles] = useState<Record<string, 'admin' | 'moderator' | 'member'>>({});
  const [showCreateChannelForm, setShowCreateChannelForm] = useState(false);
  const [newChannelName, setNewChannelName] = useState("");
  const [newChannelType, setNewChannelType] = useState("text");
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [generatedInvite, setGeneratedInvite] = useState<string>("");
  const [error, setError] = useState<string>("");

  // Voice state
  const [voiceChannelId, setVoiceChannelId] = useState<string | null>(null);
  const [voiceChannelName, setVoiceChannelName] = useState<string>("");

  // Pinned messages state
  const [showPinnedPanel, setShowPinnedPanel] = useState(false);
  const [pinnedMessages, setPinnedMessages] = useState<Message[]>([]);

  // Node discovery state
  // Removed unused node dialog state variables

  // Reaction state
  const [showEmojiPicker, setShowEmojiPicker] = useState<string | null>(null);
  const [hoveredMessageId, setHoveredMessageId] = useState<string | null>(null);

  // Common emojis for the picker
  const COMMON_EMOJIS = ['👍', '❤️', '😂', '🎉', '🤔', '👀', '🔥', '💯', '✅', '❌'];

  // Notification state
  const [notificationPreferences, setNotificationPreferences] = useState<NotificationPreferences>(
    notificationManager.getPreferences()
  );
  const [showNotificationSettings, setShowNotificationSettings] = useState(false);
  const [forceUpdate, setForceUpdate] = useState(0); // Used to trigger re-renders when unread counts change

  // Search state
  const [showSearchOverlay, setShowSearchOverlay] = useState(false);

  // Direct Messages state
  const [dmChannels, setDmChannels] = useState<DmChannelWithInfo[]>([]);
  const [selectedDmChannel, setSelectedDmChannel] = useState<DmChannelWithInfo | null>(null);
  const [showDmChannelCreate, setShowDmChannelCreate] = useState(false);

  // Node creation state
  const [showCreateNodeModal, setShowCreateNodeModal] = useState(false);
  const [newNodeName, setNewNodeName] = useState("");
  const [newNodeDescription, setNewNodeDescription] = useState("");
  const [creatingNode, setCreatingNode] = useState(false);

  // Settings state
  const [showSettings, setShowSettings] = useState(false);

  // Display name prompt state
  const [showDisplayNamePrompt, setShowDisplayNamePrompt] = useState(false);
  const [displayNameInput, setDisplayNameInput] = useState("");
  const [displayNameSaving, setDisplayNameSaving] = useState(false);

  // Keyboard shortcuts help state
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false);

  // Presence state
  const [presenceMap, setPresenceMap] = useState<Map<string, import('./types').PresenceStatus>>(new Map());
  const [lastMessageTimes, setLastMessageTimes] = useState<Map<string, number>>(new Map());

  // Context menu state
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; userId: string; publicKeyHash: string; displayName: string; bio?: string; user?: User } | null>(null);

  // Typing indicators state
  const [typingUsers, setTypingUsers] = useState<Map<string, TypingUser[]>>(new Map());
  const [typingTimeouts, setTypingTimeouts] = useState<Map<string, number>>(new Map());
  const [lastTypingSent, setLastTypingSent] = useState<number>(0);
  const typingIndicatorsEnabled = useState(() => 
    localStorage.getItem('accord-typing-indicators') !== 'false'
  )[0];

  // Permission checking utilities
  const getCurrentUserRole = useCallback((nodeId: string) => {
    return userRoles[nodeId] || 'member';
  }, [userRoles]);

  const hasPermission = useCallback((nodeId: string, permission: 'CreateChannel' | 'DeleteChannel' | 'ManageMembers' | 'KickMembers' | 'ManageInvites' | 'ManageNode') => {
    const role = getCurrentUserRole(nodeId);
    
    switch (role) {
      case 'admin':
        return true; // Admin has all permissions
      case 'moderator':
        return ['KickMembers', 'ManageInvites'].includes(permission);
      case 'member':
        return false; // Members have no admin permissions
      default:
        return false;
    }
  }, [getCurrentUserRole]);

  const getRoleBadge = (role: 'admin' | 'moderator' | 'member') => {
    switch (role) {
      case 'admin': return '👑';
      case 'moderator': return '🛡️';
      default: return '';
    }
  };

  const handleApiError = (error: any) => {
    if (error.message && error.message.includes('403')) {
      setError("You don't have permission to perform this action");
    } else {
      setError(error.message || "An error occurred");
    }
    setTimeout(() => setError(""), 5000); // Clear error after 5 seconds
  };

  // Typing indicator functions
  const sendTypingIndicator = useCallback((channelId: string) => {
    if (!typingIndicatorsEnabled || !ws || !channelId) return;
    
    const now = Date.now();
    const timeSinceLastTyping = now - lastTypingSent;
    
    // Throttle typing events to once per 3 seconds
    if (timeSinceLastTyping >= 3000) {
      ws.sendTypingStart(channelId);
      setLastTypingSent(now);
    }
  }, [ws, typingIndicatorsEnabled, lastTypingSent]);

  const formatTypingUsers = useCallback((channelId: string): string => {
    const tusers = typingUsers.get(channelId) || [];
    // Filter out current user
    const currentUserId = localStorage.getItem('accord_user_id');
    const filtered = tusers.filter(u => u.user_id !== currentUserId);
    
    if (filtered.length === 0) return '';
    
    // Resolve display names from members list
    const getName = (tu: TypingUser) => {
      const member = members.find(m => m.user_id === tu.user_id);
      if (member?.user?.display_name) return member.user.display_name;
      if (member?.profile?.display_name) return member.profile.display_name;
      return tu.displayName;
    };
    
    if (filtered.length === 1) return `${getName(filtered[0])} is typing`;
    if (filtered.length === 2) return `${getName(filtered[0])} and ${getName(filtered[1])} are typing`;
    return 'Several people are typing';
  }, [typingUsers, members]);

  // Check server availability on mount
  useEffect(() => {
    const checkServer = async () => {
      const available = await api.testConnection();
      setServerAvailable(available);
      if (!available) {
      }
    };
    checkServer();
  }, []);

  // WebSocket event handlers
  const setupWebSocketHandlers = useCallback((socket: AccordWebSocket) => {
    socket.on('connected', () => {
      setAppState(prev => ({ ...prev, isConnected: true }));
      setConnectionInfo({ status: 'connected', reconnectAttempt: 0, maxReconnectAttempts: 20 });
    });

    socket.on('disconnected', () => {
      setAppState(prev => ({ ...prev, isConnected: false }));
    });

    socket.on('connection_status', (info: ConnectionInfo) => {
      setConnectionInfo(info);
    });

    socket.on('auth_error', () => {
      // Auth token expired — force re-login
      handleLogout();
    });

    socket.on('message', (_msg: WsIncomingMessage) => {
    });

    socket.on('channel_message', async (data) => {
      // Handle incoming channel messages
      let content = data.encrypted_data;
      let isEncrypted = false;

      // Try to decrypt the message if we have encryption enabled and keys
      if (encryptionEnabled && keyPair && data.channel_id) {
        try {
          const channelKey = await getChannelKey(keyPair.privateKey, data.channel_id);
          content = await decryptMessage(channelKey, data.encrypted_data);
          isEncrypted = true;
        } catch (error) {
          console.warn('Failed to decrypt message, showing encrypted data:', error);
          // Keep the encrypted data if decryption fails
        }
      }

      const newMessage: Message = {
        id: data.message_id || Math.random().toString(),
        author: data.from || "Unknown",
        content: content,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        timestamp: data.timestamp * 1000,
        channel_id: data.channel_id,
        isEncrypted: isEncrypted,
        reply_to: data.reply_to,
        replied_message: data.replied_message ? {
          id: data.replied_message.id,
          sender_id: data.replied_message.sender_id,
          sender_public_key_hash: data.replied_message.sender_public_key_hash || '',
          encrypted_payload: data.replied_message.encrypted_payload,
          created_at: data.replied_message.created_at,
          content: data.replied_message.content,
        } : undefined,
      };

      // Track last message time for presence heuristic
      if (data.from) {
        setLastMessageTimes(prev => {
          const newMap = new Map(prev);
          newMap.set(data.from, Date.now());
          return newMap;
        });
      }

      // Check if this is a DM message
      const isDm = data.is_dm || dmChannels.some(dm => dm.id === data.channel_id);
      
      if (isDm) {
        // Handle DM message - refresh DM channels to update last message
        loadDmChannels();
        
        // Add to notifications for DM
        const dmChannel = dmChannels.find(dm => dm.id === data.channel_id);
        if (dmChannel) {
          notificationManager.addMessage(`dm-${dmChannel.id}`, data.channel_id, newMessage);
          setForceUpdate(prev => prev + 1);
        }
      } else {
        // Find which node this channel belongs to for regular messages
        const nodeId = nodes.find(node => 
          channels.some(channel => channel.id === data.channel_id && channel.node_id === node.id)
        )?.id;

        // Add message to notification system
        if (nodeId) {
          notificationManager.addMessage(nodeId, data.channel_id, newMessage);
          setForceUpdate(prev => prev + 1); // Trigger re-render for unread badges
        }
      }

      // Check if user is scrolled to the bottom before adding new message
      const container = messagesContainerRef.current;
      const wasAtBottom = container ? 
        (container.scrollHeight - container.scrollTop - container.clientHeight < 50) : true;

      setAppState(prev => ({
        ...prev,
        messages: [...prev.messages, newMessage]
      }));

      // Auto-scroll to bottom if user was at the bottom
      if (wasAtBottom && container) {
        setTimeout(() => {
          container.scrollTop = container.scrollHeight;
        }, 0);
      }
    });

    socket.on('node_info', (data) => {
      // Update node info when received
      if (data.data) {
        setAppState(prev => ({
          ...prev,
          nodes: prev.nodes.map(node => 
            node.id === data.data.id ? data.data : node
          )
        }));
      }
    });

    // Handle message edit events
    socket.on('message_edit', async (data) => {
      
      try {
        // Try to decrypt the new content if we have encryption enabled
        let content = data.encrypted_data;
        if (encryptionEnabled && keyPair) {
          const channelKey = await getChannelKey(keyPair.privateKey, data.channel_id);
          content = await decryptMessage(channelKey, data.encrypted_data);
        }

        setAppState(prev => ({
          ...prev,
          messages: prev.messages.map(msg => 
            msg.id === data.message_id
              ? { 
                  ...msg, 
                  content, 
                  edited_at: data.edited_at,
                  isEncrypted: encryptionEnabled 
                }
              : msg
          ),
        }));

        // Message editing functionality removed
      } catch (error) {
        console.warn('Failed to decrypt edited message:', error);
        // Update message anyway, just keep encrypted data
        setAppState(prev => ({
          ...prev,
          messages: prev.messages.map(msg => 
            msg.id === data.message_id
              ? { 
                  ...msg, 
                  content: data.encrypted_data, 
                  edited_at: data.edited_at,
                  isEncrypted: true 
                }
              : msg
          ),
        }));
      }
    });

    // Handle message delete events
    socket.on('message_delete', (data) => {
      
      setAppState(prev => ({
        ...prev,
        messages: prev.messages.filter(msg => msg.id !== data.message_id),
      }));

      // Message editing/deletion functionality removed
    });

    // Handle reaction add events
    socket.on('reaction_add', (data) => {
      
      setAppState(prev => ({
        ...prev,
        messages: prev.messages.map(msg => 
          msg.id === data.message_id
            ? { ...msg, reactions: data.reactions }
            : msg
        ),
      }));
    });

    // Handle reaction remove events
    socket.on('reaction_remove', (data) => {
      
      setAppState(prev => ({
        ...prev,
        messages: prev.messages.map(msg => 
          msg.id === data.message_id
            ? { ...msg, reactions: data.reactions }
            : msg
        ),
      }));
    });

    // Handle message pin events
    socket.on('message_pin', (data) => {
      
      setAppState(prev => ({
        ...prev,
        messages: prev.messages.map(msg => 
          msg.id === data.message_id
            ? { ...msg, pinned_at: data.timestamp, pinned_by: data.pinned_by }
            : msg
        ),
      }));
    });

    // Handle message unpin events
    socket.on('message_unpin', (data) => {
      
      setAppState(prev => ({
        ...prev,
        messages: prev.messages.map(msg => 
          msg.id === data.message_id
            ? { ...msg, pinned_at: undefined, pinned_by: undefined }
            : msg
        ),
      }));
    });

    // Handle typing start events
    socket.on('typing_start', (data: TypingStartMessage) => {
      
      const typingUser: TypingUser = {
        user_id: data.user_id,
        displayName: data.public_key_hash ? fingerprint(data.public_key_hash) : data.user_id.substring(0, 8),
        startedAt: Date.now(),
      };

      // Update typing users for the channel
      setTypingUsers(prev => {
        const newMap = new Map(prev);
        const channelTyping = newMap.get(data.channel_id) || [];
        
        // Remove any existing entry for this user
        const filteredTyping = channelTyping.filter(user => user.user_id !== data.user_id);
        
        // Add the new typing user
        newMap.set(data.channel_id, [...filteredTyping, typingUser]);
        
        return newMap;
      });

      // Set timeout to auto-remove this user after 5 seconds
      const timeoutKey = `${data.channel_id}_${data.user_id}`;
      setTypingTimeouts(prev => {
        const newMap = new Map(prev);
        
        // Clear existing timeout if any
        const existingTimeout = newMap.get(timeoutKey);
        if (existingTimeout) {
          clearTimeout(existingTimeout);
        }
        
        // Set new timeout
        const timeout = window.setTimeout(() => {
          setTypingUsers(prevTyping => {
            const newTypingMap = new Map(prevTyping);
            const channelTyping = newTypingMap.get(data.channel_id) || [];
            const filteredTyping = channelTyping.filter(user => user.user_id !== data.user_id);
            
            if (filteredTyping.length > 0) {
              newTypingMap.set(data.channel_id, filteredTyping);
            } else {
              newTypingMap.delete(data.channel_id);
            }
            
            return newTypingMap;
          });
          
          // Clean up timeout
          setTypingTimeouts(prevTimeouts => {
            const newTimeoutsMap = new Map(prevTimeouts);
            newTimeoutsMap.delete(timeoutKey);
            return newTimeoutsMap;
          });
        }, 5000);
        
        newMap.set(timeoutKey, timeout);
        return newMap;
      });
    });

    // Handle presence updates
    socket.on('presence_update', (data: any) => {
      if (data.user_id && data.status) {
        setPresenceMap(prev => {
          const newMap = new Map(prev);
          newMap.set(data.user_id, data.status);
          return newMap;
        });
      }
    });

    socket.on('error', (error: Error) => {
      console.error('WebSocket error:', error);
    });
  }, [encryptionEnabled, keyPair]);

  // Cleanup typing timeouts on unmount
  useEffect(() => {
    return () => {
      typingTimeouts.forEach(timeout => clearTimeout(timeout));
    };
  }, [typingTimeouts]);

  // Load user's nodes
  const loadNodes = useCallback(async () => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const userNodes = await api.getUserNodes(appState.token);
      setNodes(userNodes);
      
      // Auto-select first node if none selected
      if (userNodes.length > 0 && !selectedNodeId) {
        setSelectedNodeId(userNodes[0].id);
      }
    } catch (error) {
      console.error('Failed to load nodes:', error);
    }
  }, [appState.token, serverAvailable, selectedNodeId]);

  // Load channels for selected node
  const loadChannels = useCallback(async (nodeId: string) => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const nodeChannels = await api.getNodeChannels(nodeId, appState.token);
      setChannels(nodeChannels);
      
      // Auto-select first channel if none selected
      if (nodeChannels.length > 0 && !selectedChannelId) {
        setSelectedChannelId(nodeChannels[0].id);
      }
    } catch (error) {
      console.error('Failed to load channels:', error);
      handleApiError(error);
      setChannels([]);
    }
  }, [appState.token, serverAvailable, selectedChannelId]);

  // Load members for selected node
  const loadMembers = useCallback(async (nodeId: string) => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const nodeMembers = await api.getNodeMembers(nodeId, appState.token);
      setMembers(nodeMembers);
      
      // Find current user's role in this node
      const currentUserId = localStorage.getItem('accord_user_id');
      if (currentUserId) {
        const currentUserMember = nodeMembers.find(member => member.user_id === currentUserId);
        if (currentUserMember) {
          setUserRoles(prev => ({
            ...prev,
            [nodeId]: currentUserMember.role
          }));
        }
      }
    } catch (error) {
      console.error('Failed to load members:', error);
      handleApiError(error);
      setMembers([]);
    }
  }, [appState.token, serverAvailable]);

  // Load message history for selected channel (initial load)
  const loadMessages = useCallback(async (channelId: string) => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const response = await api.getChannelMessages(channelId, appState.token);
      
      // Format messages for display
      const formattedMessages = response.messages.map(msg => ({
        ...msg,
        time: msg.time || new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }));
      
      // Sort messages by timestamp (oldest first for display)
      formattedMessages.sort((a, b) => a.timestamp - b.timestamp);
      
      setAppState(prev => ({
        ...prev,
        messages: formattedMessages,
      }));
      
      // Update pagination state
      setHasMoreMessages(response.has_more);
      setOldestMessageCursor(response.next_cursor);
      
      // Auto-scroll to bottom on initial load
      setTimeout(() => {
        const container = messagesContainerRef.current;
        if (container) {
          container.scrollTop = container.scrollHeight;
        }
      }, 0);

      // Mark channel as read after loading messages
      markChannelAsReadAfterLoad(channelId, formattedMessages);
      
    } catch (error) {
      console.error('Failed to load messages:', error);
      handleApiError(error);
      setAppState(prev => ({
        ...prev,
        messages: [],
      }));
      setHasMoreMessages(false);
      setOldestMessageCursor(undefined);
    }
  }, [appState.token, serverAvailable]);

  // Load older messages (for pagination)
  const loadOlderMessages = useCallback(async (channelId: string) => {
    if (!appState.token || !serverAvailable || isLoadingOlderMessages || !hasMoreMessages || !oldestMessageCursor) {
      return;
    }
    
    setIsLoadingOlderMessages(true);
    
    try {
      const response = await api.getChannelMessages(channelId, appState.token, 50, oldestMessageCursor);
      
      if (response.messages.length === 0) {
        setHasMoreMessages(false);
        setIsLoadingOlderMessages(false);
        return;
      }
      
      // Format messages for display
      const formattedMessages = response.messages.map(msg => ({
        ...msg,
        time: msg.time || new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }));
      
      // Sort new messages by timestamp (oldest first)
      formattedMessages.sort((a, b) => a.timestamp - b.timestamp);
      
      // Store current scroll position before updating messages
      const container = messagesContainerRef.current;
      const scrollTop = container?.scrollTop || 0;
      const scrollHeight = container?.scrollHeight || 0;
      
      // Prepend older messages to the beginning of the list
      setAppState(prev => ({
        ...prev,
        messages: [...formattedMessages, ...prev.messages],
      }));
      
      // Update pagination state
      setHasMoreMessages(response.has_more);
      setOldestMessageCursor(response.next_cursor);
      
      // Maintain scroll position after prepending messages
      setTimeout(() => {
        if (container) {
          const newScrollHeight = container.scrollHeight;
          const heightDifference = newScrollHeight - scrollHeight;
          container.scrollTop = scrollTop + heightDifference;
        }
      }, 0);
      
    } catch (error) {
      console.error('Failed to load older messages:', error);
      handleApiError(error);
    } finally {
      setIsLoadingOlderMessages(false);
    }
  }, [appState.token, serverAvailable, isLoadingOlderMessages, hasMoreMessages, oldestMessageCursor]);

  // Handle scroll events for infinite scroll
  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const target = e.target as HTMLDivElement;
    
    // Check if scrolled to top (with small threshold)
    if (target.scrollTop <= 50 && hasMoreMessages && !isLoadingOlderMessages && selectedChannelId) {
      loadOlderMessages(selectedChannelId);
    }
  }, [hasMoreMessages, isLoadingOlderMessages, selectedChannelId, loadOlderMessages]);

  // Handle node selection
  const handleNodeSelect = useCallback((nodeId: string, index: number) => {
    setSelectedNodeId(nodeId);
    setSelectedChannelId(null);
    setActiveServer(index);
    setChannels([]);
    setMembers([]);
    setAppState(prev => ({ ...prev, messages: [] }));
    
    // Reset pagination state
    setIsLoadingOlderMessages(false);
    setHasMoreMessages(true);
    setOldestMessageCursor(undefined);
    
    // Load channels and members for the selected node
    loadChannels(nodeId);
    loadMembers(nodeId);
  }, [loadChannels, loadMembers]);

  // Load user's DM channels
  const loadDmChannels = useCallback(async () => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const response = await api.getDmChannels(appState.token);
      setDmChannels(response.dm_channels);
    } catch (error) {
      console.error('Failed to load DM channels:', error);
      handleApiError(error);
      setDmChannels([]);
    }
  }, [appState.token, serverAvailable]);

  // Create or open DM channel with a user
  const createDmChannel = useCallback(async (targetUserId: string) => {
    if (!appState.token || !serverAvailable) return null;
    
    try {
      const dmChannel = await api.createDmChannel(targetUserId, appState.token);
      
      // Reload DM channels to get the updated list with user info
      await loadDmChannels();
      
      return dmChannel;
    } catch (error) {
      console.error('Failed to create DM channel:', error);
      handleApiError(error);
      return null;
    }
  }, [appState.token, serverAvailable, loadDmChannels]);

  // Handle DM channel selection
  const handleDmChannelSelect = useCallback((dmChannel: DmChannelWithInfo) => {
    // Clear node/channel selection when selecting DM
    setSelectedNodeId(null);
    setSelectedChannelId(null);
    setSelectedDmChannel(dmChannel);
    notificationManager.setActiveChannel(dmChannel.id);
    
    // Reset pagination state
    setIsLoadingOlderMessages(false);
    setHasMoreMessages(true);
    setOldestMessageCursor(undefined);
    
    // Load messages for the DM channel
    loadMessages(dmChannel.id);
    
    // Join the DM channel via WebSocket
    if (ws && ws.isSocketConnected()) {
      ws.joinChannel(dmChannel.id);
    }
  }, [loadMessages, ws]);

  // Handle opening DM with a specific user (e.g., from member list)
  const openDmWithUser = useCallback(async (user: User) => {
    const dmChannel = await createDmChannel(user.id);
    if (dmChannel) {
      // Find the DM channel with info from our loaded channels
      await loadDmChannels(); // Refresh to get the channel with user info
      const dmChannelWithInfo = dmChannels.find(dm => dm.id === dmChannel.id);
      if (dmChannelWithInfo) {
        handleDmChannelSelect(dmChannelWithInfo);
      }
    }
  }, [createDmChannel, loadDmChannels, dmChannels, handleDmChannelSelect]);

  // Save display name
  const handleSaveDisplayName = async () => {
    if (!displayNameInput.trim() || !appState.token) return;
    setDisplayNameSaving(true);
    try {
      await api.updateProfile({ display_name: displayNameInput.trim() }, appState.token);
      // Update local state
      setAppState(prev => ({
        ...prev,
        user: prev.user ? { ...prev.user, display_name: displayNameInput.trim() } : prev.user,
      }));
      notificationManager.setCurrentUsername(displayNameInput.trim());
      setShowDisplayNamePrompt(false);
      setDisplayNameInput("");
    } catch (error) {
      console.error('Failed to update display name:', error);
    } finally {
      setDisplayNameSaving(false);
    }
  };

  // Handle channel selection
  const handleChannelSelect = useCallback((channelId: string, channelName: string) => {
    setSelectedChannelId(channelId);
    setActiveChannel(channelName);
    setAppState(prev => ({ ...prev, activeChannel: channelId }));
    notificationManager.setActiveChannel(channelId);
    
    // Mark channel as read in notification system
    if (selectedNodeId) {
      // Get the latest message ID to mark as read
      const latestMessage = appState.messages.length > 0 ? 
        appState.messages[appState.messages.length - 1] : null;
      
      notificationManager.markChannelAsRead(selectedNodeId, channelId, latestMessage?.id);
      // Store last-read timestamp per channel in localStorage
      localStorage.setItem(`accord_lastread_${channelId}`, Date.now().toString());
      setForceUpdate(prev => prev + 1); // Trigger re-render for unread badges
    }
    
    // Reset pagination state
    setIsLoadingOlderMessages(false);
    setHasMoreMessages(true);
    setOldestMessageCursor(undefined);
    
    // Load message history for the selected channel
    loadMessages(channelId);
    
    // Join channel via WebSocket if connected
    if (ws && ws.isSocketConnected()) {
      ws.joinChannel(channelId);
    }
  }, [loadMessages, ws, selectedNodeId, appState.messages]);

  // Handle creating a new channel
  const handleCreateChannel = async () => {
    if (!selectedNodeId || !appState.token || !newChannelName.trim()) return;
    
    try {
      await api.createChannel(selectedNodeId, newChannelName.trim(), newChannelType, appState.token);
      setShowCreateChannelForm(false);
      setNewChannelName("");
      setNewChannelType("text");
      // Reload channels
      await loadChannels(selectedNodeId);
    } catch (error) {
      console.error('Failed to create channel:', error);
      handleApiError(error);
    }
  };

  // Handle generating an invite
  const handleGenerateInvite = async () => {
    if (!selectedNodeId || !appState.token) return;
    
    try {
      const response = await api.createInviteWithOptions(selectedNodeId, appState.token);
      // Construct full invite link from the current relay URL
      const baseUrl = api.getBaseUrl();
      try {
        const url = new URL(baseUrl);
        const host = url.host; // includes port
        setGeneratedInvite(`accord://${host}/invite/${response.invite_code}`);
      } catch {
        // Fallback to just the code if URL parsing fails
        setGeneratedInvite(response.invite_code);
      }
      setShowInviteModal(true);
    } catch (error) {
      console.error('Failed to generate invite:', error);
      handleApiError(error);
    }
  };

  // Handle kicking a member
  const handleKickMember = async (userId: string, username: string) => {
    if (!selectedNodeId || !appState.token) return;
    
    const confirmed = window.confirm(`Are you sure you want to kick ${username} from this node?`);
    if (!confirmed) return;
    
    try {
      await api.kickMember(selectedNodeId, userId, appState.token);
      // Reload members
      await loadMembers(selectedNodeId);
    } catch (error) {
      console.error('Failed to kick member:', error);
      handleApiError(error);
    }
  };

  // Handle deleting a channel
  const handleDeleteChannel = async (channelId: string, channelName: string) => {
    if (!appState.token) return;
    
    const confirmed = window.confirm(`Are you sure you want to delete #${channelName}? This action cannot be undone.`);
    if (!confirmed) return;
    
    try {
      await api.deleteChannel(channelId, appState.token);
      // If we deleted the currently selected channel, clear selection
      if (channelId === selectedChannelId) {
        setSelectedChannelId(null);
        setActiveChannel("# general");
      }
      // Reload channels
      if (selectedNodeId) {
        await loadChannels(selectedNodeId);
      }
    } catch (error) {
      console.error('Failed to delete channel:', error);
      handleApiError(error);
    }
  };

  // Handle creating a new node
  const handleCreateNode = async () => {
    if (!appState.token || !newNodeName.trim()) return;
    setCreatingNode(true);
    try {
      const newNode = await api.createNode(newNodeName.trim(), appState.token, newNodeDescription.trim() || undefined);
      // Auto-create a #general channel
      try {
        await api.createChannel(newNode.id, 'general', 'text', appState.token);
      } catch (e) {
        console.warn('Failed to auto-create #general channel:', e);
      }
      // Reload nodes and auto-select the new one
      await loadNodes();
      setSelectedNodeId(newNode.id);
      setActiveServer(nodes.length); // will be the last index after reload
      setShowCreateNodeModal(false);
      setNewNodeName("");
      setNewNodeDescription("");
      // Load channels for the new node
      await loadChannels(newNode.id);
      await loadMembers(newNode.id);
    } catch (error) {
      console.error('Failed to create node:', error);
      handleApiError(error);
    } finally {
      setCreatingNode(false);
    }
  };

  // Handle notification preferences update
  const handleNotificationPreferencesChange = useCallback((preferences: NotificationPreferences) => {
    notificationManager.updatePreferences(preferences);
    setNotificationPreferences(preferences);
    setForceUpdate(prev => prev + 1); // Trigger re-render for any UI changes
  }, []);

  // Handle navigation to search result message
  const handleNavigateToMessage = useCallback((channelId: string, _messageId: string) => {
    // First, navigate to the channel if not already selected
    if (channelId !== selectedChannelId) {
      const channel = channels.find(ch => ch.id === channelId);
      if (channel) {
        handleChannelSelect(channelId, `# ${channel.name}`);
      }
    }
    
    // TODO: Scroll to the specific message once loaded
    // For now, just navigating to the channel
  }, [selectedChannelId, channels, handleChannelSelect]);

  // Mark channel as read when new messages are loaded
  const markChannelAsReadAfterLoad = useCallback((channelId: string, messages: Message[]) => {
    if (selectedNodeId && messages.length > 0) {
      const latestMessage = messages[messages.length - 1];
      notificationManager.markChannelAsRead(selectedNodeId, channelId, latestMessage.id);
      localStorage.setItem(`accord_lastread_${channelId}`, Date.now().toString());
      setForceUpdate(prev => prev + 1);
    }
  }, [selectedNodeId]);

  // Handle invite link submission
  const handleInviteLinkSubmit = async () => {
    setInviteError("");
    const parsed = parseInviteLink(inviteLinkInput);
    if (!parsed) {
      setInviteError("Invalid invite link. Expected format: accord://host:port/invite/CODE or https://host:port/invite/CODE");
      return;
    }
    setParsedInvite(parsed);
    setInviteConnecting(true);

    try {
      // Connect to the relay extracted from the invite link
      api.setBaseUrl(parsed.relayUrl);
      const health = await api.health();
      setServerConnected(true);
      setServerAvailable(true);
      setInviteRelayVersion(health.version);
      setServerUrl(parsed.relayUrl);

      // Check if we already have credentials for this relay
      const existingToken = getRelayToken(parsed.relayHost);
      const existingUserId = getRelayUserId(parsed.relayHost);

      if (existingToken && existingUserId) {
        // Auto-login: try using existing credentials
        try {
          storeToken(existingToken);
          localStorage.setItem('accord_user_id', existingUserId);

          // Load existing keys
          let pkHash = '';
          if (encryptionEnabled) {
            const existingKeyPair = await loadKeyFromStorage();
            if (existingKeyPair) {
              setKeyPair(existingKeyPair);
              const pk = await exportPublicKey(existingKeyPair.publicKey);
              pkHash = await sha256Hex(pk);
              setPublicKeyHash(pkHash);
              setPublicKey(pk);
            }
          }

          setAppState(prev => ({
            ...prev,
            isAuthenticated: true,
            token: existingToken,
            user: { id: existingUserId, public_key_hash: pkHash, public_key: '', created_at: 0, display_name: fingerprint(pkHash) }
          }));
          setIsAuthenticated(true);

          // Join node via invite code
          try {
            await api.joinNodeByInvite(parsed.inviteCode, existingToken);
          } catch (_e) {
            // May already be a member, that's fine
          }

          // Initialize WebSocket
          const socket = new AccordWebSocket(existingToken);
          setupWebSocketHandlers(socket);
          setWs(socket);
          socket.connect();

          setShowWelcomeScreen(false);
          setTimeout(() => { loadNodes(); loadDmChannels(); }, 100);
          return;
        } catch (_e) {
          // Token expired or invalid, fall through to register/login
        }
      }

      // No existing credentials - need to register
      setInviteNeedsRegister(true);
    } catch (_error) {
      setInviteError(`Cannot connect to relay at ${parsed.relayUrl}`);
      setParsedInvite(null);
    } finally {
      setInviteConnecting(false);
    }
  };

  // Handle registration via invite flow
  const handleInviteRegister = async () => {
    if (!parsedInvite) return;
    setInviteError("");

    if (invitePassword.length < 8) {
      setInviteError("Password must be at least 8 characters");
      return;
    }

    setInviteJoining(true);
    try {
      // Auto-generate keypair
      let publicKeyToUse = '';
      if (encryptionEnabled) {
        const newKeyPair = await generateKeyPair();
        publicKeyToUse = await exportPublicKey(newKeyPair.publicKey);
        await saveKeyToStorage(newKeyPair);
        setKeyPair(newKeyPair);
        setPublicKey(publicKeyToUse);
      }

      if (!publicKeyToUse) {
        setInviteError("Failed to generate encryption keys");
        setInviteJoining(false);
        return;
      }

      // Register
      await api.register(publicKeyToUse, invitePassword);
      const pkHash = await sha256Hex(publicKeyToUse);
      setPublicKeyHash(pkHash);

      // Login
      const response = await api.login(publicKeyToUse, invitePassword);
      storeToken(response.token);
      localStorage.setItem('accord_user_id', response.user_id);

      // Store per-relay credentials
      storeRelayToken(parsedInvite.relayHost, response.token);
      storeRelayUserId(parsedInvite.relayHost, response.user_id);

      // Join node via invite
      try {
        await api.joinNodeByInvite(parsedInvite.inviteCode, response.token);
      } catch (_e) {
        // May already be a member
      }

      setAppState(prev => ({
        ...prev,
        isAuthenticated: true,
        token: response.token,
        user: { id: response.user_id, public_key_hash: pkHash, public_key: publicKeyToUse, created_at: 0, display_name: fingerprint(pkHash) }
      }));
      setIsAuthenticated(true);

      notificationManager.setCurrentUsername(fingerprint(pkHash));

      // Initialize WebSocket
      const socket = new AccordWebSocket(response.token);
      setupWebSocketHandlers(socket);
      setWs(socket);
      socket.connect();

      // Show key backup, then land in app
      setShowKeyBackup(true);
      setShowWelcomeScreen(false);

      // Prompt for display name after first join
      setTimeout(() => { setShowDisplayNamePrompt(true); }, 500);

      setTimeout(() => { loadNodes(); loadDmChannels(); }, 100);
    } catch (error) {
      setInviteError(error instanceof Error ? error.message : "Registration failed");
    } finally {
      setInviteJoining(false);
    }
  };

  // Handle server connection (admin/manual mode)
  const handleServerConnect = async () => {
    setServerConnecting(true);
    setAuthError("");
    try {
      api.setBaseUrl(serverUrl);
      const health = await api.health();
      setServerConnected(true);
      setServerAvailable(true);
      setServerVersion(health.version);
      setShowServerScreen(false);
      setShowWelcomeScreen(false);
    } catch (error) {
      setAuthError(`Cannot connect to ${serverUrl}`);
      setServerConnected(false);
    } finally {
      setServerConnecting(false);
    }
  };

  // Handle authentication
  const handleAuth = async () => {
    if (!serverAvailable) {
      // Skip auth if server unavailable - generate keys for demo mode
      if (encryptionEnabled && !keyPair) {
        try {
          const newKeyPair = await generateKeyPair();
          await saveKeyToStorage(newKeyPair);
          setKeyPair(newKeyPair);
          const pk = await exportPublicKey(newKeyPair.publicKey);
          setPublicKey(pk);
          setPublicKeyHash(await sha256Hex(pk));
        } catch (error) {
          console.warn('Failed to generate demo keys:', error);
        }
      }
      setIsAuthenticated(true);
      setAppState(prev => ({ ...prev, isAuthenticated: true }));
      return;
    }

    setAuthError("");
    
    try {
      if (isLoginMode) {
        // Login — need keypair loaded from storage + password
        let pkToUse = publicKey.trim();
        
        // Try to load from storage if not provided
        if (!pkToUse && encryptionEnabled) {
          const existingKeyPair = await loadKeyFromStorage();
          if (existingKeyPair) {
            pkToUse = await exportPublicKey(existingKeyPair.publicKey);
            setKeyPair(existingKeyPair);
            setPublicKey(pkToUse);
          }
        }
        
        if (!pkToUse) {
          setAuthError("No keypair found. Import your key or register a new account.");
          return;
        }

        // Login with public_key + password (server computes hash)
        const response = await api.login(pkToUse, password);
        
        // Store token and user info
        storeToken(response.token);
        localStorage.setItem('accord_user_id', response.user_id);

        // Ensure keypair is loaded
        if (encryptionEnabled && !keyPair) {
          const existingKeyPair = await loadKeyFromStorage();
          if (existingKeyPair) {
            setKeyPair(existingKeyPair);
          }
        }

        const pkHash = await sha256Hex(pkToUse);
        setPublicKeyHash(pkHash);
        
        setAppState(prev => ({
          ...prev,
          isAuthenticated: true,
          token: response.token,
          user: { id: response.user_id, public_key_hash: pkHash, public_key: pkToUse, created_at: 0, display_name: fingerprint(pkHash) }
        }));
        setIsAuthenticated(true);

        // Set display name for notification system (use fingerprint)
        notificationManager.setCurrentUsername(fingerprint(pkHash));

        // Initialize WebSocket connection
        const socket = new AccordWebSocket(response.token);
        setupWebSocketHandlers(socket);
        setWs(socket);
        socket.connect();

        // Load initial data
        setTimeout(() => {
          loadNodes();
          loadDmChannels();
        }, 100);

      } else {
        // Register — validate password
        if (password.length < 8) {
          setAuthError("Password must be at least 8 characters long");
          return;
        }
        
        // Auto-generate keypair
        let publicKeyToUse = publicKey.trim();
        
        if (!publicKeyToUse && encryptionEnabled) {
          try {
            const newKeyPair = await generateKeyPair();
            publicKeyToUse = await exportPublicKey(newKeyPair.publicKey);
            await saveKeyToStorage(newKeyPair);
            setKeyPair(newKeyPair);
            setPublicKey(publicKeyToUse);
          } catch (error) {
            setAuthError("Failed to generate encryption keys");
            return;
          }
        }
        
        if (!publicKeyToUse) {
          setAuthError("Public key generation failed. Crypto may not be supported.");
          return;
        }
        
        await api.register(publicKeyToUse, password);
        
        const pkHash = await sha256Hex(publicKeyToUse);
        setPublicKeyHash(pkHash);
        
        // Show key backup prompt
        setShowKeyBackup(true);

        // Prompt for display name after registration
        setTimeout(() => { setShowDisplayNamePrompt(true); }, 500);
      }
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Authentication failed");
    }
  };

  // Handle logout
  const handleLogout = () => {
    if (ws) {
      ws.disconnect();
      setWs(null);
    }
    
    clearToken();
    localStorage.removeItem('accord_user_id');
    
    // Clear encryption state
    setKeyPair(null);
    clearChannelKeyCache();
    
    // Clear navigation state
    setNodes([]);
    setChannels([]);
    setMembers([]);
    setSelectedNodeId(null);
    setSelectedChannelId(null);
    
    setIsAuthenticated(false);
    setAppState({
      isAuthenticated: false,
      nodes: [],
      messages: [],
      isConnected: false,
    });
    
    setPassword("");
    setPublicKey("");
    setPublicKeyHash("");
    
    // Reset welcome/invite state for re-entry
    setShowWelcomeScreen(true);
    setWelcomeMode('choose');
    setInviteLinkInput("");
    setParsedInvite(null);
    setInviteError("");
    setInviteNeedsRegister(false);
    setInvitePassword("");
  };

  // Handle sending messages
  const handleSendMessage = async () => {
    if (!message.trim()) return;

    // Determine which channel to use - DM channel takes priority
    const channelToUse = selectedDmChannel?.id || selectedChannelId || appState.activeChannel;
    
    if (ws && ws.isSocketConnected() && channelToUse) {
      // Send via WebSocket if connected and we have an active channel
      try {
        let messageToSend = message;
        let isEncrypted = false;

        // Encrypt message if encryption is enabled and we have keys
        if (encryptionEnabled && keyPair && channelToUse) {
          try {
            const channelKey = await getChannelKey(keyPair.privateKey, channelToUse);
            messageToSend = await encryptMessage(channelKey, message);
            isEncrypted = true;
          } catch (error) {
            console.warn('Failed to encrypt message, sending plaintext:', error);
          }
        }

        // Pass reply_to if we're replying to a message
        ws.sendChannelMessage(channelToUse, messageToSend, replyingTo?.id);

        // Add to local messages for immediate display
        const newMessage: Message = {
          id: Math.random().toString(),
          author: appState.user?.display_name || fingerprint(appState.user?.public_key_hash || '') || "You",
          content: message, // Show original plaintext locally
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          timestamp: Date.now(),
          channel_id: channelToUse,
          isEncrypted: isEncrypted,
          reply_to: replyingTo?.id,
          replied_message: replyingTo ? {
            id: replyingTo.id,
            sender_id: replyingTo.author,
            sender_public_key_hash: '',
            encrypted_payload: "",
            created_at: replyingTo.timestamp,
            content: replyingTo.content,
          } : undefined,
        };

        setAppState(prev => ({
          ...prev,
          messages: [...prev.messages, newMessage]
        }));

        // Auto-scroll to bottom after sending
        const container = messagesContainerRef.current;
        if (container) {
          setTimeout(() => {
            container.scrollTop = container.scrollHeight;
          }, 0);
        }

      } catch (error) {
        console.error('Failed to send message:', error);
      }
    } else {
      // Add to local messages as fallback
      const newMessage: Message = {
        id: Math.random().toString(),
        author: appState.user?.display_name || fingerprint(appState.user?.public_key_hash || '') || "You",
        content: message,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        timestamp: Date.now(),
        isEncrypted: false,
      };

      setAppState(prev => ({
        ...prev,
        messages: [...prev.messages, newMessage]
      }));

      // Auto-scroll to bottom after sending
      const container = messagesContainerRef.current;
      if (container) {
        setTimeout(() => {
          container.scrollTop = container.scrollHeight;
        }, 0);
      }
    }

    setMessage("");
    setReplyingTo(null);
  };

  // Message editing functionality removed

  // Handle saving message edit
  const handleSaveEdit = async () => {
    if (!editingMessageId || !editingContent.trim() || !appState.user) return;

    try {
      let messageToSend = editingContent;

      // Encrypt message if encryption is enabled and we have keys
      if (encryptionEnabled && keyPair && selectedChannelId) {
        try {
          const channelKey = await getChannelKey(keyPair.privateKey, selectedChannelId);
          messageToSend = await encryptMessage(channelKey, editingContent);
        } catch (error) {
          console.warn('Failed to encrypt edited message:', error);
          setError('Failed to encrypt message');
          return;
        }
      }

      if (ws && ws.isSocketConnected()) {
        // Send via WebSocket
        ws.sendEditMessage(editingMessageId, messageToSend);
      } else {
        // Send via REST API
        await api.editMessage(editingMessageId, appState.user.id, messageToSend);
        // Update local state immediately
        setAppState(prev => ({
          ...prev,
          messages: prev.messages.map(msg => 
            msg.id === editingMessageId
              ? { ...msg, content: editingContent, edited_at: Date.now() }
              : msg
          ),
        }));
      }

      // Clear editing state
      setEditingMessageId(null);
      setEditingContent("");
    } catch (error) {
      console.error('Failed to edit message:', error);
      setError('Failed to edit message');
    }
  };

  // Handle canceling message edit
  const handleCancelEdit = () => {
    setEditingMessageId(null);
    setEditingContent("");
  };

  // Handle delete message confirmation
  const handleDeleteMessage = async (messageId: string) => {
    if (!appState.token) return;

    try {
      if (ws && ws.isSocketConnected()) {
        // Send via WebSocket
        ws.sendDeleteMessage(messageId);
      } else {
        // Send via REST API
        await api.deleteMessage(messageId, appState.token);
        // Update local state immediately
        setAppState(prev => ({
          ...prev,
          messages: prev.messages.filter(msg => msg.id !== messageId),
        }));
      }

      setShowDeleteConfirm(null);
    } catch (error) {
      console.error('Failed to delete message:', error);
      setError('Failed to delete message');
    }
  };

  // Check if user can delete a message (author or admin/mod)
  const canDeleteMessage = (message: Message): boolean => {
    if (!appState.user || !selectedNodeId) return false;
    
    // Author can always delete their own messages
    if (message.author === (appState.user.display_name || fingerprint(appState.user.public_key_hash))) return true;
    
    // Check if user is admin/mod of the current node
    const currentUserId = localStorage.getItem('accord_user_id');
    const member = members.find(m => m.user_id === currentUserId);
    return member ? (member.role === 'admin' || member.role === 'moderator') : false;
  };

  // Reply functionality
  const handleReply = (message: Message) => {
    setReplyingTo(message);
    // Focus the message input
    const messageInput = document.querySelector('.message-input') as HTMLTextAreaElement;
    if (messageInput) {
      messageInput.focus();
    }
  };

  const handleCancelReply = () => {
    setReplyingTo(null);
  };

  const scrollToMessage = (messageId: string) => {
    const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
    if (messageElement) {
      messageElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
      // Add highlight effect
      messageElement.classList.add('highlight-message');
      setTimeout(() => {
        messageElement.classList.remove('highlight-message');
      }, 2000);
    }
  };

  // Handle adding a reaction to a message
  const handleAddReaction = async (messageId: string, emoji: string) => {
    if (!appState.token) return;

    try {
      if (ws && ws.isSocketConnected()) {
        // Send via WebSocket
        ws.addReaction(messageId, emoji);
      } else {
        // Send via REST API
        await api.addReaction(messageId, emoji, appState.token);
      }
    } catch (error) {
      console.error('Failed to add reaction:', error);
      setError('Failed to add reaction');
    }

    setShowEmojiPicker(null); // Close emoji picker
  };

  // Handle removing a reaction from a message
  const handleRemoveReaction = async (messageId: string, emoji: string) => {
    if (!appState.token) return;

    try {
      if (ws && ws.isSocketConnected()) {
        // Send via WebSocket
        ws.removeReaction(messageId, emoji);
      } else {
        // Send via REST API
        await api.removeReaction(messageId, emoji, appState.token);
      }
    } catch (error) {
      console.error('Failed to remove reaction:', error);
      setError('Failed to remove reaction');
    }
  };

  // Pin message (admin/mod only)
  const handlePinMessage = async (messageId: string) => {
    if (!appState.token) return;

    try {
      if (ws && ws.isSocketConnected()) {
        // Send via WebSocket
        ws.pinMessage(messageId);
      } else {
        // Send via REST API
        await api.pinMessage(messageId, appState.token);
      }
    } catch (error) {
      console.error('Failed to pin message:', error);
      setError('Failed to pin message');
    }
  };

  // Unpin message (admin/mod only)
  const handleUnpinMessage = async (messageId: string) => {
    if (!appState.token) return;

    try {
      if (ws && ws.isSocketConnected()) {
        // Send via WebSocket
        ws.unpinMessage(messageId);
      } else {
        // Send via REST API
        await api.unpinMessage(messageId, appState.token);
      }
    } catch (error) {
      console.error('Failed to unpin message:', error);
      setError('Failed to unpin message');
    }
  };

  // Load pinned messages for current channel
  const loadPinnedMessages = async () => {
    if (!selectedChannelId || !appState.token) return;

    try {
      const response = await api.getPinnedMessages(selectedChannelId, appState.token);
      const formattedPinnedMessages = response.pinned_messages.map((msg: any) => ({
        ...msg,
        time: new Date(msg.created_at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        pinned_at: msg.pinned_at * 1000, // Convert to milliseconds
        timestamp: msg.created_at * 1000,
      }));
      
      setPinnedMessages(formattedPinnedMessages);
    } catch (error) {
      console.error('Failed to load pinned messages:', error);
      setError('Failed to load pinned messages');
    }
  };

  // Toggle pinned messages panel
  const togglePinnedPanel = () => {
    setShowPinnedPanel(prev => {
      if (!prev) {
        loadPinnedMessages();
      }
      return !prev;
    });
  };

  // Toggle reaction (add if not present, remove if present)
  const handleToggleReaction = async (messageId: string, emoji: string) => {
    if (!appState.user) return;

    const message = appState.messages.find(m => m.id === messageId);
    if (!message || !message.reactions) {
      handleAddReaction(messageId, emoji);
      return;
    }

    const existingReaction = message.reactions.find(r => r.emoji === emoji);
    if (existingReaction && existingReaction.users.includes(appState.user.id)) {
      handleRemoveReaction(messageId, emoji);
    } else {
      handleAddReaction(messageId, emoji);
    }
  };

  // Check for existing session on mount
  useEffect(() => {
    const checkExistingSession = async () => {
      const token = getToken();
      const userId = localStorage.getItem('accord_user_id');
      
      if (token && userId && serverAvailable) {
        setShowWelcomeScreen(false);
        // Load existing keys if available
        let existingKeyPair: CryptoKeyPair | null = null;
        if (encryptionEnabled) {
          existingKeyPair = await loadKeyFromStorage();
          if (existingKeyPair) {
            setKeyPair(existingKeyPair);
          }
        }

        // Compute public key hash if we have a key
        let pkHash = '';
        if (existingKeyPair) {
          const pk = await exportPublicKey(existingKeyPair.publicKey);
          pkHash = await sha256Hex(pk);
          setPublicKeyHash(pkHash);
          setPublicKey(pk);
        }

        setAppState(prev => ({
          ...prev,
          isAuthenticated: true,
          token,
          user: { id: userId, public_key_hash: pkHash, public_key: '', created_at: 0, display_name: fingerprint(pkHash) }
        }));
        setIsAuthenticated(true);

        // Initialize WebSocket connection
        const socket = new AccordWebSocket(token);
        setupWebSocketHandlers(socket);
        setWs(socket);
        socket.connect();

        // Load initial data
        setTimeout(() => {
          loadNodes();
          loadDmChannels();
        }, 100);
      }
    };

    checkExistingSession();
  }, [serverAvailable, setupWebSocketHandlers, encryptionEnabled, loadNodes]);

  // Load channels and members when node is selected
  useEffect(() => {
    if (selectedNodeId && appState.token && serverAvailable) {
      loadChannels(selectedNodeId);
      loadMembers(selectedNodeId);
    }
  }, [selectedNodeId, appState.token, serverAvailable, loadChannels, loadMembers]);

  // Load messages when channel is selected
  useEffect(() => {
    if (selectedChannelId && appState.token && serverAvailable) {
      loadMessages(selectedChannelId);
    }
  }, [selectedChannelId, appState.token, serverAvailable, loadMessages]);

  // Keyboard shortcuts for search, settings, help, and escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ctrl+K / Cmd+K: open search
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'f')) {
        e.preventDefault();
        setShowSearchOverlay(true);
      }
      // Ctrl+, / Cmd+,: open settings
      if ((e.ctrlKey || e.metaKey) && e.key === ',') {
        e.preventDefault();
        setShowSettings(true);
      }
      // Ctrl+/ / Cmd+/: keyboard shortcuts help
      if ((e.ctrlKey || e.metaKey) && e.key === '/') {
        e.preventDefault();
        setShowShortcutsHelp(prev => !prev);
      }
      // Escape: close modals / cancel editing
      if (e.key === 'Escape') {
        if (showShortcutsHelp) { setShowShortcutsHelp(false); return; }
        if (showSearchOverlay) { setShowSearchOverlay(false); return; }
        if (showSettings) { setShowSettings(false); return; }
        if (showNotificationSettings) { setShowNotificationSettings(false); return; }
        if (showCreateNodeModal) { setShowCreateNodeModal(false); return; }
        if (showInviteModal) { setShowInviteModal(false); return; }
        if (showDisplayNamePrompt) { setShowDisplayNamePrompt(false); return; }
        if (editingMessageId) { handleCancelEdit(); return; }
        if (replyingTo) { handleCancelReply(); return; }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [showShortcutsHelp, showSearchOverlay, showSettings, showNotificationSettings, showCreateNodeModal, showInviteModal, showDisplayNamePrompt, editingMessageId, replyingTo]);

  // Apply font-size and density from localStorage on mount
  useEffect(() => {
    const savedFontSize = localStorage.getItem('accord-font-size');
    if (savedFontSize) {
      document.documentElement.style.setProperty('--font-size', savedFontSize);
    }
  }, []);

  const [messageDensity] = useState<string>(() =>
    localStorage.getItem('accord-message-density') || 'comfortable'
  );

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (ws) {
        ws.disconnect();
      }
    };
  }, [ws]);

  // Key backup modal
  if (showKeyBackup) {
    return (
      <div className="app">
        <div className="auth-page">
          <div className="auth-card key-backup-card">
            <h2 className="auth-title">🔑 Backup Your Key</h2>
            <p className="auth-subtitle">
              Your identity is your keypair. If you lose it, you lose access to your account forever.
              <strong className="warning" style={{ color: 'var(--yellow)' }}> There is no recovery.</strong>
            </p>
            <div className="form-group">
              <label className="form-label">Your Public Key Fingerprint</label>
              <div className="key-value">{publicKeyHash || 'computing...'}</div>
            </div>
            <div className="form-group">
              <label className="form-label">Public Key (share this)</label>
              <textarea
                readOnly
                value={publicKey}
                rows={3}
                className="form-textarea"
              />
            </div>
            <div className="auth-success" style={{ marginBottom: '16px' }}>
              ✅ Your keypair is saved in this browser's storage. To use Accord on another device, you'll need to export and import your key.
            </div>
            <div className="key-backup-actions">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(publicKey).catch(() => {});
                  alert('Public key copied to clipboard!');
                }}
                className="btn btn-green"
              >
                Copy Public Key
              </button>
              <button
                onClick={() => {
                  setShowKeyBackup(false);
                  setIsLoginMode(true);
                  setPassword("");
                  setAuthError("");
                }}
                className="btn btn-primary"
              >
                Continue to Login
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Welcome / Invite link screen
  if (showWelcomeScreen) {
    return (
      <div className="app">
        <div className="auth-page">
          <div className="auth-card auth-card-narrow">
            
            {welcomeMode === 'choose' && (
              <>
                <div className="auth-brand">
                  <h1>⚡ <span className="brand-accent">Accord</span></h1>
                </div>
                <p className="auth-tagline">Privacy-first community communications</p>
                <div className="auth-buttons-stack">
                  <button onClick={() => setWelcomeMode('invite')} className="btn btn-primary">
                    I have an invite link
                  </button>
                  <button onClick={() => setWelcomeMode('admin')} className="btn btn-outline">
                    Set up a new relay (admin)
                  </button>
                </div>
              </>
            )}

            {welcomeMode === 'invite' && !inviteNeedsRegister && (
              <>
                <button onClick={() => { setWelcomeMode('choose'); setInviteError(''); setInviteLinkInput(''); setParsedInvite(null); setInviteRelayVersion(''); }} className="auth-back-btn">← Back</button>
                <h2 className="auth-title">Join via Invite</h2>
                <p className="auth-subtitle">Paste the invite link you received</p>
                
                <div className="form-group">
                  <input
                    type="text"
                    placeholder="accord://host:port/invite/CODE or https://..."
                    value={inviteLinkInput}
                    onChange={(e) => setInviteLinkInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleInviteLinkSubmit(); }}
                    className="form-input"
                  />
                </div>

                {inviteError && <div className="auth-error">{inviteError}</div>}
                {inviteRelayVersion && <div className="auth-success">✅ Connected to relay v{inviteRelayVersion}</div>}

                <button
                  onClick={handleInviteLinkSubmit}
                  disabled={inviteConnecting || !inviteLinkInput.trim()}
                  className="btn btn-primary"
                >
                  {inviteConnecting ? 'Connecting to relay...' : 'Join'}
                </button>
              </>
            )}

            {welcomeMode === 'invite' && inviteNeedsRegister && (
              <>
                <h2 className="auth-title">Create Your Identity</h2>
                <p className="auth-subtitle">Connected to relay — now set a password to create your identity</p>
                <div className="auth-info-box">
                  <span className="accent">🔐 A keypair will be auto-generated. No username needed.</span>
                </div>

                <div className="form-group">
                  <label className="form-label">Password (min 8 characters)</label>
                  <input
                    type="password"
                    placeholder="Choose a password"
                    value={invitePassword}
                    onChange={(e) => setInvitePassword(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleInviteRegister(); }}
                    className="form-input"
                  />
                </div>

                {inviteError && <div className="auth-error">{inviteError}</div>}

                <button
                  onClick={handleInviteRegister}
                  disabled={inviteJoining || invitePassword.length < 8}
                  className="btn btn-green"
                >
                  {inviteJoining ? 'Creating identity & joining...' : 'Create Identity & Join'}
                </button>
              </>
            )}

            {welcomeMode === 'admin' && (
              <>
                <button onClick={() => { setWelcomeMode('choose'); setAuthError(''); }} className="auth-back-btn">← Back</button>
                <h2 className="auth-title">Connect to Relay</h2>
                <p className="auth-subtitle">Enter the relay server URL (admin/power-user)</p>
                
                <div className="form-group">
                  <label className="form-label">Server URL</label>
                  <input
                    type="text"
                    placeholder="http://localhost:8080"
                    value={serverUrl}
                    onChange={(e) => setServerUrl(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleServerConnect(); }}
                    className="form-input"
                  />
                </div>

                {authError && <div className="auth-error">{authError}</div>}
                {serverVersion && <div className="auth-success">✅ Connected — server v{serverVersion}</div>}

                <button
                  onClick={handleServerConnect}
                  disabled={serverConnecting}
                  className="btn btn-primary"
                >
                  {serverConnecting ? 'Connecting...' : 'Connect'}
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    );
  }

  // Legacy server connection screen (from Settings → Advanced)
  if (showServerScreen) {
    return (
      <div className="app">
        <div className="auth-page">
          <div className="auth-card auth-card-narrow">
            <h2 className="auth-title">Connect to Relay</h2>
            <p className="auth-subtitle">Manual relay connection</p>
            
            <div className="form-group">
              <label className="form-label">Server URL</label>
              <input
                type="text"
                placeholder="http://localhost:8080"
                value={serverUrl}
                onChange={(e) => setServerUrl(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') handleServerConnect(); }}
                className="form-input"
              />
            </div>

            {authError && <div className="auth-error">{authError}</div>}
            {serverVersion && <div className="auth-success">✅ Connected — server v{serverVersion}</div>}

            <button
              onClick={handleServerConnect}
              disabled={serverConnecting}
              className="btn btn-primary"
            >
              {serverConnecting ? 'Connecting...' : 'Connect'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Render authentication screen
  if (!isAuthenticated) {
    return (
      <div className="app">
        <div className="auth-page">
          <div className="auth-card">
            <h2 className="auth-title">
              {isLoginMode ? 'Login to Accord' : 'Create Identity'}
            </h2>
            <p className="auth-subtitle">
              {isLoginMode 
                ? 'Authenticate with your keypair and password' 
                : 'A new keypair will be generated automatically'}
            </p>
            
            <div className="auth-server-bar">
              <span>🔗 {serverUrl} {serverAvailable && <span className="connected">● connected</span>}</span>
              <button onClick={() => { setShowWelcomeScreen(true); setWelcomeMode('choose'); setAuthError(''); }} className="btn-ghost" style={{ fontSize: '12px' }}>Change</button>
            </div>

            {isLoginMode && (
              <div className="form-group">
                <label className="form-label">Key Status</label>
                <div className="auth-info-box">
                  {keyPair || publicKey ? (
                    <span className="accent">🔑 Keypair loaded from browser storage</span>
                  ) : (
                    <span style={{ color: 'var(--yellow)' }}>⚠️ No keypair found — register or import</span>
                  )}
                </div>
              </div>
            )}

            <div className="form-group">
              <label className="form-label">Password</label>
              <input
                type="password"
                placeholder={isLoginMode ? "Enter your password" : "Choose a password (min 8 chars)"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') handleAuth(); }}
                className="form-input"
              />
              {!isLoginMode && password && password.length < 8 && (
                <div className="form-hint" style={{ color: 'var(--red)' }}>
                  Password must be at least 8 characters
                </div>
              )}
            </div>

            {!isLoginMode && encryptionEnabled && (
              <div className="auth-info-box" style={{ marginBottom: '20px' }}>
                <div className="accent">🔐 A new ECDH P-256 keypair will be generated for your identity</div>
                <div style={{ fontSize: '12px', marginTop: '4px' }}>No username needed — you are identified by your public key hash</div>
              </div>
            )}

            {authError && <div className="auth-error">{authError}</div>}

            <button onClick={handleAuth} className="btn btn-primary" style={{ marginBottom: '16px' }}>
              {isLoginMode ? 'Login' : 'Create Identity & Register'}
            </button>

            <div className="auth-toggle">
              <button
                onClick={() => { setIsLoginMode(!isLoginMode); setAuthError(""); setPassword(""); }}
                className="btn-ghost"
              >
                {isLoginMode ? 'Need to create an identity?' : 'Already have a keypair? Login'}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Presence helper: determine effective status for a member
  const getPresenceStatus = useCallback((userId: string): import('./types').PresenceStatus => {
    // Check explicit presence from server
    const explicit = presenceMap.get(userId);
    if (explicit) return explicit;
    
    // Heuristic: user sent a message in the last 5 minutes = online
    const lastMsg = lastMessageTimes.get(userId);
    if (lastMsg && Date.now() - lastMsg < 5 * 60 * 1000) {
      return 'online' as import('./types').PresenceStatus;
    }
    
    // Check member profile status
    const member = members.find(m => m.user_id === userId);
    if (member?.status) return member.status;
    if (member?.profile?.status) return member.profile.status;
    
    return 'offline' as import('./types').PresenceStatus;
  }, [presenceMap, lastMessageTimes, members]);

  // Sort members: online > idle > dnd > offline
  const sortedMembers = React.useMemo(() => {
    const order: Record<string, number> = { online: 0, idle: 1, dnd: 2, offline: 3 };
    return [...members].sort((a, b) => {
      const sa = order[getPresenceStatus(a.user_id)] ?? 3;
      const sb = order[getPresenceStatus(b.user_id)] ?? 3;
      return sa - sb;
    });
  }, [members, getPresenceStatus]);

  // Context menu handler
  const handleContextMenu = useCallback((e: React.MouseEvent, userId: string, publicKeyHash: string, name: string, bio?: string, user?: User) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, userId, publicKeyHash, displayName: name, bio, user });
  }, []);

  // Close context menu on click anywhere
  useEffect(() => {
    const handler = () => setContextMenu(null);
    if (contextMenu) {
      document.addEventListener('click', handler);
      return () => document.removeEventListener('click', handler);
    }
  }, [contextMenu]);

  // Use server data — no mock fallback
  const servers = nodes.map(n => n.name);
  const channelList = channels.map(ch => `# ${ch.name}`);
  const displayName = (u: User) => u.display_name || fingerprint(u.public_key_hash);
  const users = members.map(m => displayName(m.user));

  return (
    <div className="app">
      {/* Server list */}
      <div className="server-list" key={forceUpdate}>
        {servers.map((s, i) => {
          const nodeId = nodes.length > 0 ? nodes[i]?.id : null;
          const nodeUnreads = nodeId ? notificationManager.getNodeUnreads(nodeId) : { totalUnreads: 0, totalMentions: 0 };
          
          return (
            <div
              key={nodeId || s}
              className={`server-icon ${i === activeServer ? "active" : ""}`}
              onClick={() => {
                if (nodeId) {
                  handleNodeSelect(nodeId, i);
                } else {
                  setActiveServer(i);
                }
              }}
              title={s}
            >
              {s[0]}
              {nodeUnreads.totalMentions > 0 && (
                <div className="server-notification mention">
                  {nodeUnreads.totalMentions > 9 ? '9+' : nodeUnreads.totalMentions}
                </div>
              )}
              {nodeUnreads.totalMentions === 0 && nodeUnreads.totalUnreads > 0 && (
                <div className="server-notification dot" />
              )}
            </div>
          );
        })}
        <div 
          className="server-icon add-server" 
          title="Create Node"
          onClick={() => setShowCreateNodeModal(true)}
          style={{ cursor: 'pointer' }}
        >
          +
        </div>
      </div>

      {/* Channel sidebar */}
      <div className="channel-sidebar">
        <div className="sidebar-header">
          <div className="sidebar-header-row">
            <div style={{ display: 'flex', alignItems: 'center' }}>
              {servers[activeServer]}
              {serverAvailable && (
                <span className="connection-status">
                  <span className={`connection-dot ${connectionInfo.status}`}>●</span>
                  <span className="connection-label">
                    {connectionInfo.status === 'connected' && 'Connected'}
                    {connectionInfo.status === 'reconnecting' && `Reconnecting... ${connectionInfo.reconnectAttempt}/${connectionInfo.maxReconnectAttempts}`}
                    {connectionInfo.status === 'disconnected' && !appState.isConnected && 'Disconnected'}
                  </span>
                  {connectionInfo.status === 'disconnected' && !appState.isConnected && ws && (
                    <button className="connection-retry-btn" onClick={() => ws.retry()}>Retry</button>
                  )}
                </span>
              )}
              {!serverAvailable && <span className="demo-badge">DEMO</span>}
            </div>
            
            {selectedNodeId && (hasPermission(selectedNodeId, 'ManageInvites') || hasPermission(selectedNodeId, 'ManageNode')) && (
              <div className="sidebar-admin-buttons">
                {hasPermission(selectedNodeId, 'ManageInvites') && (
                  <button onClick={handleGenerateInvite} className="sidebar-admin-btn" title="Generate Invite">Invite</button>
                )}
                {hasPermission(selectedNodeId, 'ManageNode') && (
                  <button onClick={() => alert('Node settings coming soon!')} className="sidebar-admin-btn danger" title="Node Settings">Settings</button>
                )}
              </div>
            )}
          </div>
          
          {selectedNodeId && userRoles[selectedNodeId] && (
            <div className="sidebar-role">{getRoleBadge(userRoles[selectedNodeId])} {userRoles[selectedNodeId]}</div>
          )}
        </div>
        
        <div className="channel-list">
          {channelList.map((ch, i) => {
            const channel = channels.length > 0 ? channels[i] : null;
            const isActive = channel ? channel.id === selectedChannelId : ch === activeChannel;
            const canDeleteChannel = selectedNodeId && hasPermission(selectedNodeId, 'DeleteChannel');
            const isVoiceChannel = channel?.channel_type === 'voice';
            const isConnectedToVoice = isVoiceChannel && voiceChannelId === channel?.id;
            
            const channelUnreads = selectedNodeId && channel ? 
              notificationManager.getChannelUnreads(selectedNodeId, channel.id) : 
              { count: 0, mentions: 0 };
            const hasUnread = channelUnreads.count > 0 || channelUnreads.mentions > 0;
            
            return (
              <div
                key={channel?.id || ch}
                className={`channel ${isActive ? "active" : ""} ${isConnectedToVoice ? "voice-connected" : ""} ${hasUnread && !isActive ? "unread" : ""}`}
              >
                <div
                  onClick={() => {
                    if (channel) {
                      if (isVoiceChannel) {
                        // Handle voice channel click
                        if (isConnectedToVoice) {
                          // Already connected, do nothing or show voice panel
                        } else {
                          // Connect to voice channel
                          setVoiceChannelId(channel.id);
                          setVoiceChannelName(channel.name);
                        }
                      } else {
                        // Text channel
                        handleChannelSelect(channel.id, ch);
                      }
                    } else {
                      setActiveChannel(ch);
                    }
                  }}
                  style={{ flex: 1, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}
                >
                  <span>
                    {isVoiceChannel ? '🔊' : '#'} {channel?.name || ch.replace(/^# /, '')}
                  </span>
                  {isVoiceChannel && (
                    <span style={{ fontSize: '11px', color: '#8e9297' }}>
                      {/* TODO: Show connected user count */}
                      (0)
                    </span>
                  )}
                  {isConnectedToVoice && (
                    <span style={{ fontSize: '10px', color: '#43b581' }}>●</span>
                  )}
                </div>

                <div className="channel-badges">
                  {channelUnreads.mentions > 0 && (
                    <div className="mention-badge">
                      {channelUnreads.mentions > 9 ? '9+' : channelUnreads.mentions}
                    </div>
                  )}
                  {channelUnreads.mentions === 0 && channelUnreads.count > 0 && (
                    <div className="unread-badge">
                      {channelUnreads.count > 99 ? '99+' : channelUnreads.count}
                    </div>
                  )}
                  
                  {canDeleteChannel && channel && (
                    <button
                      onClick={(e) => { e.stopPropagation(); handleDeleteChannel(channel.id, channel.name); }}
                      className="channel-delete-btn"
                      title="Delete channel"
                    >
                      ×
                    </button>
                  )}
                </div>
              </div>
            );
          })}
          
          {/* Create Channel Button for Admins */}
          {selectedNodeId && hasPermission(selectedNodeId, 'CreateChannel') && (
            <div style={{ marginTop: '8px', padding: '0 8px' }}>
              {!showCreateChannelForm ? (
                <button onClick={() => setShowCreateChannelForm(true)} className="btn btn-green btn-sm" style={{ width: '100%' }}>
                  + Create Channel
                </button>
              ) : (
                <div className="create-channel-form">
                  <input type="text" placeholder="Channel name" value={newChannelName} onChange={(e) => setNewChannelName(e.target.value)} />
                  <select value={newChannelType} onChange={(e) => setNewChannelType(e.target.value)}>
                    <option value="text">Text Channel</option>
                    <option value="voice">Voice Channel</option>
                  </select>
                  <div className="create-channel-actions">
                    <button onClick={handleCreateChannel} className="btn btn-green btn-sm">Create</button>
                    <button onClick={() => { setShowCreateChannelForm(false); setNewChannelName(""); setNewChannelType("text"); }} className="btn btn-outline btn-sm">Cancel</button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Direct Messages Section */}
        <div className="dm-section">
          <div className="dm-header">
            Direct Messages
            <button onClick={() => setShowDmChannelCreate(!showDmChannelCreate)} className="dm-header-add-btn" title="Create DM">+</button>
          </div>
          
          <div className="dm-list">
            {dmChannels.map((dmChannel) => {
              const isActive = selectedDmChannel?.id === dmChannel.id;
              const dmUnreads = notificationManager.getChannelUnreads(`dm-${dmChannel.id}`, dmChannel.id);
              
              return (
                <div
                  key={dmChannel.id}
                  className={`dm-item ${isActive ? 'active' : ''}`}
                  onClick={() => handleDmChannelSelect(dmChannel)}
                >
                  <div className="dm-avatar">
                    {dmChannel.other_user_profile.display_name[0].toUpperCase()}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="dm-name">{dmChannel.other_user_profile.display_name}</div>
                    {dmChannel.last_message && (
                      <div className="dm-last-message">{dmChannel.last_message.content.substring(0, 30)}</div>
                    )}
                  </div>
                  
                  {/* Unread indicators */}
                  <div className="dm-badges">
                    {dmUnreads.mentions > 0 && (
                      <div className="mention-badge">
                        {dmUnreads.mentions > 9 ? '9+' : dmUnreads.mentions}
                      </div>
                    )}
                    {dmUnreads.mentions === 0 && dmUnreads.count > 0 && (
                      <div className="notification-dot" />
                    )}
                  </div>
                </div>
              );
            })}
            
            {dmChannels.length === 0 && (
              <div className="dm-empty">No direct messages yet</div>
            )}
          </div>
        </div>
        
        <div className="user-panel">
          <div className="user-avatar">
            {(appState.user?.display_name || fingerprint(appState.user?.public_key_hash || ''))?.[0] || "U"}
          </div>
          <div className="user-info">
            <div className="username">{appState.user?.display_name || fingerprint(appState.user?.public_key_hash || '') || "You"}</div>
            <div className="user-status">
              {appState.isConnected ? "Online" : "Offline"}
            </div>
          </div>
          <button
            onClick={() => setShowNotificationSettings(true)}
            className="user-panel-settings"
            title="Notification Settings"
          >
            🔔
          </button>
          <button
            onClick={() => setShowSettings(true)}
            className="user-panel-settings"
            title="Settings (Ctrl+,)"
          >
            ⚙️
          </button>
          <button onClick={handleLogout} className="user-panel-logout">Logout</button>
        </div>
      </div>

      {/* Main chat area */}
      <div className="chat-area">
      <FileDropZone
        channelId={selectedDmChannel?.id || selectedChannelId || ''}
        token={appState.token || ''}
        keyPair={keyPair}
        encryptionEnabled={encryptionEnabled}
      >
        <div className="chat-header">
          <div className="chat-header-left">
            {selectedDmChannel ? (
              <>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <div className="dm-avatar" style={{ width: '24px', height: '24px', fontSize: '12px', marginRight: '8px' }}>
                    {selectedDmChannel.other_user_profile.display_name[0].toUpperCase()}
                  </div>
                  <span className="chat-channel-name">{selectedDmChannel.other_user_profile.display_name}</span>
                </div>
                <span className="chat-topic">
                  Direct message with {selectedDmChannel.other_user_profile.display_name}
                </span>
              </>
            ) : (
              <>
                <span className="chat-channel-name">{activeChannel}</span>
                <span className="chat-topic">Welcome to {activeChannel}!</span>
              </>
            )}
          </div>
          <div className="chat-header-right">
            <button onClick={togglePinnedPanel} className={`chat-header-btn ${showPinnedPanel ? 'active' : ''}`} title="Toggle pinned messages">📌</button>
            {encryptionEnabled && keyPair && (
              <span className="e2ee-badge enabled" title="End-to-end encryption enabled">🔐 E2EE</span>
            )}
            {encryptionEnabled && !keyPair && (
              <span className="e2ee-badge warning" title="Encryption not available">🔓 No Keys</span>
            )}
            {!encryptionEnabled && (
              <span className="e2ee-badge disabled" title="Encryption not supported">🚫 No E2EE</span>
            )}
            <button
              className="search-button"
              onClick={() => setShowSearchOverlay(true)}
              title="Search messages (Ctrl+K)"
            >
              🔍
            </button>
          </div>
        </div>
        <div 
          className={`messages ${voiceChannelId ? 'with-voice' : ''} density-${messageDensity}`}
          ref={messagesContainerRef}
          onScroll={handleScroll}
        >
          {isLoadingOlderMessages && (
            <div className="messages-loading"><span className="spinner spinner-sm"></span> Loading older messages...</div>
          )}
          {!hasMoreMessages && appState.messages.length > 0 && (
            <div className="messages-beginning">You've reached the beginning of this channel</div>
          )}
          {!isLoadingOlderMessages && appState.messages.length === 0 && selectedChannelId && (
            <div className="empty-state">
              <div className="empty-state-icon">💬</div>
              <div className="empty-state-title">No messages yet</div>
              <div className="empty-state-text">Be the first to send a message in this channel!</div>
            </div>
          )}
          {!selectedChannelId && !selectedDmChannel && channels.length === 0 && nodes.length > 0 && (
            <div className="empty-state">
              <div className="empty-state-icon">#</div>
              <div className="empty-state-title">No channels</div>
              <div className="empty-state-text">Create a channel to start chatting.</div>
            </div>
          )}
          {nodes.length === 0 && !selectedDmChannel && (
            <div className="empty-state">
              <div className="empty-state-icon">⚡</div>
              <div className="empty-state-title">Welcome to Accord</div>
              <div className="empty-state-text">Join a node via invite or create your own to get started.</div>
            </div>
          )}
          {appState.messages.map((msg, i) => (
            <div key={msg.id || i} className={`message ${msg.reply_to ? 'reply-message' : ''}`} data-message-id={msg.id}>
              {/* Reply preview if this message is a reply */}
              {msg.replied_message && (
                <div className="reply-preview" onClick={() => scrollToMessage(msg.reply_to!)}>
                  <div className="reply-bar"></div>
                  <div className="reply-content">
                    <span className="reply-author">Replying to {fingerprint(msg.replied_message.sender_public_key_hash)}</span>
                    <span className="reply-snippet">{msg.replied_message.content || msg.replied_message.encrypted_payload.substring(0, 50) + '...'}</span>
                  </div>
                </div>
              )}
              <div className="message-avatar">{msg.author[0]}</div>
              <div className="message-body">
                <div className="message-header">
                  <span className="message-author" onContextMenu={(e) => {
                    // Find the member who authored this message
                    const authorMember = members.find(m => displayName(m.user) === msg.author || fingerprint(m.public_key_hash) === msg.author);
                    if (authorMember) {
                      handleContextMenu(e, authorMember.user_id, authorMember.public_key_hash, msg.author, authorMember.profile?.bio, authorMember.user);
                    }
                  }}>{msg.author}</span>
                  <span className="message-time">{msg.time}</span>
                  {msg.edited_at && (
                    <span className="message-edited" title={`Edited at ${new Date(msg.edited_at).toLocaleString()}`}>(edited)</span>
                  )}
                  {msg.isEncrypted && (
                    <span className="message-encrypted-badge" title="End-to-end encrypted">🔒</span>
                  )}
                  {msg.pinned_at && (
                    <span className="message-pinned-badge" title={`Pinned ${new Date(msg.pinned_at).toLocaleString()}`}>📌</span>
                  )}
                  {/* Message Actions - Show on hover for all users */}
                  {appState.user && (
                    <div className="message-actions">
                      {/* Reply button for all users */}
                      <button
                        onClick={() => handleReply(msg)}
                        className="message-action-btn"
                        title="Reply to message"
                      >
                        💬
                      </button>
                      {msg.author === (appState.user.display_name || fingerprint(appState.user.public_key_hash)) && (
                        <button
                          onClick={() => handleStartEdit(msg.id, msg.content)}
                          className="message-action-btn"
                          title="Edit message"
                        >
                          ✏️
                        </button>
                      )}
                      {(msg.author === (appState.user.display_name || fingerprint(appState.user.public_key_hash)) || canDeleteMessage(msg)) && (
                        <button
                          onClick={() => setShowDeleteConfirm(msg.id)}
                          className="message-action-btn"
                          title="Delete message"
                        >
                          🗑️
                        </button>
                      )}
                      {/* Pin/Unpin button for admin/moderator users */}
                      {canDeleteMessage(msg) && (
                        <button
                          onClick={() => msg.pinned_at ? handleUnpinMessage(msg.id) : handlePinMessage(msg.id)}
                          className="message-action-btn"
                          title={msg.pinned_at ? "Unpin message" : "Pin message"}
                        >
                          {msg.pinned_at ? '📌' : '📌'}
                        </button>
                      )}
                    </div>
                  )}
                </div>
                {/* Editing Interface */}
                {editingMessageId === msg.id ? (
                  <div className="message-edit-container">
                    <input
                      type="text"
                      value={editingContent}
                      onChange={(e) => setEditingContent(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault();
                          handleSaveEdit();
                        } else if (e.key === 'Escape') {
                          handleCancelEdit();
                        }
                      }}
                      className="message-edit-input"
                      placeholder="Edit your message..."
                      autoFocus
                    />
                    <div className="message-edit-actions">
                      <button onClick={handleSaveEdit} className="edit-save-btn">
                        Save
                      </button>
                      <button onClick={handleCancelEdit} className="edit-cancel-btn">
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <div 
                    className="message-content"
                    dangerouslySetInnerHTML={{ 
                      __html: notificationManager.highlightMentions(msg.content) 
                    }}
                  />
                )}

                {/* File Attachments */}
                {msg.files && msg.files.length > 0 && (
                  <div className="message-attachments">
                    {msg.files.map((file) => (
                      <FileAttachment
                        key={file.id}
                        file={file}
                        token={appState.token || ''}
                        channelId={msg.channel_id || selectedDmChannel?.id || selectedChannelId || ''}
                        keyPair={keyPair}
                        encryptionEnabled={encryptionEnabled}
                      />
                    ))}
                  </div>
                )}

                {/* Message Reactions */}
                <div 
                  className="message-reactions-container"
                  onMouseEnter={() => setHoveredMessageId(msg.id)}
                  onMouseLeave={() => setHoveredMessageId(null)}
                >
                  {/* Existing reactions */}
                  {msg.reactions && msg.reactions.length > 0 && (
                    <div className="message-reactions">
                      {msg.reactions.map((reaction) => {
                        const userReacted = appState.user && reaction.users.includes(appState.user.id);
                        return (
                          <button
                            key={reaction.emoji}
                            className={`reaction ${userReacted ? 'reaction-user-reacted' : ''}`}
                            onClick={() => handleToggleReaction(msg.id, reaction.emoji)}
                            title={`${reaction.users.length} reactions`}
                          >
                            <span className="reaction-emoji">{reaction.emoji}</span>
                            <span className="reaction-count">{reaction.count}</span>
                          </button>
                        );
                      })}
                    </div>
                  )}

                  {/* Add reaction button - show on hover */}
                  {hoveredMessageId === msg.id && appState.user && (
                    <div className="add-reaction-container">
                      <button 
                        className="add-reaction-btn"
                        onClick={() => setShowEmojiPicker(showEmojiPicker === msg.id ? null : msg.id)}
                        title="Add reaction"
                      >
                        😊
                      </button>

                      {/* Emoji picker */}
                      {showEmojiPicker === msg.id && (
                        <div className="emoji-picker">
                          {COMMON_EMOJIS.map((emoji) => (
                            <button
                              key={emoji}
                              className="emoji-option"
                              onClick={() => handleAddReaction(msg.id, emoji)}
                              title={`React with ${emoji}`}
                            >
                              {emoji}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Delete Confirmation Dialog */}
                {showDeleteConfirm === msg.id && (
                  <div className="delete-confirm-overlay">
                    <div className="delete-confirm-dialog">
                      <p>Are you sure you want to delete this message?</p>
                      <div className="delete-confirm-actions">
                        <button 
                          onClick={() => handleDeleteMessage(msg.id)}
                          className="delete-confirm-btn"
                        >
                          Delete
                        </button>
                        <button 
                          onClick={() => setShowDeleteConfirm(null)}
                          className="delete-cancel-btn"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
          
        </div>
        {/* Typing indicator */}
        {selectedChannelId && formatTypingUsers(selectedChannelId) && (
          <div className="typing-indicator">
            <div className="typing-dots-animated">
              <span></span><span></span><span></span>
            </div>
            <span className="typing-text">{formatTypingUsers(selectedChannelId)}</span>
          </div>
        )}
        <div className="message-input-container">
          {/* Reply preview bar */}
          {replyingTo && (
            <div className="reply-input-preview">
              <div className="reply-input-bar"></div>
              <div className="reply-input-content">
                <span className="reply-input-text">
                  Replying to <strong>{replyingTo.author}</strong>: {replyingTo.content.substring(0, 100)}{replyingTo.content.length > 100 ? '...' : ''}
                </span>
                <button className="reply-cancel-btn" onClick={handleCancelReply} title="Cancel reply">×</button>
              </div>
            </div>
          )}
          {/* File attachment button */}
          {serverAvailable && appState.activeChannel && (
            <FileUploadButton
              channelId={appState.activeChannel}
              token={appState.token || ''}
              keyPair={keyPair}
              encryptionEnabled={encryptionEnabled}
            />
          )}
          <textarea
            className="message-input"
            placeholder={`Message ${activeChannel}`}
            value={message}
            rows={1}
            onChange={(e) => {
              setMessage(e.target.value);
              // Auto-resize textarea
              e.target.style.height = 'auto';
              e.target.style.height = Math.min(e.target.scrollHeight, 200) + 'px';
              // Send typing indicator when user types (throttled)
              if (selectedChannelId) {
                sendTypingIndicator(selectedChannelId);
              }
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleSendMessage();
              }
              // Shift+Enter: default behavior (newline in textarea)
            }}
          />
          {/* File list button */}
          {serverAvailable && appState.activeChannel && (
            <FileList
              channelId={appState.activeChannel}
              token={appState.token || ''}
              keyPair={keyPair}
              encryptionEnabled={encryptionEnabled}
            />
          )}
        </div>
      </FileDropZone>
      </div>

      {/* Voice Chat Component */}
      {voiceChannelId && (
        <VoiceChat
          ws={ws}
          currentUserId={localStorage.getItem('accord_user_id')}
          channelId={voiceChannelId}
          channelName={voiceChannelName}
          onLeave={() => {
            setVoiceChannelId(null);
            setVoiceChannelName("");
          }}
        />
      )}

      {/* Member sidebar */}
      <div className="member-sidebar">
        <div className="member-header">Members — {users.length}</div>
        {sortedMembers.length > 0 ? (
          sortedMembers.map((member) => {
            const currentUserId = localStorage.getItem('accord_user_id');
            const isCurrentUser = member.user_id === currentUserId;
            const presence = getPresenceStatus(member.user_id);
            const canKick = selectedNodeId && hasPermission(selectedNodeId, 'KickMembers') && !isCurrentUser;
            
            return (
              <div key={member.user.id} className={`member ${presence === 'offline' ? 'member-offline' : ''}`}
                onContextMenu={(e) => handleContextMenu(e, member.user_id, member.public_key_hash, displayName(member.user), member.profile?.bio, member.user)}
              >
                <div className="member-avatar-wrapper">
                  <div className="member-avatar">{displayName(member.user)[0]}</div>
                  <span className={`presence-dot presence-${presence}`} title={presence}></span>
                </div>
                <span className="member-name">{displayName(member.user)}</span>
                <span className="member-role-badge" title={member.role}>{getRoleBadge(member.role)}</span>
                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  {!isCurrentUser && (
                    <button onClick={(e) => { e.stopPropagation(); openDmWithUser(member.user); }} className="member-action-btn" title="Send DM">DM</button>
                  )}
                  {canKick && (
                    <button onClick={(e) => { e.stopPropagation(); handleKickMember(member.user_id, displayName(member.user)); }} className="member-action-btn danger" title="Kick member">Kick</button>
                  )}
                </div>
              </div>
            );
          })
        ) : members.length === 0 ? (
          <div className="members-empty">
            {nodes.length === 0 ? 'Join or create a node to see members' : 'No members loaded'}
          </div>
        ) : null}
      </div>

      {/* Error Message */}
      {error && (
        <div className="error-toast">
          <span style={{ flex: 1 }}>{error}</span>
          <button onClick={() => setError("")} className="error-toast-close">×</button>
        </div>
      )}

      {/* Create Node Modal */}
      {showCreateNodeModal && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3>Create a Node</h3>
            <p>A Node is your community space. A #general channel will be created automatically.</p>
            <div className="form-group">
              <label className="form-label">Node Name</label>
              <input type="text" placeholder="My Community" value={newNodeName} onChange={(e) => setNewNodeName(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') handleCreateNode(); }} className="form-input" />
            </div>
            <div className="form-group">
              <label className="form-label">Description (optional)</label>
              <input type="text" placeholder="What's this node about?" value={newNodeDescription} onChange={(e) => setNewNodeDescription(e.target.value)} className="form-input" />
            </div>
            <div className="modal-actions">
              <button onClick={handleCreateNode} disabled={creatingNode || !newNodeName.trim()} className="btn btn-green">{creatingNode ? 'Creating...' : 'Create Node'}</button>
              <button onClick={() => { setShowCreateNodeModal(false); setNewNodeName(""); setNewNodeDescription(""); }} className="btn btn-outline">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Invite Modal */}
      {showInviteModal && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3>Invite Link Generated</h3>
            <p>Share this invite link with others to let them join this node:</p>
            <div className="modal-code-block">{generatedInvite}</div>
            <div className="modal-actions">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(generatedInvite).then(() => {
                    alert('Invite code copied to clipboard!');
                  }).catch(() => {
                    const textArea = document.createElement('textarea');
                    textArea.value = generatedInvite;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    alert('Invite code copied to clipboard!');
                  });
                }}
                className="btn btn-primary" style={{ width: 'auto' }}
              >
                Copy
              </button>
              <button onClick={() => { setShowInviteModal(false); setGeneratedInvite(""); }} className="btn btn-outline" style={{ width: 'auto' }}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Search Overlay */}
      <SearchOverlay
        isVisible={showSearchOverlay}
        onClose={() => setShowSearchOverlay(false)}
        nodeId={selectedNodeId}
        channels={channels}
        token={appState.token || null}
        onNavigateToMessage={handleNavigateToMessage}
      />

      {/* Notification Settings Modal */}
      <NotificationSettings
        isOpen={showNotificationSettings}
        onClose={() => setShowNotificationSettings(false)}
        preferences={notificationPreferences}
        onPreferencesChange={handleNotificationPreferencesChange}
      />

      {/* Settings Modal */}
      <Settings
        isOpen={showSettings}
        onClose={() => setShowSettings(false)}
        currentUser={appState.user}
        onUserUpdate={(updates) => {
          // Update user state if needed
          if (appState.user) {
            setAppState(prev => ({
              ...prev,
              user: {
                ...prev.user!,
                ...updates
              }
            }));
          }
        }}
      />

      {/* Pinned Messages Panel */}
      {showPinnedPanel && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            right: 0,
            width: '400px',
            height: '100vh',
            background: 'var(--background)',
            borderLeft: '1px solid var(--border)',
            zIndex: 1000,
            display: 'flex',
            flexDirection: 'column',
            color: 'var(--text)',
          }}
        >
          {/* Panel Header */}
          <div
            style={{
              padding: '16px',
              borderBottom: '1px solid var(--border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600 }}>
              📌 Pinned Messages
            </h3>
            <button
              onClick={() => setShowPinnedPanel(false)}
              style={{
                background: 'none',
                border: 'none',
                fontSize: '18px',
                cursor: 'pointer',
                color: 'var(--text)',
                padding: '4px',
                borderRadius: '4px',
              }}
            >
              ✕
            </button>
          </div>

          {/* Pinned Messages List */}
          <div
            style={{
              flex: 1,
              overflowY: 'auto',
              padding: '16px',
            }}
          >
            {pinnedMessages.length === 0 ? (
              <div
                style={{
                  textAlign: 'center',
                  color: 'var(--text-muted)',
                  marginTop: '50px',
                }}
              >
                <div style={{ fontSize: '48px', marginBottom: '16px' }}>📌</div>
                <p>No pinned messages in this channel yet.</p>
                <p style={{ fontSize: '14px' }}>
                  Pin messages to keep important information easily accessible.
                </p>
              </div>
            ) : (
              <div>
                {pinnedMessages.map((msg, i) => (
                  <div
                    key={msg.id || i}
                    style={{
                      marginBottom: '16px',
                      padding: '12px',
                      background: 'var(--background-modifier-accent)',
                      borderRadius: '8px',
                      border: '1px solid var(--border)',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        marginBottom: '8px',
                        fontSize: '14px',
                      }}
                    >
                      <div
                        style={{
                          width: '24px',
                          height: '24px',
                          borderRadius: '50%',
                          background: 'var(--primary)',
                          color: 'white',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '12px',
                          fontWeight: 600,
                          marginRight: '8px',
                        }}
                      >
                        {msg.author[0]}
                      </div>
                      <span style={{ fontWeight: 600, marginRight: '8px' }}>
                        {msg.author}
                      </span>
                      <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                        {new Date(msg.timestamp).toLocaleDateString()} at {msg.time}
                      </span>
                    </div>
                    <div
                      style={{
                        marginLeft: '32px',
                        lineHeight: '1.4',
                      }}
                      dangerouslySetInnerHTML={{
                        __html: notificationManager.highlightMentions(msg.content),
                      }}
                    />
                    <div
                      style={{
                        marginLeft: '32px',
                        marginTop: '8px',
                        fontSize: '12px',
                        color: 'var(--text-muted)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                      }}
                    >
                      📌 Pinned {new Date(msg.pinned_at!).toLocaleDateString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* DM Channel Creation Modal */}
      {showDmChannelCreate && (
        <div className="modal-overlay">
          <div className="modal-card" style={{ maxWidth: '380px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ margin: 0 }}>Start a Direct Message</h3>
              <button onClick={() => setShowDmChannelCreate(false)} className="error-toast-close" style={{ color: 'var(--text-muted)' }}>×</button>
            </div>
            <p>Select a user to start a direct message:</p>
            <div style={{ maxHeight: '300px', overflow: 'auto' }}>
              {members
                .filter(member => member.user_id !== localStorage.getItem('accord_user_id'))
                .map((member) => (
                  <div
                    key={member.user_id}
                    className="member"
                    onClick={() => { openDmWithUser(member.user); setShowDmChannelCreate(false); }}
                  >
                    <div className="dm-avatar" style={{ width: '24px', height: '24px', fontSize: '12px', marginRight: '12px' }}>
                      {displayName(member.user)[0].toUpperCase()}
                    </div>
                    <div>
                      <div style={{ color: 'var(--text-primary)', fontSize: '14px', fontWeight: '500' }}>{displayName(member.user)}</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{getRoleBadge(member.role)} {member.role}</div>
                    </div>
                  </div>
                ))}
              {members.filter(member => member.user_id !== localStorage.getItem('accord_user_id')).length === 0 && (
                <div className="members-empty">No other members available</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Display Name Prompt Modal */}
      {showDisplayNamePrompt && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3>Set Your Display Name</h3>
            <p>Choose a name that others will see instead of your fingerprint.</p>
            <div className="form-group">
              <label className="form-label">Display Name</label>
              <input
                type="text"
                placeholder="Enter a display name..."
                value={displayNameInput}
                onChange={(e) => setDisplayNameInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') handleSaveDisplayName(); }}
                className="form-input"
                autoFocus
                maxLength={32}
              />
            </div>
            <div className="modal-actions">
              <button
                onClick={handleSaveDisplayName}
                disabled={displayNameSaving || !displayNameInput.trim()}
                className="btn btn-green"
                style={{ width: 'auto' }}
              >
                {displayNameSaving ? 'Saving...' : 'Save'}
              </button>
              <button
                onClick={() => setShowDisplayNamePrompt(false)}
                className="btn btn-outline"
                style={{ width: 'auto' }}
              >
                Skip
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Context Menu */}
      {contextMenu && (
        <div className="context-menu" style={{ left: contextMenu.x, top: contextMenu.y }}>
          <div className="context-menu-item context-menu-profile-header">
            <div style={{ fontWeight: 600, fontSize: '14px' }}>{contextMenu.displayName}</div>
            <div style={{ fontSize: '11px', color: 'var(--text-faint)', fontFamily: 'var(--font-mono)' }}>{fingerprint(contextMenu.publicKeyHash)}</div>
            {contextMenu.bio && <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>{contextMenu.bio}</div>}
          </div>
          <div className="context-menu-separator"></div>
          <div className="context-menu-item" onClick={() => {
            // View profile - show alert with details for now
            const info = `Display Name: ${contextMenu.displayName}\nFingerprint: ${fingerprint(contextMenu.publicKeyHash)}\nFull Hash: ${contextMenu.publicKeyHash}${contextMenu.bio ? `\nBio: ${contextMenu.bio}` : ''}`;
            alert(info);
            setContextMenu(null);
          }}>👤 View Profile</div>
          {contextMenu.user && contextMenu.userId !== localStorage.getItem('accord_user_id') && (
            <div className="context-menu-item" onClick={() => {
              if (contextMenu.user) openDmWithUser(contextMenu.user);
              setContextMenu(null);
            }}>💬 Send DM</div>
          )}
          <div className="context-menu-separator"></div>
          <div className="context-menu-item" onClick={() => {
            navigator.clipboard.writeText(contextMenu.publicKeyHash).catch(() => {});
            setContextMenu(null);
          }}>📋 Copy Public Key Hash</div>
        </div>
      )}

      {/* Keyboard Shortcuts Help Modal */}
      {showShortcutsHelp && (
        <div className="modal-overlay" onClick={() => setShowShortcutsHelp(false)}>
          <div className="modal-card shortcuts-modal" onClick={(e) => e.stopPropagation()}>
            <h3>⌨️ Keyboard Shortcuts</h3>
            <div className="shortcuts-list">
              <div className="shortcut-row"><kbd>Enter</kbd><span>Send message</span></div>
              <div className="shortcut-row"><kbd>Shift + Enter</kbd><span>New line in message</span></div>
              <div className="shortcut-row"><kbd>Escape</kbd><span>Close modal / Cancel edit</span></div>
              <div className="shortcut-row"><kbd>Ctrl + K</kbd><span>Open search</span></div>
              <div className="shortcut-row"><kbd>Ctrl + /</kbd><span>Show this help</span></div>
              <div className="shortcut-row"><kbd>Ctrl + ,</kbd><span>Open settings</span></div>
            </div>
            <div className="modal-actions" style={{ marginTop: '16px' }}>
              <button onClick={() => setShowShortcutsHelp(false)} className="btn btn-outline" style={{ width: 'auto' }}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;