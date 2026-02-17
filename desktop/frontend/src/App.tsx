import React, { useState, useEffect, useCallback, useRef } from "react";
import { api, parseInviteLink, storeRelayToken, storeRelayUserId, getRelayToken, getRelayUserId } from "./api";
import { AccordWebSocket } from "./ws";
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
import { FileUploadButton, FileList } from "./FileManager";
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
    
    if (tusers.length === 0) return '';
    if (tusers.length === 1) return `${tusers[0].displayName} is typing...`;
    if (tusers.length === 2) return `${tusers[0].displayName} and ${tusers[1].displayName} are typing...`;
    return `${tusers[0].displayName}, ${tusers[1].displayName} and ${tusers.length - 2} other${tusers.length > 3 ? 's' : ''} are typing...`;
  }, [typingUsers]);

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
    });

    socket.on('disconnected', () => {
      setAppState(prev => ({ ...prev, isConnected: false }));
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

  // Handle channel selection
  const handleChannelSelect = useCallback((channelId: string, channelName: string) => {
    setSelectedChannelId(channelId);
    setActiveChannel(channelName);
    setAppState(prev => ({ ...prev, activeChannel: channelId }));
    
    // Mark channel as read in notification system
    if (selectedNodeId) {
      // Get the latest message ID to mark as read
      const latestMessage = appState.messages.length > 0 ? 
        appState.messages[appState.messages.length - 1] : null;
      
      notificationManager.markChannelAsRead(selectedNodeId, channelId, latestMessage?.id);
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

  // Keyboard shortcuts for search and settings
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey && (e.key === 'k' || e.key === 'f')) || 
          (e.metaKey && (e.key === 'k' || e.key === 'f'))) {
        e.preventDefault();
        setShowSearchOverlay(true);
      }
      if ((e.ctrlKey && e.key === ',') || (e.metaKey && e.key === ',')) {
        e.preventDefault();
        setShowSettings(true);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

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
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', background: '#2c2f33', color: '#ffffff' }}>
          <div style={{ background: '#36393f', padding: '2rem', borderRadius: '8px', width: '500px', maxWidth: '90vw' }}>
            <h2 style={{ textAlign: 'center', marginBottom: '1rem' }}>🔑 Backup Your Key</h2>
            <p style={{ color: '#b9bbbe', marginBottom: '1rem', fontSize: '0.9rem' }}>
              Your identity is your keypair. If you lose it, you lose access to your account forever. 
              <strong style={{ color: '#faa61a' }}> There is no recovery.</strong>
            </p>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ fontSize: '0.8rem', color: '#b9bbbe', display: 'block', marginBottom: '0.3rem' }}>Your Public Key Fingerprint:</label>
              <div style={{ background: '#40444b', padding: '0.6rem', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.85rem', wordBreak: 'break-all' }}>
                {publicKeyHash || 'computing...'}
              </div>
            </div>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ fontSize: '0.8rem', color: '#b9bbbe', display: 'block', marginBottom: '0.3rem' }}>Public Key (share this):</label>
              <textarea
                readOnly
                value={publicKey}
                rows={3}
                style={{ width: '100%', background: '#40444b', color: '#ffffff', border: 'none', borderRadius: '4px', padding: '0.6rem', fontFamily: 'monospace', fontSize: '0.75rem', resize: 'none' }}
              />
            </div>
            <p style={{ color: '#43b581', fontSize: '0.85rem', marginBottom: '1rem' }}>
              ✅ Your keypair is saved in this browser's storage. To use Accord on another device, you'll need to export and import your key.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(publicKey).catch(() => {});
                  alert('Public key copied to clipboard!');
                }}
                style={{ flex: 1, padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#43b581', color: '#ffffff', fontSize: '1rem', cursor: 'pointer' }}
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
                style={{ flex: 1, padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#7289da', color: '#ffffff', fontSize: '1rem', cursor: 'pointer' }}
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
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', background: '#2c2f33', color: '#ffffff' }}>
          <div style={{ background: '#36393f', padding: '2rem', borderRadius: '8px', width: '450px', maxWidth: '90vw' }}>
            
            {welcomeMode === 'choose' && (
              <>
                <h2 style={{ textAlign: 'center', marginBottom: '0.5rem' }}>Welcome to Accord</h2>
                <p style={{ textAlign: 'center', color: '#b9bbbe', marginBottom: '2rem', fontSize: '0.9rem' }}>
                  Private, encrypted communication
                </p>
                
                <button
                  onClick={() => setWelcomeMode('invite')}
                  style={{ width: '100%', padding: '1rem', borderRadius: '4px', border: 'none', background: '#7289da', color: '#ffffff', fontSize: '1rem', cursor: 'pointer', marginBottom: '0.75rem' }}
                >
                  I have an invite link
                </button>
                
                <button
                  onClick={() => setWelcomeMode('admin')}
                  style={{ width: '100%', padding: '0.8rem', borderRadius: '4px', border: '1px solid #4f545c', background: 'transparent', color: '#b9bbbe', fontSize: '0.9rem', cursor: 'pointer' }}
                >
                  Set up a new relay (admin)
                </button>
              </>
            )}

            {welcomeMode === 'invite' && !inviteNeedsRegister && (
              <>
                <button onClick={() => { setWelcomeMode('choose'); setInviteError(''); setInviteLinkInput(''); setParsedInvite(null); setInviteRelayVersion(''); }} style={{ background: 'none', border: 'none', color: '#7289da', cursor: 'pointer', fontSize: '0.85rem', marginBottom: '1rem' }}>← Back</button>
                <h2 style={{ textAlign: 'center', marginBottom: '0.5rem' }}>Join via Invite</h2>
                <p style={{ textAlign: 'center', color: '#b9bbbe', marginBottom: '1.5rem', fontSize: '0.85rem' }}>
                  Paste the invite link you received
                </p>
                
                <div style={{ marginBottom: '1rem' }}>
                  <input
                    type="text"
                    placeholder="accord://host:port/invite/CODE or https://..."
                    value={inviteLinkInput}
                    onChange={(e) => setInviteLinkInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleInviteLinkSubmit(); }}
                    style={{ width: '100%', padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#40444b', color: '#ffffff', fontSize: '0.95rem' }}
                  />
                </div>

                {inviteError && (
                  <div style={{ color: '#f04747', marginBottom: '1rem', fontSize: '0.9rem' }}>{inviteError}</div>
                )}

                {inviteRelayVersion && (
                  <div style={{ color: '#43b581', marginBottom: '1rem', fontSize: '0.85rem' }}>✅ Connected to relay v{inviteRelayVersion}</div>
                )}

                <button
                  onClick={handleInviteLinkSubmit}
                  disabled={inviteConnecting || !inviteLinkInput.trim()}
                  style={{ width: '100%', padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#7289da', color: '#ffffff', fontSize: '1rem', cursor: 'pointer', opacity: (inviteConnecting || !inviteLinkInput.trim()) ? 0.6 : 1 }}
                >
                  {inviteConnecting ? 'Connecting to relay...' : 'Join'}
                </button>
              </>
            )}

            {welcomeMode === 'invite' && inviteNeedsRegister && (
              <>
                <h2 style={{ textAlign: 'center', marginBottom: '0.5rem' }}>Create Your Identity</h2>
                <p style={{ textAlign: 'center', color: '#b9bbbe', marginBottom: '0.5rem', fontSize: '0.85rem' }}>
                  Connected to relay — now set a password to create your identity
                </p>
                <div style={{ background: '#2f3136', padding: '0.6rem', borderRadius: '4px', marginBottom: '1rem', fontSize: '0.8rem', color: '#43b581' }}>
                  🔐 A keypair will be auto-generated. No username needed.
                </div>

                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ fontSize: '0.8rem', color: '#b9bbbe', display: 'block', marginBottom: '0.3rem' }}>Password (min 8 characters)</label>
                  <input
                    type="password"
                    placeholder="Choose a password"
                    value={invitePassword}
                    onChange={(e) => setInvitePassword(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleInviteRegister(); }}
                    style={{ width: '100%', padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#40444b', color: '#ffffff', fontSize: '1rem' }}
                  />
                </div>

                {inviteError && (
                  <div style={{ color: '#f04747', marginBottom: '1rem', fontSize: '0.9rem' }}>{inviteError}</div>
                )}

                <button
                  onClick={handleInviteRegister}
                  disabled={inviteJoining || invitePassword.length < 8}
                  style={{ width: '100%', padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#43b581', color: '#ffffff', fontSize: '1rem', cursor: 'pointer', opacity: (inviteJoining || invitePassword.length < 8) ? 0.6 : 1 }}
                >
                  {inviteJoining ? 'Creating identity & joining...' : 'Create Identity & Join'}
                </button>
              </>
            )}

            {welcomeMode === 'admin' && (
              <>
                <button onClick={() => { setWelcomeMode('choose'); setAuthError(''); }} style={{ background: 'none', border: 'none', color: '#7289da', cursor: 'pointer', fontSize: '0.85rem', marginBottom: '1rem' }}>← Back</button>
                <h2 style={{ textAlign: 'center', marginBottom: '0.5rem' }}>Connect to Relay</h2>
                <p style={{ textAlign: 'center', color: '#b9bbbe', marginBottom: '1.5rem', fontSize: '0.85rem' }}>
                  Enter the relay server URL (admin/power-user)
                </p>
                
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ fontSize: '0.8rem', color: '#b9bbbe', display: 'block', marginBottom: '0.3rem' }}>Server URL</label>
                  <input
                    type="text"
                    placeholder="http://localhost:8080"
                    value={serverUrl}
                    onChange={(e) => setServerUrl(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleServerConnect(); }}
                    style={{ width: '100%', padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#40444b', color: '#ffffff', fontSize: '1rem' }}
                  />
                </div>

                {authError && (
                  <div style={{ color: '#f04747', marginBottom: '1rem', fontSize: '0.9rem' }}>{authError}</div>
                )}

                {serverVersion && (
                  <div style={{ color: '#43b581', marginBottom: '1rem', fontSize: '0.85rem' }}>✅ Connected — server v{serverVersion}</div>
                )}

                <button
                  onClick={handleServerConnect}
                  disabled={serverConnecting}
                  style={{ width: '100%', padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#7289da', color: '#ffffff', fontSize: '1rem', cursor: 'pointer', opacity: serverConnecting ? 0.6 : 1 }}
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
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', background: '#2c2f33', color: '#ffffff' }}>
          <div style={{ background: '#36393f', padding: '2rem', borderRadius: '8px', width: '400px', maxWidth: '90vw' }}>
            <h2 style={{ textAlign: 'center', marginBottom: '0.5rem' }}>Connect to Relay</h2>
            <p style={{ textAlign: 'center', color: '#b9bbbe', marginBottom: '1.5rem', fontSize: '0.9rem' }}>Manual relay connection</p>
            
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ fontSize: '0.8rem', color: '#b9bbbe', display: 'block', marginBottom: '0.3rem' }}>Server URL</label>
              <input
                type="text"
                placeholder="http://localhost:8080"
                value={serverUrl}
                onChange={(e) => setServerUrl(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') handleServerConnect(); }}
                style={{ width: '100%', padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#40444b', color: '#ffffff', fontSize: '1rem' }}
              />
            </div>

            {authError && (
              <div style={{ color: '#f04747', marginBottom: '1rem', fontSize: '0.9rem' }}>{authError}</div>
            )}

            {serverVersion && (
              <div style={{ color: '#43b581', marginBottom: '1rem', fontSize: '0.85rem' }}>✅ Connected — server v{serverVersion}</div>
            )}

            <button
              onClick={handleServerConnect}
              disabled={serverConnecting}
              style={{ width: '100%', padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#7289da', color: '#ffffff', fontSize: '1rem', cursor: 'pointer', marginBottom: '0.5rem', opacity: serverConnecting ? 0.6 : 1 }}
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
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', background: '#2c2f33', color: '#ffffff' }}>
          <div style={{ background: '#36393f', padding: '2rem', borderRadius: '8px', width: '450px', maxWidth: '90vw' }}>
            <h2 style={{ textAlign: 'center', marginBottom: '0.5rem' }}>
              {isLoginMode ? 'Login to Accord' : 'Create Identity'}
            </h2>
            <p style={{ textAlign: 'center', color: '#b9bbbe', marginBottom: '1.5rem', fontSize: '0.85rem' }}>
              {isLoginMode 
                ? 'Authenticate with your keypair and password' 
                : 'A new keypair will be generated automatically'}
            </p>
            
            <div style={{ background: '#2f3136', padding: '0.6rem', borderRadius: '4px', marginBottom: '1rem', fontSize: '0.8rem', color: '#b9bbbe' }}>
              🔗 {serverUrl} {serverAvailable && <span style={{ color: '#43b581' }}>● connected</span>}
              <button onClick={() => { setShowWelcomeScreen(true); setWelcomeMode('choose'); setAuthError(''); }} style={{ float: 'right', background: 'none', border: 'none', color: '#7289da', cursor: 'pointer', fontSize: '0.8rem' }}>Change</button>
            </div>

            {isLoginMode && (
              <div style={{ marginBottom: '1rem' }}>
                <label style={{ fontSize: '0.8rem', color: '#b9bbbe', display: 'block', marginBottom: '0.3rem' }}>
                  Key Status
                </label>
                <div style={{ background: '#40444b', padding: '0.6rem', borderRadius: '4px', fontSize: '0.85rem' }}>
                  {keyPair || publicKey ? (
                    <span style={{ color: '#43b581' }}>🔑 Keypair loaded from browser storage</span>
                  ) : (
                    <span style={{ color: '#faa61a' }}>⚠️ No keypair found — register or import</span>
                  )}
                </div>
              </div>
            )}

            <div style={{ marginBottom: '1rem' }}>
              <label style={{ fontSize: '0.8rem', color: '#b9bbbe', display: 'block', marginBottom: '0.3rem' }}>Password</label>
              <input
                type="password"
                placeholder={isLoginMode ? "Enter your password" : "Choose a password (min 8 chars)"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') handleAuth(); }}
                style={{ width: '100%', padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#40444b', color: '#ffffff', fontSize: '1rem' }}
              />
              {!isLoginMode && password && password.length < 8 && (
                <div style={{ fontSize: '0.8rem', color: '#f04747', marginTop: '0.3rem' }}>
                  Password must be at least 8 characters
                </div>
              )}
            </div>

            {!isLoginMode && encryptionEnabled && (
              <div style={{ marginBottom: '1rem', background: '#2f3136', padding: '0.6rem', borderRadius: '4px' }}>
                <div style={{ fontSize: '0.8rem', color: '#43b581' }}>
                  🔐 A new ECDH P-256 keypair will be generated for your identity
                </div>
                <div style={{ fontSize: '0.75rem', color: '#b9bbbe', marginTop: '0.3rem' }}>
                  No username needed — you are identified by your public key hash
                </div>
              </div>
            )}

            {authError && (
              <div style={{ color: '#f04747', marginBottom: '1rem', fontSize: '0.9rem' }}>{authError}</div>
            )}

            <button
              onClick={handleAuth}
              style={{ width: '100%', padding: '0.8rem', borderRadius: '4px', border: 'none', background: '#7289da', color: '#ffffff', fontSize: '1rem', cursor: 'pointer', marginBottom: '1rem' }}
            >
              {isLoginMode ? 'Login' : 'Create Identity & Register'}
            </button>

            <div style={{ textAlign: 'center' }}>
              <button
                onClick={() => { setIsLoginMode(!isLoginMode); setAuthError(""); setPassword(""); }}
                style={{ background: 'none', border: 'none', color: '#7289da', cursor: 'pointer', textDecoration: 'underline' }}
              >
                {isLoginMode ? 'Need to create an identity?' : 'Already have a keypair? Login'}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

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
        <div className="sidebar-header" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              {servers[activeServer]}
              {appState.isConnected && (
                <span style={{ fontSize: '10px', color: '#43b581', marginLeft: '8px' }}>●</span>
              )}
              {!serverAvailable && (
                <span style={{ fontSize: '10px', color: '#faa61a', marginLeft: '8px' }}>DEMO</span>
              )}
            </div>
            
            {/* Admin/Moderator Controls */}
            {selectedNodeId && (hasPermission(selectedNodeId, 'ManageInvites') || hasPermission(selectedNodeId, 'ManageNode')) && (
              <div style={{ display: 'flex', gap: '4px' }}>
                {hasPermission(selectedNodeId, 'ManageInvites') && (
                  <button
                    onClick={handleGenerateInvite}
                    style={{
                      background: '#7289da',
                      border: 'none',
                      color: '#ffffff',
                      padding: '2px 6px',
                      borderRadius: '2px',
                      cursor: 'pointer',
                      fontSize: '10px'
                    }}
                    title="Generate Invite"
                  >
                    Invite
                  </button>
                )}
                {hasPermission(selectedNodeId, 'ManageNode') && (
                  <button
                    onClick={() => alert('Node settings coming soon!')}
                    style={{
                      background: '#f04747',
                      border: 'none',
                      color: '#ffffff',
                      padding: '2px 6px',
                      borderRadius: '2px',
                      cursor: 'pointer',
                      fontSize: '10px'
                    }}
                    title="Node Settings"
                  >
                    Settings
                  </button>
                )}
              </div>
            )}
          </div>
          
          {/* Show current user's role */}
          {selectedNodeId && userRoles[selectedNodeId] && (
            <div style={{ fontSize: '11px', color: '#b9bbbe', opacity: 0.8 }}>
              {getRoleBadge(userRoles[selectedNodeId])} {userRoles[selectedNodeId]}
            </div>
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
            
            return (
              <div
                key={channel?.id || ch}
                className={`channel ${isActive ? "active" : ""}`}
                style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'space-between',
                  background: isConnectedToVoice ? 'rgba(67, 181, 129, 0.2)' : undefined
                }}
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
                    channelUnreads.count > 9 ? (
                      <div className="notification-badge">9+</div>
                    ) : (
                      <div className="notification-dot" />
                    )
                  )}
                  
                  {canDeleteChannel && channel && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteChannel(channel.id, channel.name);
                      }}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#f04747',
                        cursor: 'pointer',
                        fontSize: '12px',
                        padding: '2px 4px',
                        borderRadius: '2px',
                        opacity: 0.7,
                        marginLeft: '4px'
                      }}
                      title="Delete channel"
                      onMouseEnter={(e) => e.currentTarget.style.opacity = '1'}
                      onMouseLeave={(e) => e.currentTarget.style.opacity = '0.7'}
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
            <div style={{ marginTop: '8px', padding: '0 16px' }}>
              {!showCreateChannelForm ? (
                <button
                  onClick={() => setShowCreateChannelForm(true)}
                  style={{
                    background: '#43b581',
                    border: 'none',
                    color: '#ffffff',
                    padding: '6px 12px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontSize: '12px',
                    width: '100%'
                  }}
                >
                  + Create Channel
                </button>
              ) : (
                <div style={{ 
                  background: '#40444b', 
                  padding: '8px', 
                  borderRadius: '4px',
                  marginBottom: '8px'
                }}>
                  <input
                    type="text"
                    placeholder="Channel name"
                    value={newChannelName}
                    onChange={(e) => setNewChannelName(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '4px 8px',
                      marginBottom: '4px',
                      border: 'none',
                      borderRadius: '2px',
                      background: '#36393f',
                      color: '#ffffff',
                      fontSize: '12px'
                    }}
                  />
                  <select
                    value={newChannelType}
                    onChange={(e) => setNewChannelType(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '4px 8px',
                      marginBottom: '4px',
                      border: 'none',
                      borderRadius: '2px',
                      background: '#36393f',
                      color: '#ffffff',
                      fontSize: '12px'
                    }}
                  >
                    <option value="text">Text Channel</option>
                    <option value="voice">Voice Channel</option>
                  </select>
                  <div style={{ display: 'flex', gap: '4px' }}>
                    <button
                      onClick={handleCreateChannel}
                      style={{
                        flex: 1,
                        background: '#43b581',
                        border: 'none',
                        color: '#ffffff',
                        padding: '4px 8px',
                        borderRadius: '2px',
                        cursor: 'pointer',
                        fontSize: '11px'
                      }}
                    >
                      Create
                    </button>
                    <button
                      onClick={() => {
                        setShowCreateChannelForm(false);
                        setNewChannelName("");
                        setNewChannelType("text");
                      }}
                      style={{
                        flex: 1,
                        background: '#747f8d',
                        border: 'none',
                        color: '#ffffff',
                        padding: '4px 8px',
                        borderRadius: '2px',
                        cursor: 'pointer',
                        fontSize: '11px'
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Direct Messages Section */}
        <div className="dm-section" style={{ borderTop: '1px solid #3f4147', paddingTop: '8px', marginTop: '8px' }}>
          <div className="dm-header" style={{ 
            fontSize: '11px', 
            color: '#b9bbbe', 
            textTransform: 'uppercase', 
            fontWeight: '600', 
            marginBottom: '8px',
            padding: '0 16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between'
          }}>
            Direct Messages
            <button
              onClick={() => setShowDmChannelCreate(!showDmChannelCreate)}
              style={{
                background: 'none',
                border: 'none',
                color: '#b9bbbe',
                cursor: 'pointer',
                fontSize: '12px',
                padding: '2px',
                borderRadius: '2px'
              }}
              title="Create DM"
            >
              +
            </button>
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
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '6px 16px',
                    cursor: 'pointer',
                    backgroundColor: isActive ? '#40444b' : 'transparent',
                    borderRadius: '4px',
                    margin: '0 8px',
                    marginBottom: '2px'
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive) e.currentTarget.style.backgroundColor = '#36393f';
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive) e.currentTarget.style.backgroundColor = 'transparent';
                  }}
                >
                  <div 
                    className="dm-avatar"
                    style={{
                      width: '20px',
                      height: '20px',
                      borderRadius: '50%',
                      backgroundColor: '#5865f2',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      marginRight: '8px',
                      fontSize: '10px',
                      fontWeight: '600',
                      color: '#ffffff'
                    }}
                  >
                    {dmChannel.other_user_profile.display_name[0].toUpperCase()}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div 
                      className="dm-name"
                      style={{
                        fontSize: '14px',
                        color: isActive ? '#ffffff' : '#b9bbbe',
                        fontWeight: isActive ? '500' : '400',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis'
                      }}
                    >
                      {dmChannel.other_user_profile.display_name}
                    </div>
                    {dmChannel.last_message && (
                      <div 
                        style={{
                          fontSize: '11px',
                          color: '#8e9297',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis'
                        }}
                      >
                        {dmChannel.last_message.content.substring(0, 30)}
                      </div>
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
              <div style={{ 
                padding: '16px', 
                color: '#8e9297', 
                fontSize: '13px', 
                textAlign: 'center' 
              }}>
                No direct messages yet
              </div>
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
          <button
            onClick={handleLogout}
            style={{
              background: 'none',
              border: 'none',
              color: '#b9bbbe',
              cursor: 'pointer',
              fontSize: '12px'
            }}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Main chat area */}
      <div className="chat-area">
        <div className="chat-header">
          <div className="chat-header-left">
            {selectedDmChannel ? (
              <>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <div 
                    className="dm-avatar"
                    style={{
                      width: '24px',
                      height: '24px',
                      borderRadius: '50%',
                      backgroundColor: '#5865f2',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      marginRight: '8px',
                      fontSize: '12px',
                      fontWeight: '600',
                      color: '#ffffff'
                    }}
                  >
                    {selectedDmChannel.other_user_profile.display_name[0].toUpperCase()}
                  </div>
                  <span className="chat-channel-name">
                    {selectedDmChannel.other_user_profile.display_name}
                  </span>
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
            <button
              onClick={togglePinnedPanel}
              style={{
                background: 'none',
                border: 'none',
                fontSize: '18px',
                cursor: 'pointer',
                color: showPinnedPanel ? '#faa61a' : '#666',
                marginRight: '12px',
                padding: '4px',
                borderRadius: '4px',
                transition: 'color 0.2s'
              }}
              title="Toggle pinned messages"
            >
              📌
            </button>
            {encryptionEnabled && keyPair && (
              <span 
                style={{ 
                  fontSize: '12px', 
                  color: '#43b581',
                  marginRight: '16px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
                title="End-to-end encryption enabled"
              >
                🔐 E2EE
              </span>
            )}
            {encryptionEnabled && !keyPair && (
              <span 
                style={{ 
                  fontSize: '12px', 
                  color: '#faa61a',
                  marginRight: '16px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
                title="Encryption not available"
              >
                🔓 No Keys
              </span>
            )}
            {!encryptionEnabled && (
              <span 
                style={{ 
                  fontSize: '12px', 
                  color: '#747f8d',
                  marginRight: '16px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
                title="Encryption not supported"
              >
                🚫 No E2EE
              </span>
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
          className={`messages ${voiceChannelId ? 'with-voice' : ''}`}
          ref={messagesContainerRef}
          onScroll={handleScroll}
        >
          {isLoadingOlderMessages && (
            <div style={{
              textAlign: 'center',
              padding: '12px',
              color: '#b9bbbe',
              fontSize: '14px',
              fontStyle: 'italic'
            }}>
              Loading older messages...
            </div>
          )}
          {!hasMoreMessages && appState.messages.length > 0 && (
            <div style={{
              textAlign: 'center',
              padding: '12px',
              color: '#72767d',
              fontSize: '13px',
              opacity: 0.7,
              borderBottom: '1px solid #40444b',
              marginBottom: '8px'
            }}>
              You've reached the beginning of this channel
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
                  <span className="message-author">{msg.author}</span>
                  <span className="message-time">{msg.time}</span>
                  {msg.edited_at && (
                    <span 
                      style={{ 
                        fontSize: '12px', 
                        color: '#666',
                        marginLeft: '8px',
                        fontStyle: 'italic'
                      }}
                      title={`Edited at ${new Date(msg.edited_at).toLocaleString()}`}
                    >
                      (edited)
                    </span>
                  )}
                  {msg.isEncrypted && (
                    <span 
                      style={{ 
                        fontSize: '12px', 
                        color: '#43b581',
                        marginLeft: '8px'
                      }}
                      title="End-to-end encrypted"
                    >
                      🔒
                    </span>
                  )}
                  {msg.pinned_at && (
                    <span 
                      style={{ 
                        fontSize: '12px', 
                        color: '#faa61a',
                        marginLeft: '8px'
                      }}
                      title={`Pinned ${new Date(msg.pinned_at).toLocaleString()}`}
                    >
                      📌
                    </span>
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
          
          {/* Typing indicator */}
          {selectedChannelId && formatTypingUsers(selectedChannelId) && (
            <div className="typing-indicator">
              <span className="typing-text">{formatTypingUsers(selectedChannelId)}</span>
              <span className="typing-dots">
                <span>.</span>
                <span>.</span>
                <span>.</span>
              </span>
            </div>
          )}
        </div>
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
          <input
            className="message-input"
            type="text"
            placeholder={`Message ${activeChannel}`}
            value={message}
            onChange={(e) => {
              setMessage(e.target.value);
              // Send typing indicator when user types (throttled)
              if (selectedChannelId) {
                sendTypingIndicator(selectedChannelId);
              }
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                handleSendMessage();
              }
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
        {members.length > 0 ? (
          members.map((member) => {
            const currentUserId = localStorage.getItem('accord_user_id');
            const isCurrentUser = member.user_id === currentUserId;
            const canKick = selectedNodeId && hasPermission(selectedNodeId, 'KickMembers') && !isCurrentUser;
            
            return (
              <div key={member.user.id} className="member" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
                  <div className="member-avatar">{displayName(member.user)[0]}</div>
                  <span className="member-name" style={{ marginLeft: '8px' }}>
                    {displayName(member.user)}
                  </span>
                  <span 
                    style={{ 
                      fontSize: '12px',
                      marginLeft: '4px'
                    }}
                    title={member.role}
                  >
                    {getRoleBadge(member.role)}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <span 
                    className="member-status"
                    style={{ 
                      fontSize: '12px',
                      color: '#43b581' // Online color - we'll assume all are online for now
                    }}
                  >
                    ●
                  </span>
                  {!isCurrentUser && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        openDmWithUser(member.user);
                      }}
                      style={{
                        background: '#5865f2',
                        border: 'none',
                        color: '#ffffff',
                        padding: '2px 6px',
                        borderRadius: '2px',
                        cursor: 'pointer',
                        fontSize: '10px',
                        opacity: 0.7,
                        marginRight: '4px'
                      }}
                      title="Send DM"
                      onMouseEnter={(e) => e.currentTarget.style.opacity = '1'}
                      onMouseLeave={(e) => e.currentTarget.style.opacity = '0.7'}
                    >
                      DM
                    </button>
                  )}
                  {canKick && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleKickMember(member.user_id, displayName(member.user));
                      }}
                      style={{
                        background: '#f04747',
                        border: 'none',
                        color: '#ffffff',
                        padding: '2px 6px',
                        borderRadius: '2px',
                        cursor: 'pointer',
                        fontSize: '10px',
                        opacity: 0.7
                      }}
                      title="Kick member"
                      onMouseEnter={(e) => e.currentTarget.style.opacity = '1'}
                      onMouseLeave={(e) => e.currentTarget.style.opacity = '0.7'}
                    >
                      Kick
                    </button>
                  )}
                </div>
              </div>
            );
          })
        ) : members.length === 0 ? (
          <div style={{ padding: '16px', color: '#8e9297', fontSize: '13px', textAlign: 'center' }}>
            {nodes.length === 0 ? 'Join or create a node to see members' : 'No members loaded'}
          </div>
        ) : null}
      </div>

      {/* Error Message */}
      {error && (
        <div style={{
          position: 'fixed',
          top: '20px',
          right: '20px',
          background: '#f04747',
          color: '#ffffff',
          padding: '12px 16px',
          borderRadius: '4px',
          zIndex: 1000,
          maxWidth: '300px',
          fontSize: '14px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)'
        }}>
          {error}
          <button
            onClick={() => setError("")}
            style={{
              background: 'none',
              border: 'none',
              color: '#ffffff',
              cursor: 'pointer',
              fontSize: '16px',
              marginLeft: '8px',
              padding: '0'
            }}
          >
            ×
          </button>
        </div>
      )}

      {/* Create Node Modal */}
      {showCreateNodeModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1001
        }}>
          <div style={{
            background: '#36393f',
            padding: '24px',
            borderRadius: '8px',
            maxWidth: '400px',
            width: '90%',
            color: '#ffffff'
          }}>
            <h3 style={{ margin: '0 0 16px 0' }}>Create a Node</h3>
            <p style={{ margin: '0 0 16px 0', color: '#b9bbbe', fontSize: '0.9rem' }}>
              A Node is your community space. A #general channel will be created automatically.
            </p>
            <div style={{ marginBottom: '12px' }}>
              <label style={{ fontSize: '0.8rem', color: '#b9bbbe', display: 'block', marginBottom: '4px' }}>Node Name</label>
              <input
                type="text"
                placeholder="My Community"
                value={newNodeName}
                onChange={(e) => setNewNodeName(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') handleCreateNode(); }}
                style={{ width: '100%', padding: '8px', borderRadius: '4px', border: 'none', background: '#40444b', color: '#ffffff', fontSize: '1rem' }}
              />
            </div>
            <div style={{ marginBottom: '16px' }}>
              <label style={{ fontSize: '0.8rem', color: '#b9bbbe', display: 'block', marginBottom: '4px' }}>Description (optional)</label>
              <input
                type="text"
                placeholder="What's this node about?"
                value={newNodeDescription}
                onChange={(e) => setNewNodeDescription(e.target.value)}
                style={{ width: '100%', padding: '8px', borderRadius: '4px', border: 'none', background: '#40444b', color: '#ffffff', fontSize: '0.95rem' }}
              />
            </div>
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button
                onClick={handleCreateNode}
                disabled={creatingNode || !newNodeName.trim()}
                style={{ background: '#43b581', border: 'none', color: '#ffffff', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer', opacity: (creatingNode || !newNodeName.trim()) ? 0.6 : 1 }}
              >
                {creatingNode ? 'Creating...' : 'Create Node'}
              </button>
              <button
                onClick={() => { setShowCreateNodeModal(false); setNewNodeName(""); setNewNodeDescription(""); }}
                style={{ background: '#747f8d', border: 'none', color: '#ffffff', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Invite Modal */}
      {showInviteModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1001
        }}>
          <div style={{
            background: '#36393f',
            padding: '24px',
            borderRadius: '8px',
            maxWidth: '400px',
            width: '90%',
            color: '#ffffff'
          }}>
            <h3 style={{ margin: '0 0 16px 0', color: '#ffffff' }}>Invite Link Generated</h3>
            <p style={{ margin: '0 0 16px 0', color: '#b9bbbe' }}>
              Share this invite link with others to let them join this node:
            </p>
            <div style={{
              background: '#40444b',
              padding: '12px',
              borderRadius: '4px',
              marginBottom: '16px',
              fontFamily: 'monospace',
              fontSize: '14px',
              wordBreak: 'break-all',
              userSelect: 'text'
            }}>
              {generatedInvite}
            </div>
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(generatedInvite).then(() => {
                    alert('Invite code copied to clipboard!');
                  }).catch(() => {
                    // Fallback for browsers that don't support clipboard API
                    const textArea = document.createElement('textarea');
                    textArea.value = generatedInvite;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    alert('Invite code copied to clipboard!');
                  });
                }}
                style={{
                  background: '#7289da',
                  border: 'none',
                  color: '#ffffff',
                  padding: '8px 16px',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Copy
              </button>
              <button
                onClick={() => {
                  setShowInviteModal(false);
                  setGeneratedInvite("");
                }}
                style={{
                  background: '#747f8d',
                  border: 'none',
                  color: '#ffffff',
                  padding: '8px 16px',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Close
              </button>
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
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            backgroundColor: '#36393f',
            borderRadius: '8px',
            padding: '24px',
            minWidth: '300px',
            maxWidth: '90vw',
            maxHeight: '80vh',
            overflow: 'auto'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '16px'
            }}>
              <h3 style={{ margin: 0, color: '#ffffff' }}>Start a Direct Message</h3>
              <button
                onClick={() => setShowDmChannelCreate(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#b9bbbe',
                  cursor: 'pointer',
                  fontSize: '18px',
                  padding: '4px'
                }}
              >
                ×
              </button>
            </div>
            
            <div style={{ marginBottom: '16px', color: '#b9bbbe', fontSize: '14px' }}>
              Select a user to start a direct message:
            </div>
            
            <div style={{ maxHeight: '300px', overflow: 'auto' }}>
              {members
                .filter(member => member.user_id !== localStorage.getItem('accord_user_id'))
                .map((member) => (
                  <div
                    key={member.user_id}
                    onClick={() => {
                      openDmWithUser(member.user);
                      setShowDmChannelCreate(false);
                    }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      padding: '8px 12px',
                      cursor: 'pointer',
                      borderRadius: '4px',
                      marginBottom: '4px',
                      backgroundColor: 'transparent'
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.backgroundColor = '#40444b';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }}
                  >
                    <div 
                      style={{
                        width: '24px',
                        height: '24px',
                        borderRadius: '50%',
                        backgroundColor: '#5865f2',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        marginRight: '12px',
                        fontSize: '12px',
                        fontWeight: '600',
                        color: '#ffffff'
                      }}
                    >
                      {displayName(member.user)[0].toUpperCase()}
                    </div>
                    <div>
                      <div style={{ color: '#ffffff', fontSize: '14px', fontWeight: '500' }}>
                        {displayName(member.user)}
                      </div>
                      <div style={{ color: '#b9bbbe', fontSize: '12px' }}>
                        {getRoleBadge(member.role)} {member.role}
                      </div>
                    </div>
                  </div>
                ))}
              
              {members.filter(member => member.user_id !== localStorage.getItem('accord_user_id')).length === 0 && (
                <div style={{ 
                  padding: '16px', 
                  color: '#8e9297', 
                  fontSize: '14px', 
                  textAlign: 'center' 
                }}>
                  No other members available
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Removed non-existent dialog components */}
    </div>
  );
}

export default App;