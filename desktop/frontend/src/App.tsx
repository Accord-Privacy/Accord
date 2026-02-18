import React, { useState, useEffect, useCallback, useRef, Suspense } from "react";
import { api, parseInviteLink, generateInviteLink, storeRelayToken, storeRelayUserId, getRelayToken, getRelayUserId, detectSameOriginRelay } from "./api";
import { AccordWebSocket, ConnectionInfo } from "./ws";
import { AppState, Message, WsIncomingMessage, Node, Channel, NodeMember, User, TypingUser, TypingStartMessage, DmChannelWithInfo, ParsedInviteLink, Role, ReadReceipt, ReadReceiptMessage } from "./types";
import { 
  generateKeyPair, 
  exportPublicKey, 
  saveKeyToStorage, 
  loadKeyFromStorage, 
  getChannelKey, 
  encryptMessage, 
  decryptMessage, 
  clearChannelKeyCache,
  isCryptoSupported,
  sha256Hex,
  keyPairToMnemonic,
  mnemonicToKeyPair,
  saveKeyWithPassword,
  loadKeyWithPassword,
  hasStoredKeyPair,
  getStoredPublicKey,
  setActiveIdentity,
} from "./crypto";
import { storeToken, getToken, clearToken } from "./tokenStorage";
import { FileUploadButton, FileList, FileDropZone, FileAttachment } from "./FileManager";
import { EmojiPickerButton } from "./EmojiPicker";
const VoiceChat = React.lazy(() => import("./VoiceChat").then(m => ({ default: m.VoiceChat })));
import { SearchOverlay } from "./SearchOverlay";
const NodeSettings = React.lazy(() => import("./NodeSettings").then(m => ({ default: m.NodeSettings })));
import { notificationManager, NotificationPreferences } from "./notifications";
import { renderMessageMarkdown } from "./markdown";
const NotificationSettings = React.lazy(() => import("./NotificationSettings").then(m => ({ default: m.NotificationSettings })));
const Settings = React.lazy(() => import("./Settings").then(m => ({ default: m.Settings })));
import { LoadingSpinner } from "./LoadingSpinner";
import { SetupWizard, SetupResult } from "./SetupWizard";
import { listIdentities } from "./identityStorage";
import { CLIENT_BUILD_HASH, getCombinedTrust, getTrustIndicator } from "./buildHash";
import { initHashVerifier, getKnownHashes, onHashListUpdate } from "./hashVerifier";
import { E2EEManager, type PreKeyBundle } from "./e2ee";
import { initKeyboardShortcuts, SHORTCUTS } from "./keyboard";

// Helper: truncate a public key hash to a short fingerprint for display
function fingerprint(publicKeyHash: string): string {
  if (!publicKeyHash || publicKeyHash.length < 16) return publicKeyHash || 'unknown';
  return publicKeyHash.substring(0, 8) + '...' + publicKeyHash.substring(publicKeyHash.length - 8);
}

// Voice Connection Panel (sidebar bottom, above user panel)
const VoiceConnectionPanel: React.FC<{
  channelName: string;
  connectedAt: number | null;
  onDisconnect: () => void;
}> = ({ channelName, connectedAt, onDisconnect }) => {
  const [elapsed, setElapsed] = useState("00:00");
  const [isMuted, setIsMuted] = useState(false);
  const [isDeafened, setIsDeafened] = useState(false);

  useEffect(() => {
    if (!connectedAt) return;
    const interval = setInterval(() => {
      const secs = Math.floor((Date.now() - connectedAt) / 1000);
      const m = String(Math.floor(secs / 60)).padStart(2, '0');
      const s = String(secs % 60).padStart(2, '0');
      setElapsed(`${m}:${s}`);
    }, 1000);
    return () => clearInterval(interval);
  }, [connectedAt]);

  return (
    <div className="voice-connection-panel">
      <div className="voice-connection-info">
        <span className="voice-connection-dot">●</span>
        <div className="voice-connection-details">
          <span className="voice-connection-label">Voice Connected</span>
          <span className="voice-connection-channel">{channelName}</span>
        </div>
        <span className="voice-connection-timer">{elapsed}</span>
      </div>
      <div className="voice-connection-controls">
        <button
          className={`voice-ctrl-btn ${isMuted ? 'active' : ''}`}
          onClick={() => setIsMuted(!isMuted)}
          title={isMuted ? 'Unmute' : 'Mute'}
        >
          {isMuted ? '🔇' : '🎤'}
        </button>
        <button
          className={`voice-ctrl-btn ${isDeafened ? 'active' : ''}`}
          onClick={() => { setIsDeafened(!isDeafened); if (!isDeafened) setIsMuted(true); }}
          title={isDeafened ? 'Undeafen' : 'Deafen'}
        >
          {isDeafened ? '🔇' : '🔊'}
        </button>
        <button
          className="voice-ctrl-btn voice-disconnect-btn"
          onClick={onDisconnect}
          title="Disconnect"
        >
          📞
        </button>
      </div>
    </div>
  );
};

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
  const [showWelcomeScreen, setShowWelcomeScreen] = useState(() => {
    // Skip welcome if we already know a server URL or if served from a relay
    const savedUrl = localStorage.getItem('accord_server_url');
    if (savedUrl) return false;
    // Check if current origin looks like a relay (not a dev server)
    const origin = typeof window !== 'undefined' ? window.location.origin : '';
    if (origin && !origin.includes(':1420') && !origin.includes(':5173') && !origin.includes(':3000')) {
      // Optimistically set server URL to current origin and skip welcome
      localStorage.setItem('accord_server_url', origin);
      return false;
    }
    return true;
  });
  const [welcomeMode, setWelcomeMode] = useState<'choose' | 'invite' | 'admin' | 'recover'>('choose');
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

  // Mnemonic / Recovery state
  const [showMnemonicModal, setShowMnemonicModal] = useState(false);
  const [mnemonicPhrase, setMnemonicPhrase] = useState("");
  const [mnemonicAcknowledged, setMnemonicAcknowledged] = useState(false);
  const [showRecoverModal, setShowRecoverModal] = useState(false);
  const [recoverMnemonic, setRecoverMnemonic] = useState("");
  const [recoverPassword, setRecoverPassword] = useState("");
  const [recoverError, setRecoverError] = useState("");
  const [recoverLoading, setRecoverLoading] = useState(false);
  const [hasExistingKey, setHasExistingKey] = useState(() => hasStoredKeyPair());
  // Store password in memory for session reconnect
  const passwordRef = useRef<string>("");

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
  const [lastConnectionError, setLastConnectionError] = useState<string>("");

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
  const [voiceConnectedAt, setVoiceConnectedAt] = useState<number | null>(null);

  // Custom status state
  const [customStatus, setCustomStatus] = useState<string>("");
  const [showStatusPopover, setShowStatusPopover] = useState(false);
  const [statusInput, setStatusInput] = useState("");

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
  const [showJoinNodeModal, setShowJoinNodeModal] = useState(false);
  const [joinInviteCode, setJoinInviteCode] = useState("");
  const [joiningNode, setJoiningNode] = useState(false);
  const [joinError, setJoinError] = useState("");
  const [newNodeName, setNewNodeName] = useState("");
  const [newNodeDescription, setNewNodeDescription] = useState("");
  const [creatingNode, setCreatingNode] = useState(false);

  // Settings state
  const [showSettings, setShowSettings] = useState(false);

  // Server hello / trust indicator state
  const [serverBuildHash, setServerBuildHash] = useState<string>("");
  const [serverHelloVersion, setServerHelloVersion] = useState<string>("");
  const [knownHashes, setKnownHashes] = useState(getKnownHashes());

  // Initialize hash verifier on mount
  useEffect(() => {
    initHashVerifier();
    return onHashListUpdate(() => setKnownHashes(getKnownHashes()));
  }, []);

  const [connectedSince, setConnectedSince] = useState<number | null>(null);
  const [showConnectionInfo, setShowConnectionInfo] = useState(false);

  // Node settings state
  const [showNodeSettings, setShowNodeSettings] = useState(false);
  const [collapsedCategories, setCollapsedCategories] = useState<Set<string>>(new Set());
  const [nodeRoles, setNodeRoles] = useState<Role[]>([]);
  // Map of userId -> Role[] for the current node
  const [memberRolesMap, setMemberRolesMap] = useState<Record<string, Role[]>>({});
  const [showRolePopup, setShowRolePopup] = useState<{ userId: string; x: number; y: number } | null>(null);
  const [showTemplateImport, setShowTemplateImport] = useState(false);
  const [templateInput, setTemplateInput] = useState('');
  const [templateImporting, setTemplateImporting] = useState(false);
  const [templateResult, setTemplateResult] = useState<any>(null);
  const [templateError, setTemplateError] = useState('');

  // Delete channel confirmation modal state
  const [deleteChannelConfirm, setDeleteChannelConfirm] = useState<{ id: string; name: string } | null>(null);

  // Display name prompt state
  const [showDisplayNamePrompt, setShowDisplayNamePrompt] = useState(false);
  const [displayNameInput, setDisplayNameInput] = useState("");
  const [displayNameSaving, setDisplayNameSaving] = useState(false);

  // First-run setup wizard state
  const [showSetupWizard, setShowSetupWizard] = useState(() => {
    // Show wizard if no identity exists (first run)
    if (hasStoredKeyPair()) return false;
    // Also check localStorage identity index
    const idx = localStorage.getItem('accord_identity_index');
    if (idx) {
      try { if (JSON.parse(idx).length > 0) return false; } catch {}
    }
    // Check legacy keys
    if (localStorage.getItem('accord_public_key')) return false;
    return true;
  });

  // Keyboard shortcuts help state
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false);

  // Member sidebar visibility
  const [showMemberSidebar, setShowMemberSidebar] = useState(true);

  // Message input emoji picker state
  const [showInputEmojiPicker, setShowInputEmojiPicker] = useState(false);
  const messageInputRef = useRef<HTMLTextAreaElement>(null);
  const loadNodesRef = useRef<(() => Promise<void>) | undefined>(undefined);
  const creatingNodeRef = useRef(false);

  // E2EE manager for 1:1 DM Double Ratchet encryption
  const e2eeManagerRef = useRef<E2EEManager | null>(null);
  // Cache of fetched prekey bundles by user ID
  const prekeyBundleCacheRef = useRef<Map<string, PreKeyBundle>>(new Map());

  // Scroll-to-bottom state
  const [showScrollToBottom, setShowScrollToBottom] = useState(false);
  const [newMessageCount, setNewMessageCount] = useState(0);

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

  // Read receipts state: channelId -> ReadReceipt[]
  const [readReceipts, setReadReceipts] = useState<Map<string, ReadReceipt[]>>(new Map());
  const lastReadSent = useRef<Map<string, string>>(new Map()); // channelId -> last message_id sent

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

  // Send read receipt to server
  const sendReadReceipt = useCallback((channelId: string, messageId: string) => {
    if (!appState.token || !messageId || !channelId) return;
    // Don't re-send for the same message
    if (lastReadSent.current.get(channelId) === messageId) return;
    lastReadSent.current.set(channelId, messageId);
    api.markChannelRead(channelId, messageId, appState.token).catch(() => {
      // Silent fail — read receipts are best-effort
    });
  }, [appState.token]);

  // Initialize E2EE manager and publish prekey bundle to server
  const initializeE2EE = useCallback(async (token: string) => {
    if (e2eeManagerRef.current?.isInitialized) return;
    try {
      const manager = new E2EEManager();
      const bundle = manager.initialize();
      e2eeManagerRef.current = manager;

      // Publish prekey bundle to server (base64-encoded keys)
      const toBase64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
      await api.publishKeyBundle(
        toBase64(bundle.identityKey),
        toBase64(bundle.signedPrekey),
        bundle.oneTimePrekey ? [toBase64(bundle.oneTimePrekey)] : [],
        token,
      );
      console.log('E2EE initialized and prekey bundle published');
    } catch (error) {
      console.error('Failed to initialize E2EE:', error);
    }
  }, []);

  // Fetch a peer's prekey bundle and initiate E2EE session
  const ensureE2EESession = useCallback(async (peerId: string, token: string): Promise<boolean> => {
    const manager = e2eeManagerRef.current;
    if (!manager?.isInitialized) return false;
    if (manager.hasSession(peerId)) return true;

    try {
      // Check cache first
      let bundle = prekeyBundleCacheRef.current.get(peerId);
      if (!bundle) {
        const resp = await api.fetchKeyBundle(peerId, token);
        const fromBase64 = (b64: string) => {
          const binary = atob(b64);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          return bytes;
        };
        bundle = {
          identityKey: fromBase64(resp.identity_key),
          signedPrekey: fromBase64(resp.signed_prekey),
          oneTimePrekey: resp.one_time_prekey ? fromBase64(resp.one_time_prekey) : undefined,
        };
        prekeyBundleCacheRef.current.set(peerId, bundle);
      }
      manager.initiateSession(peerId, bundle);
      return true;
    } catch (error) {
      console.warn('Failed to establish E2EE session with peer:', peerId, error);
      return false;
    }
  }, []);

  // Register API token refresher for automatic re-auth on 401
  useEffect(() => {
    const refresher = async (): Promise<string | null> => {
      const storedPk = getStoredPublicKey();
      const pwd = passwordRef.current;
      if (!storedPk || !pwd) return null;
      try {
        const response = await api.login(storedPk, pwd);
        storeToken(response.token);
        localStorage.setItem('accord_user_id', response.user_id);
        setAppState(prev => ({ ...prev, token: response.token }));
        return response.token;
      } catch {
        return null;
      }
    };
    api.setTokenRefresher(refresher);
    return () => api.setTokenRefresher(null);
  }, []);

  // Initialize E2EE when authenticated with a token
  useEffect(() => {
    if (isAuthenticated && appState.token) {
      initializeE2EE(appState.token);
    }
  }, [isAuthenticated, appState.token, initializeE2EE]);

  // Async identity check for Tauri keyring (supplement synchronous check)
  useEffect(() => {
    if (!showSetupWizard) return;
    listIdentities().then(ids => {
      if (ids.length > 0) setShowSetupWizard(false);
    }).catch(() => {});
  }, []);

  // Check server availability on mount — with same-origin auto-detection
  useEffect(() => {
    const checkServer = async () => {
      // If no server URL saved yet, try same-origin detection first
      if (!localStorage.getItem('accord_server_url')) {
        const sameOrigin = await detectSameOriginRelay();
        if (sameOrigin) {
          api.setBaseUrl(sameOrigin);
          setServerUrl(sameOrigin);
          setServerAvailable(true);
          setShowWelcomeScreen(false); // Skip welcome — we know where we are
          return;
        }
      }
      const available = await api.testConnection();
      setServerAvailable(available);
    };
    checkServer();
  }, []);

  // WebSocket event handlers
  const setupWebSocketHandlers = useCallback((socket: AccordWebSocket) => {
    socket.on('connected', () => {
      setAppState(prev => ({ ...prev, isConnected: true }));
      setConnectionInfo({ status: 'connected', reconnectAttempt: 0, maxReconnectAttempts: 20 });
      setLastConnectionError("");
      setConnectedSince(Date.now());
      // Reload nodes on reconnect to prevent stale/missing node list
      loadNodesRef.current?.();
    });

    socket.on('hello' as any, (data: any) => {
      if (data.server_version) setServerHelloVersion(data.server_version);
      if (data.server_build_hash) setServerBuildHash(data.server_build_hash);
    });

    socket.on('disconnected', () => {
      setAppState(prev => ({ ...prev, isConnected: false }));
      setConnectedSince(null);
    });

    socket.on('connection_status', (info: ConnectionInfo) => {
      setConnectionInfo(info);
    });

    socket.on('error', (err: Error) => {
      setLastConnectionError(err.message || 'Connection error');
    });

    socket.on('auth_error', async () => {
      // Auth token expired — try auto re-authenticate with stored key + password
      const storedPk = getStoredPublicKey();
      const pwd = passwordRef.current;
      if (storedPk && pwd) {
        try {
          const response = await api.login(storedPk, pwd);
          storeToken(response.token);
          localStorage.setItem('accord_user_id', response.user_id);
          setAppState(prev => ({ ...prev, token: response.token }));
          // Reconnect WebSocket with new token
          socket.disconnect();
          const newSocket = new AccordWebSocket(response.token, serverUrl.replace(/^http/, "ws"));
          setupWebSocketHandlers(newSocket);
          setWs(newSocket);
          newSocket.connect();
          return;
        } catch {
          // Re-auth failed, fall through to logout
        }
      }
      handleLogout();
    });

    socket.on('message', (_msg: WsIncomingMessage) => {
    });

    socket.on('channel_message', async (data) => {
      // Handle incoming channel messages
      let content = data.encrypted_data;
      let isEncrypted = false;

      // Check if this is a DM message
      const isIncomingDm = data.is_dm || dmChannels.some(dm => dm.id === data.channel_id);

      if (isIncomingDm && e2eeManagerRef.current?.isInitialized && data.from) {
        // DM: try Double Ratchet E2EE decryption
        try {
          content = e2eeManagerRef.current.decrypt(data.from, data.encrypted_data);
          isEncrypted = true;
        } catch (error) {
          console.warn('E2EE decrypt failed, trying symmetric fallback:', error);
          // Fallback to symmetric
          if (encryptionEnabled && keyPair && data.channel_id) {
            try {
              const channelKey = await getChannelKey(keyPair.privateKey, data.channel_id);
              content = await decryptMessage(channelKey, data.encrypted_data);
              isEncrypted = true;
            } catch (e2) {
              console.warn('Symmetric decrypt also failed:', e2);
            }
          }
        }
      } else if (encryptionEnabled && keyPair && data.channel_id) {
        // Channel: use symmetric decryption
        try {
          const channelKey = await getChannelKey(keyPair.privateKey, data.channel_id);
          content = await decryptMessage(channelKey, data.encrypted_data);
          isEncrypted = true;
        } catch (error) {
          console.warn('Failed to decrypt message, showing encrypted data:', error);
        }
      }

      // Look up sender display name from member list
      const senderMember = members.find(m => m.user_id === data.from);
      const senderName = senderMember 
        ? (senderMember.user?.display_name || senderMember.profile?.display_name || fingerprint(senderMember.public_key_hash || data.from || ''))
        : fingerprint(data.from || '');

      const newMessage: Message = {
        id: data.message_id || Math.random().toString(),
        author: senderName,
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
          notificationManager.addMessage(`dm-${dmChannel.id}`, data.channel_id, newMessage, true);
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
        // Send read receipt for the new message since user is at bottom
        if (data.channel_id === selectedChannelId && newMessage.id) {
          sendReadReceipt(data.channel_id, newMessage.id);
        }
      } else {
        // User is scrolled up — increment unread count
        setNewMessageCount(prev => prev + 1);
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

    // Handle read receipt events
    socket.on('read_receipt', (data: ReadReceiptMessage) => {
      setReadReceipts(prev => {
        const newMap = new Map(prev);
        const channelReceipts = (newMap.get(data.channel_id) || []).filter(
          r => r.user_id !== data.user_id
        );
        channelReceipts.push({
          user_id: data.user_id,
          message_id: data.message_id,
          timestamp: data.timestamp,
        });
        newMap.set(data.channel_id, channelReceipts);
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
      setNodes(Array.isArray(userNodes) ? userNodes : []);
      
      // Auto-select first node if none selected
      if (userNodes.length > 0 && !selectedNodeId) {
        setSelectedNodeId(userNodes[0].id);
      }
    } catch (error) {
      console.error('Failed to load nodes:', error);
    }
  }, [appState.token, serverAvailable, selectedNodeId]);

  // Keep ref updated for use in WS handlers (avoids stale closures)
  loadNodesRef.current = loadNodes;

  // Load channels for selected node
  const loadChannels = useCallback(async (nodeId: string) => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const nodeChannels = await api.getNodeChannels(nodeId, appState.token);
      setChannels(Array.isArray(nodeChannels) ? nodeChannels : []);
      
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
      const rawMembers = await api.getNodeMembers(nodeId, appState.token);
      const nodeMembers = (Array.isArray(rawMembers) ? rawMembers : []).map((m: any) => ({
        ...m,
        // Synthesize a `user` object from member/profile data so the UI can render members
        user: m.user || {
          id: m.user_id,
          public_key_hash: m.public_key_hash || '',
          public_key: '',
          created_at: m.joined_at || 0,
          display_name: m.profile?.display_name || undefined,
        },
      }));
      setMembers(nodeMembers);
      
      // Load member role assignments
      loadAllMemberRoles(nodeId, nodeMembers);
      
      // Find current user's role in this node
      const currentUserId = localStorage.getItem('accord_user_id');
      if (currentUserId && nodeMembers.length > 0) {
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

  // Load roles for selected node
  const loadRoles = useCallback(async (nodeId: string) => {
    if (!appState.token || !serverAvailable) return;
    try {
      const roles = await api.getRoles(nodeId, appState.token);
      setNodeRoles(Array.isArray(roles) ? roles : []);
    } catch (error) {
      console.error('Failed to load roles:', error);
      setNodeRoles([]);
    }
  }, [appState.token, serverAvailable]);

  // Load all member roles for the current node
  const loadAllMemberRoles = useCallback(async (nodeId: string, memberList: Array<NodeMember & { user: User }>) => {
    if (!appState.token || !serverAvailable) return;
    const map: Record<string, Role[]> = {};
    await Promise.all(memberList.map(async (m) => {
      try {
        const roles = await api.getMemberRoles(nodeId, m.user_id, appState.token!);
        map[m.user_id] = Array.isArray(roles) ? roles : [];
      } catch {
        map[m.user_id] = [];
      }
    }));
    setMemberRolesMap(map);
  }, [appState.token, serverAvailable]);

  // Get highest hoisted role color for a user
  const getMemberRoleColor = useCallback((userId: string): string | undefined => {
    const userRolesList = memberRolesMap[userId];
    if (!userRolesList || userRolesList.length === 0) return undefined;
    // Sort by position descending, find highest hoisted role with a color
    const sorted = [...userRolesList].sort((a, b) => b.position - a.position);
    const hoisted = sorted.find(r => r.hoist && r.color);
    if (hoisted) return hoisted.color!;
    // Fallback: highest role with a color
    const withColor = sorted.find(r => r.color);
    return withColor?.color || undefined;
  }, [memberRolesMap]);

  // Get highest hoisted role for a user (for member list grouping)
  const getMemberHighestHoistedRole = useCallback((userId: string): Role | undefined => {
    const userRolesList = memberRolesMap[userId];
    if (!userRolesList || userRolesList.length === 0) return undefined;
    return [...userRolesList].sort((a, b) => b.position - a.position).find(r => r.hoist);
  }, [memberRolesMap]);

  // Toggle role assignment for a member
  const toggleMemberRole = useCallback(async (userId: string, roleId: string, hasRole: boolean) => {
    if (!selectedNodeId || !appState.token) return;
    try {
      if (hasRole) {
        await api.removeMemberRole(selectedNodeId, userId, roleId, appState.token);
      } else {
        await api.assignMemberRole(selectedNodeId, userId, roleId, appState.token);
      }
      // Reload that member's roles
      const roles = await api.getMemberRoles(selectedNodeId, userId, appState.token);
      setMemberRolesMap(prev => ({ ...prev, [userId]: Array.isArray(roles) ? roles : [] }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update role');
    }
  }, [selectedNodeId, appState.token]);

  // Load message history for selected channel (initial load)
  const loadMessages = useCallback(async (channelId: string) => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const response = await api.getChannelMessages(channelId, appState.token);
      
      // Format messages for display
      const formattedMessages = response.messages.map(msg => ({
        ...msg,
        author: msg.author || fingerprint(msg.sender_public_key_hash || msg.sender_id || '' ) || 'Unknown',
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
        author: msg.author || fingerprint(msg.sender_public_key_hash || msg.sender_id || '' ) || 'Unknown',
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

  // Handle inserting emoji at cursor position
  const handleInsertEmoji = useCallback((emoji: string) => {
    const textarea = messageInputRef.current;
    if (textarea) {
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const newMsg = message.substring(0, start) + emoji + message.substring(end);
      setMessage(newMsg);
      // Restore cursor position after emoji
      setTimeout(() => {
        textarea.selectionStart = textarea.selectionEnd = start + emoji.length;
        textarea.focus();
      }, 0);
    } else {
      setMessage(prev => prev + emoji);
    }
    setShowInputEmojiPicker(false);
  }, [message]);

  // Handle scroll events for infinite scroll + scroll-to-bottom
  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const target = e.target as HTMLDivElement;
    
    // Check if scrolled to top (with small threshold)
    if (target.scrollTop <= 50 && hasMoreMessages && !isLoadingOlderMessages && selectedChannelId) {
      loadOlderMessages(selectedChannelId);
    }

    // Show/hide scroll-to-bottom button
    const distanceFromBottom = target.scrollHeight - target.scrollTop - target.clientHeight;
    setShowScrollToBottom(distanceFromBottom > 200);
    if (distanceFromBottom < 50) {
      setNewMessageCount(0);
    }
  }, [hasMoreMessages, isLoadingOlderMessages, selectedChannelId, loadOlderMessages]);

  const scrollToBottom = useCallback(() => {
    const container = messagesContainerRef.current;
    if (container) {
      container.scrollTo({ top: container.scrollHeight, behavior: 'smooth' });
      setNewMessageCount(0);
    }
  }, []);

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
    loadRoles(nodeId);
  }, [loadChannels, loadMembers, loadRoles]);

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

  // Save custom status
  const handleSaveCustomStatus = async () => {
    if (!appState.token) return;
    const newStatus = statusInput.trim().slice(0, 128);
    try {
      await api.updateProfile({ custom_status: newStatus || undefined }, appState.token);
      setCustomStatus(newStatus);
      setShowStatusPopover(false);
    } catch (error) {
      console.error('Failed to update custom status:', error);
    }
  };

  // Load own custom status on login
  useEffect(() => {
    if (appState.user?.id && appState.token) {
      api.getUserProfile(appState.user.id, appState.token).then(profile => {
        if (profile?.custom_status) {
          setCustomStatus(profile.custom_status);
          setStatusInput(profile.custom_status);
        }
      }).catch(() => {});
    }
  }, [appState.user?.id, appState.token]);

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
      // Send read receipt to server
      if (latestMessage?.id) {
        sendReadReceipt(channelId, latestMessage.id);
      }
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
        setGeneratedInvite(generateInviteLink(host, response.invite_code));
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

  // Handle deleting a channel (called after modal confirmation)
  const handleDeleteChannelConfirmed = async (channelId: string) => {
    if (!appState.token) return;
    
    try {
      await api.deleteChannel(channelId, appState.token);
      if (channelId === selectedChannelId) {
        setSelectedChannelId(null);
        setActiveChannel("# general");
      }
      if (selectedNodeId) {
        await loadChannels(selectedNodeId);
      }
    } catch (error) {
      console.error('Failed to delete channel:', error);
      handleApiError(error);
    }
    setDeleteChannelConfirm(null);
  };

  // Handle creating a new node
  const handleJoinNode = async () => {
    if (!appState.token || !joinInviteCode.trim()) return;
    setJoiningNode(true);
    setJoinError("");
    try {
      // Parse invite link or use as raw code
      const input = joinInviteCode.trim();
      const parsed = parseInviteLink(input);
      const code = parsed ? parsed.inviteCode : input;
      
      await api.joinNodeByInvite(code, appState.token);
      setShowJoinNodeModal(false);
      setShowCreateNodeModal(false);
      setJoinInviteCode("");
      // Reload nodes to show the new one
      await loadNodes();
    } catch (error: any) {
      setJoinError(error.message || "Failed to join node");
    } finally {
      setJoiningNode(false);
    }
  };

  const handleCreateNode = async () => {
    if (!appState.token || !newNodeName.trim()) return;
    if (creatingNodeRef.current) return; // Prevent double-fire
    creatingNodeRef.current = true;
    setCreatingNode(true);
    try {
      const newNode = await api.createNode(newNodeName.trim(), appState.token, newNodeDescription.trim() || undefined);
      // Only create #general if the server didn't already create default channels
      try {
        const existingChannels = await api.getNodeChannels(newNode.id, appState.token);
        const hasChannels = Array.isArray(existingChannels) && existingChannels.length > 0;
        if (!hasChannels) {
          await api.createChannel(newNode.id, 'general', 'text', appState.token);
        }
      } catch (e) {
        console.warn('Failed to check/create #general channel:', e);
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
      creatingNodeRef.current = false;
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
      // Send read receipt to server
      sendReadReceipt(channelId, latestMessage.id);
    }
  }, [selectedNodeId, sendReadReceipt]);

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
              setPublicKeyHash(pkHash); setActiveIdentity(pkHash);
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

          // Initialize WebSocket — pass server URL so it connects to the right relay
          const wsBaseUrl = serverUrl.replace(/^http/, 'ws');
          const socket = new AccordWebSocket(existingToken, wsBaseUrl);
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
      let pkHash = '';
      if (encryptionEnabled) {
        const newKeyPair = await generateKeyPair();
        publicKeyToUse = await exportPublicKey(newKeyPair.publicKey);
        pkHash = await sha256Hex(publicKeyToUse);
        setActiveIdentity(pkHash);
        await saveKeyToStorage(newKeyPair, pkHash);
        await saveKeyWithPassword(newKeyPair, invitePassword, pkHash);
        setKeyPair(newKeyPair);
        setPublicKey(publicKeyToUse);
        // Generate mnemonic for backup
        const mnemonic = await keyPairToMnemonic(newKeyPair);
        setMnemonicPhrase(mnemonic);
      }

      if (!publicKeyToUse) {
        setInviteError("Failed to generate encryption keys");
        setInviteJoining(false);
        return;
      }

      // Register
      await api.register(publicKeyToUse, invitePassword);
      passwordRef.current = invitePassword;
      setPublicKeyHash(pkHash); setActiveIdentity(pkHash);

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
      const socket = new AccordWebSocket(response.token, serverUrl.replace(/^http/, "ws"));
      setupWebSocketHandlers(socket);
      setWs(socket);
      socket.connect();

      // Show mnemonic backup modal, then land in app
      setShowMnemonicModal(true);
      setMnemonicAcknowledged(false);
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
      const cleanUrl = serverUrl.replace(/\/+$/, '');
      setServerUrl(cleanUrl);
      api.setBaseUrl(cleanUrl);
      localStorage.setItem('accord_server_url', cleanUrl);
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
          // Set active identity from stored hash for key lookup
          const storedHash = localStorage.getItem('accord_public_key_hash');
          if (storedHash) setActiveIdentity(storedHash);
          // Try password-based decryption first
          let existingKeyPair = await loadKeyWithPassword(password);
          if (!existingKeyPair) {
            existingKeyPair = await loadKeyFromStorage();
          }
          if (existingKeyPair) {
            pkToUse = await exportPublicKey(existingKeyPair.publicKey);
            setKeyPair(existingKeyPair);
            setPublicKey(pkToUse);
          } else if (hasExistingKey) {
            // There's a stored public key but we can't decrypt the private key
            const storedPk = getStoredPublicKey();
            if (storedPk) pkToUse = storedPk;
          }
          // Last try: unencrypted public key saved from previous login
          if (!pkToUse) {
            const plainPk = localStorage.getItem('accord_public_key_plain');
            if (plainPk) pkToUse = plainPk;
          }
        }
        
        // Last resort: check if we have the public key stored separately
        if (!pkToUse) {
          const savedPkHash = localStorage.getItem('accord_public_key_hash');
          if (savedPkHash) {
            // We have the hash but not the full public key — try auth by hash
            // Server needs to support this, for now show better error
            setAuthError("Keypair not found in this browser. Use 'Recover with recovery phrase' to restore your identity, or register a new account.");
            return;
          }
          setAuthError("No identity found. Create a new identity or recover with your recovery phrase.");
          return;
        }

        // Login with public_key + password (server computes hash)
        const response = await api.login(pkToUse, password);
        
        // Store token and user info
        storeToken(response.token);
        localStorage.setItem('accord_user_id', response.user_id);
        passwordRef.current = password;

        const pkHash = await sha256Hex(pkToUse);
        setPublicKeyHash(pkHash); setActiveIdentity(pkHash);

        // Try loading key with password first, then fall back to token-based
        if (encryptionEnabled && !keyPair) {
          let existingKeyPair = await loadKeyWithPassword(password, pkHash);
          if (!existingKeyPair) {
            existingKeyPair = await loadKeyFromStorage(pkHash);
          }
          if (existingKeyPair) {
            setKeyPair(existingKeyPair);
            // Re-save with password for future logins
            await saveKeyWithPassword(existingKeyPair, password, pkHash);
          }
        }
        setHasExistingKey(true);
        // Save public key unencrypted so we can identify the user after logout
        localStorage.setItem('accord_public_key_plain', pkToUse);
        localStorage.setItem('accord_public_key_hash', pkHash);
        
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
        const socket = new AccordWebSocket(response.token, serverUrl.replace(/^http/, "ws"));
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
            const earlyHash = await sha256Hex(publicKeyToUse);
            setActiveIdentity(earlyHash);
            await saveKeyToStorage(newKeyPair, earlyHash);
            await saveKeyWithPassword(newKeyPair, password, earlyHash);
            setKeyPair(newKeyPair);
            setPublicKey(publicKeyToUse);
            // Generate mnemonic for backup
            const mnemonic = await keyPairToMnemonic(newKeyPair);
            setMnemonicPhrase(mnemonic);
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
        passwordRef.current = password;
        
        const pkHash = await sha256Hex(publicKeyToUse);
        setPublicKeyHash(pkHash); setActiveIdentity(pkHash);
        // Save public key unencrypted for future logins
        localStorage.setItem('accord_public_key_plain', publicKeyToUse);
        localStorage.setItem('accord_public_key_hash', pkHash);
        
        // Show mnemonic backup modal (replaces old key backup)
        setShowMnemonicModal(true);
        setMnemonicAcknowledged(false);

        // Prompt for display name after registration
        setTimeout(() => { setShowDisplayNamePrompt(true); }, 500);
      }
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Authentication failed");
    }
  };

  // Handle mnemonic recovery
  const handleRecover = async () => {
    setRecoverError("");
    setRecoverLoading(true);
    try {
      // Derive keypair from mnemonic
      const recoveredKeyPair = mnemonicToKeyPair(recoverMnemonic);
      const pk = await exportPublicKey(recoveredKeyPair.publicKey);
      
      // Authenticate with server
      const response = await api.login(pk, recoverPassword);
      
      // Save keys (compute hash first for namespacing)
      const pkHash = await sha256Hex(pk);
      setActiveIdentity(pkHash);
      await saveKeyToStorage(recoveredKeyPair, pkHash);
      await saveKeyWithPassword(recoveredKeyPair, recoverPassword, pkHash);
      setKeyPair(recoveredKeyPair);
      setPublicKey(pk);
      passwordRef.current = recoverPassword;
      
      setPublicKeyHash(pkHash); setActiveIdentity(pkHash);
      
      storeToken(response.token);
      localStorage.setItem('accord_user_id', response.user_id);
      
      setAppState(prev => ({
        ...prev,
        isAuthenticated: true,
        token: response.token,
        user: { id: response.user_id, public_key_hash: pkHash, public_key: pk, created_at: 0, display_name: fingerprint(pkHash) }
      }));
      setIsAuthenticated(true);
      setShowRecoverModal(false);
      setRecoverMnemonic("");
      setRecoverPassword("");
      setHasExistingKey(true);
      
      notificationManager.setCurrentUsername(fingerprint(pkHash));
      
      // Initialize WebSocket
      const socket = new AccordWebSocket(response.token, serverUrl.replace(/^http/, "ws"));
      setupWebSocketHandlers(socket);
      setWs(socket);
      socket.connect();
      
      setTimeout(() => { loadNodes(); loadDmChannels(); }, 100);
    } catch (error) {
      setRecoverError(error instanceof Error ? error.message : "Recovery failed. Check your phrase and password.");
    } finally {
      setRecoverLoading(false);
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
    passwordRef.current = "";
    
    // Clear in-memory encryption state but keep keypair in localStorage for re-login
    setKeyPair(null);
    clearChannelKeyCache();
    setHasExistingKey(hasStoredKeyPair());
    
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

        // Encrypt: use E2EE (Double Ratchet) for DMs, symmetric for channels
        const isDmSend = !!selectedDmChannel;
        if (isDmSend && e2eeManagerRef.current?.isInitialized && appState.token) {
          // DM: use Double Ratchet E2EE
          try {
            const recipientId = selectedDmChannel!.other_user.id;
            await ensureE2EESession(recipientId, appState.token);
            messageToSend = e2eeManagerRef.current.encrypt(recipientId, message);
            isEncrypted = true;
          } catch (error) {
            console.warn('E2EE encrypt failed, falling back to symmetric:', error);
            // Fallback to symmetric encryption
            if (encryptionEnabled && keyPair) {
              try {
                const channelKey = await getChannelKey(keyPair.privateKey, channelToUse);
                messageToSend = await encryptMessage(channelKey, message);
                isEncrypted = true;
              } catch (e2) {
                console.warn('Symmetric encrypt also failed, sending plaintext:', e2);
              }
            }
          }
        } else if (encryptionEnabled && keyPair && channelToUse) {
          // Channel: use symmetric encryption
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
      const token = await getToken();
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
          setPublicKeyHash(pkHash); setActiveIdentity(pkHash);
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
        const socket = new AccordWebSocket(token, serverUrl.replace(/^http/, "ws"));
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

  // Keyboard shortcuts — powered by keyboard.ts manager
  useEffect(() => {
    return initKeyboardShortcuts({
      openSearch: () => setShowSearchOverlay(true),
      openSettings: () => setShowSettings(true),
      toggleShortcutsHelp: () => setShowShortcutsHelp(prev => !prev),
      toggleEmojiPicker: () => setShowInputEmojiPicker(prev => !prev),
      closeTopModal: () => {
        if (showShortcutsHelp) { setShowShortcutsHelp(false); return; }
        if (showSearchOverlay) { setShowSearchOverlay(false); return; }
        if (showSettings) { setShowSettings(false); return; }
        if (showNodeSettings) { setShowNodeSettings(false); return; }
        if (deleteChannelConfirm) { setDeleteChannelConfirm(null); return; }
        if (showNotificationSettings) { setShowNotificationSettings(false); return; }
        if (showCreateNodeModal) { setShowCreateNodeModal(false); return; }
        if (showInviteModal) { setShowInviteModal(false); return; }
        if (showDisplayNamePrompt) { setShowDisplayNamePrompt(false); return; }
        if (showInputEmojiPicker) { setShowInputEmojiPicker(false); return; }
        if (editingMessageId) { handleCancelEdit(); return; }
        if (replyingTo) { handleCancelReply(); return; }
      },
      navigateChannel: (direction: 'up' | 'down') => {
        // Navigate text channels up/down in the sidebar
        const textChannels = channels.filter(c => c.channel_type === 'text');
        if (textChannels.length === 0) return;
        const currentIdx = textChannels.findIndex(c => c.id === selectedChannelId);
        let nextIdx: number;
        if (currentIdx === -1) {
          nextIdx = 0;
        } else {
          nextIdx = direction === 'up'
            ? (currentIdx - 1 + textChannels.length) % textChannels.length
            : (currentIdx + 1) % textChannels.length;
        }
        const next = textChannels[nextIdx];
        handleChannelSelect(next.id, next.name);
      },
      toggleMute: () => {
        // Click the mute button in the voice connection panel
        const btn = document.querySelector('.voice-connection-controls .voice-ctrl-btn:first-child') as HTMLButtonElement | null;
        btn?.click();
      },
      toggleDeafen: () => {
        // Click the deafen button in the voice connection panel
        const btn = document.querySelector('.voice-connection-controls .voice-ctrl-btn:nth-child(2)') as HTMLButtonElement | null;
        btn?.click();
      },
    });
  }, [showShortcutsHelp, showSearchOverlay, showSettings, showNotificationSettings, showCreateNodeModal, showInviteModal, showDisplayNamePrompt, editingMessageId, replyingTo, showInputEmojiPicker, channels, selectedChannelId, handleChannelSelect]);

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

  // Presence helper: determine effective status for a member
  const getPresenceStatus = useCallback((userId: string): import('./types').PresenceStatus => {
    const explicit = presenceMap.get(userId);
    if (explicit) return explicit;
    const lastMsg = lastMessageTimes.get(userId);
    if (lastMsg && Date.now() - lastMsg < 5 * 60 * 1000) {
      return 'online' as import('./types').PresenceStatus;
    }
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

  // Key backup modal
  // Mnemonic backup modal (shown after registration)
  if (showMnemonicModal) {
    return (
      <div className="app">
        <div className="auth-page">
          <div className="auth-card key-backup-card">
            <h2 className="auth-title">🔑 Save Your Recovery Phrase</h2>
            <p className="auth-subtitle">
              This 24-word phrase is the <strong>only way</strong> to recover your identity if you lose access to this browser.
              <strong className="warning" style={{ color: 'var(--yellow)' }}> Write it down and store it safely. It will NOT be shown again.</strong>
            </p>
            <div className="form-group">
              <label className="form-label">Recovery Phrase (24 words)</label>
              <div style={{
                background: 'var(--bg-tertiary)',
                border: '2px solid var(--yellow)',
                borderRadius: '8px',
                padding: '16px',
                fontFamily: 'monospace',
                fontSize: '15px',
                lineHeight: '2',
                wordSpacing: '8px',
                userSelect: 'all',
                cursor: 'text',
              }}>
                {mnemonicPhrase}
              </div>
            </div>
            <div className="form-group" style={{ marginTop: '16px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={mnemonicAcknowledged}
                  onChange={(e) => setMnemonicAcknowledged(e.target.checked)}
                />
                I have written down my recovery phrase and stored it safely
              </label>
            </div>
            <div className="key-backup-actions">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(mnemonicPhrase).catch(() => {});
                  alert('Recovery phrase copied to clipboard! Store it safely and clear your clipboard.');
                }}
                className="btn btn-green"
              >
                Copy to Clipboard
              </button>
              <button
                onClick={() => {
                  setShowMnemonicModal(false);
                  setMnemonicPhrase("");
                  // After registration, go to login
                  if (!isAuthenticated) {
                    setIsLoginMode(true);
                    setPassword("");
                    setAuthError("");
                  }
                }}
                disabled={!mnemonicAcknowledged}
                className="btn btn-primary"
                title={!mnemonicAcknowledged ? "Please acknowledge you saved your phrase" : ""}
              >
                {isAuthenticated ? 'Continue' : 'Continue to Login'}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Recovery modal (enter mnemonic to recover identity)
  if (showRecoverModal) {
    return (
      <div className="app">
        <div className="auth-page">
          <div className="auth-card">
            <button onClick={() => { setShowRecoverModal(false); setRecoverError(""); setRecoverMnemonic(""); setRecoverPassword(""); }} className="auth-back-btn">← Back</button>
            <h2 className="auth-title">🔄 Recover Identity</h2>
            <p className="auth-subtitle">Enter your 24-word recovery phrase and password to restore your identity</p>
            
            <div className="form-group">
              <label className="form-label">Recovery Phrase (24 words)</label>
              <textarea
                placeholder="word1 word2 word3 ... word24"
                value={recoverMnemonic}
                onChange={(e) => setRecoverMnemonic(e.target.value)}
                rows={3}
                className="form-textarea"
                style={{ fontFamily: 'monospace' }}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Password</label>
              <input
                type="password"
                placeholder="Your account password"
                value={recoverPassword}
                onChange={(e) => setRecoverPassword(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') handleRecover(); }}
                className="form-input"
              />
            </div>

            {recoverError && <div className="auth-error">{recoverError}</div>}

            <button
              onClick={handleRecover}
              disabled={recoverLoading || !recoverMnemonic.trim() || !recoverPassword}
              className="btn btn-primary"
            >
              {recoverLoading ? 'Recovering...' : 'Recover Identity'}
            </button>
          </div>
        </div>
      </div>
    );
  }

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

  // First-run setup wizard
  if (showSetupWizard) {
    const handleSetupComplete = async (result: SetupResult) => {
      try {
        // Store identity
        setKeyPair(result.keyPair);
        setPublicKey(result.publicKey);
        setPublicKeyHash(result.publicKeyHash);
        setActiveIdentity(result.publicKeyHash);
        passwordRef.current = result.password;
        if (result.mnemonic) setMnemonicPhrase(result.mnemonic);

        // Store relay URL
        const relayUrl = result.relayUrl;
        localStorage.setItem('accord_server_url', relayUrl);
        api.setBaseUrl(relayUrl);
        setServerUrl(relayUrl);

        // Store mesh preference
        if (result.meshEnabled) {
          localStorage.setItem('accord_mesh_enabled', 'true');
        }

        // Register on the relay
        await api.register(result.publicKey, result.password);
        const response = await api.login(result.publicKey, result.password);
        storeToken(response.token);
        localStorage.setItem('accord_user_id', response.user_id);

        // Save key with token-based wrapping too
        await saveKeyToStorage(result.keyPair, result.publicKeyHash);

        setAppState(prev => ({
          ...prev,
          isAuthenticated: true,
          token: response.token,
          user: { id: response.user_id, public_key_hash: result.publicKeyHash, public_key: result.publicKey, created_at: Date.now() / 1000, display_name: fingerprint(result.publicKeyHash) }
        }));
        setIsAuthenticated(true);

        // Join via invite if provided
        if (result.inviteCode) {
          try { await api.joinNodeByInvite(result.inviteCode, response.token); } catch {}
        }

        // Connect WebSocket
        const wsBaseUrl = relayUrl.replace(/^http/, 'ws');
        const socket = new AccordWebSocket(response.token, wsBaseUrl);
        setupWebSocketHandlers(socket);
        setWs(socket);
        socket.connect();

        setHasExistingKey(true);
        setShowSetupWizard(false);
        setShowWelcomeScreen(false);
        setServerAvailable(true);

        // Prompt for display name
        setShowDisplayNamePrompt(true);

        setTimeout(() => { loadNodes(); loadDmChannels(); }, 100);
      } catch (e: any) {
        setAuthError(e.message || "Setup failed");
        // Fall back to welcome screen
        setShowSetupWizard(false);
        setShowWelcomeScreen(true);
      }
    };

    return (
      <SetupWizard
        onComplete={handleSetupComplete}
        onSkip={() => {
          setShowSetupWizard(false);
          setShowWelcomeScreen(true);
        }}
      />
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
                  {serverAvailable ? (
                    <>
                      <button onClick={() => { setShowWelcomeScreen(false); setIsLoginMode(true); }} className="btn btn-primary">
                        Log in
                      </button>
                      <button onClick={() => { setShowWelcomeScreen(false); setIsLoginMode(false); }} className="btn btn-outline">
                        Create new identity
                      </button>
                      <button onClick={() => setWelcomeMode('invite')} className="btn btn-outline">
                        I have an invite link
                      </button>
                      <button onClick={() => { setShowWelcomeScreen(false); setShowRecoverModal(true); setRecoverError(""); }} className="btn-ghost" style={{ fontSize: '13px', marginTop: '8px', opacity: 0.8 }}>
                        🔄 Recover identity with recovery phrase
                      </button>
                    </>
                  ) : (
                    <>
                      <button onClick={() => setWelcomeMode('invite')} className="btn btn-primary">
                        I have an invite link
                      </button>
                      <button onClick={() => setWelcomeMode('admin')} className="btn btn-outline">
                        Set up a new relay (admin)
                      </button>
                      <button onClick={() => setWelcomeMode('recover')} className="btn-ghost" style={{ fontSize: '13px', marginTop: '8px', opacity: 0.8 }}>
                        🔄 Recover identity (connect to relay first)
                      </button>
                    </>
                  )}
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
              {isLoginMode ? (hasExistingKey ? 'Welcome Back' : 'Login to Accord') : 'Create Identity'}
            </h2>
            <p className="auth-subtitle">
              {isLoginMode 
                ? (hasExistingKey ? 'Enter your password to sign back in' : 'Authenticate with your keypair and password')
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
                  {keyPair || publicKey || hasExistingKey ? (
                    <span className="accent">🔑 Keypair found — enter your password to sign back in</span>
                  ) : localStorage.getItem('accord_public_key_plain') ? (
                    <span className="accent">🔑 Identity remembered — enter your password to log in</span>
                  ) : (
                    <span style={{ color: 'var(--yellow)' }}>⚠️ No identity found on this device — create a new one or recover with your phrase</span>
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

            <div className="auth-toggle" style={{ display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'center' }}>
              <button
                onClick={() => { setIsLoginMode(!isLoginMode); setAuthError(""); setPassword(""); }}
                className="btn-ghost"
              >
                {isLoginMode ? 'Need to create an identity?' : 'Already have a keypair? Login'}
              </button>
              
              <div style={{ borderTop: '1px solid var(--border)', width: '100%', paddingTop: '12px', marginTop: '4px', display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', opacity: 0.6 }}>Lost access to your keypair?</span>
                <button
                  onClick={() => { setShowRecoverModal(true); setRecoverError(""); }}
                  className="btn btn-outline"
                  style={{ width: '100%' }}
                >
                  🔄 Recover with recovery phrase
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Use server data — no mock fallback
  const servers = nodes.map(n => n.name);
  const displayName = (u: User | undefined) => u ? (u.display_name || fingerprint(u.public_key_hash)) : 'Unknown';

  // Helper to determine channel type as number
  const getChannelTypeNum = (ch: Channel): number => {
    if (typeof ch.channel_type === 'number') return ch.channel_type;
    if (ch.channel_type === 'voice') return 2;
    if (ch.channel_type === 'category') return 4;
    return 0; // text
  };

  // Sort channels by position
  const sortedChannels = [...channels].sort((a, b) => (a.position ?? 0) - (b.position ?? 0));
  
  // Separate categories and regular channels
  const categories = sortedChannels.filter(ch => getChannelTypeNum(ch) === 4);
  const nonCategoryChannels = sortedChannels.filter(ch => getChannelTypeNum(ch) !== 4);
  const uncategorizedChannels = nonCategoryChannels.filter(ch => !ch.parent_id);
  const categorizedChannels = (catId: string) => nonCategoryChannels.filter(ch => ch.parent_id === catId);

  const toggleCategory = (catId: string) => {
    setCollapsedCategories(prev => {
      const next = new Set(prev);
      if (next.has(catId)) next.delete(catId);
      else next.add(catId);
      return next;
    });
  };

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
              {nodes[i]?.icon_hash ? (
                <img 
                  src={`${api.getNodeIconUrl(nodes[i].id)}?v=${nodes[i].icon_hash}`}
                  alt={s[0]}
                  style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: 'inherit' }}
                  onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; (e.target as HTMLImageElement).parentElement!.textContent = s[0]; }}
                />
              ) : s[0]}
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
          title="Join or Create Node"
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
                    <button className="connection-retry-btn" onClick={() => { setLastConnectionError(""); ws.retry(); }}>Retry</button>
                  )}
                  {lastConnectionError && connectionInfo.status !== 'connected' && (
                    <span className="connection-error-detail" title={lastConnectionError} style={{ fontSize: 11, color: 'var(--error, #f04747)', display: 'block', marginTop: 2 }}>
                      {lastConnectionError.length > 60 ? lastConnectionError.substring(0, 57) + '...' : lastConnectionError}
                    </span>
                  )}
                </span>
              )}
              {!serverAvailable && <span className="demo-badge">DEMO</span>}
            </div>
            
            <div className="sidebar-admin-buttons">
              {selectedNodeId && hasPermission(selectedNodeId, 'ManageInvites') && (
                <button onClick={handleGenerateInvite} className="sidebar-admin-btn" title="Generate Invite">Invite</button>
              )}
              {selectedNodeId && (
                <button onClick={() => setShowNodeSettings(true)} className="sidebar-admin-btn" title="Node Settings">⚙️</button>
              )}
            </div>
          </div>
          
          {selectedNodeId && userRoles[selectedNodeId] && (
            <div className="sidebar-role">{getRoleBadge(userRoles[selectedNodeId])} {userRoles[selectedNodeId]}</div>
          )}
          {selectedNodeId && nodes.find(n => n.id === selectedNodeId)?.description && (
            <div className="sidebar-description" title={nodes.find(n => n.id === selectedNodeId)?.description}>
              {nodes.find(n => n.id === selectedNodeId)?.description}
            </div>
          )}
        </div>
        
        <div className="channel-list">
          {/* Render a single channel item */}
          {(() => {
            const canDeleteChannel = selectedNodeId && hasPermission(selectedNodeId, 'DeleteChannel');
            
            const renderChannel = (channel: Channel) => {
              const isVoiceChannel = getChannelTypeNum(channel) === 2;
              const isActive = channel.id === selectedChannelId;
              const isConnectedToVoice = isVoiceChannel && voiceChannelId === channel.id;
              const clientUnreads = selectedNodeId ? 
                notificationManager.getChannelUnreads(selectedNodeId, channel.id) : 
                { count: 0, mentions: 0 };
              // Use server unread_count as fallback if client hasn't tracked any
              const channelUnreads = clientUnreads.count > 0 ? clientUnreads : 
                { count: channel.unread_count || 0, mentions: clientUnreads.mentions };
              const hasUnread = channelUnreads.count > 0 || channelUnreads.mentions > 0;
              
              return (
                <div
                  key={channel.id}
                  className={`channel ${isActive ? "active" : ""} ${isConnectedToVoice ? "voice-connected" : ""} ${hasUnread && !isActive ? "unread" : ""}`}
                  title={channel.topic || undefined}
                >
                  <div
                    onClick={() => {
                      if (isVoiceChannel) {
                        if (!isConnectedToVoice) {
                          setVoiceChannelId(channel.id);
                          setVoiceChannelName(channel.name);
                          setVoiceConnectedAt(Date.now());
                        }
                      } else {
                        handleChannelSelect(channel.id, `# ${channel.name}`);
                      }
                    }}
                    style={{ flex: 1, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}
                  >
                    <span style={{ color: isVoiceChannel ? '#8e9297' : undefined }}>
                      {isVoiceChannel ? '🔊' : '#'} {channel.name}
                    </span>
                    {isVoiceChannel && !isConnectedToVoice && (
                      <span style={{ fontSize: '10px', color: '#8e9297', marginLeft: '4px' }}>Voice Channel</span>
                    )}
                    {isConnectedToVoice && (
                      <span style={{ fontSize: '10px', color: '#43b581' }}>●</span>
                    )}
                  </div>
                  <div className="channel-badges">
                    {channelUnreads.mentions > 0 && (
                      <div className="mention-badge">{channelUnreads.mentions > 9 ? '9+' : channelUnreads.mentions}</div>
                    )}
                    {channelUnreads.mentions === 0 && channelUnreads.count > 0 && (
                      <div className="unread-badge">{channelUnreads.count > 99 ? '99+' : channelUnreads.count}</div>
                    )}
                    {canDeleteChannel && (
                      <button onClick={(e) => { e.stopPropagation(); setDeleteChannelConfirm({ id: channel.id, name: channel.name }); }} className="channel-delete-btn" title="Delete channel">×</button>
                    )}
                  </div>
                  {/* Voice channel connected users */}
                  {isConnectedToVoice && voiceChannelId === channel.id && (
                    <div className="voice-channel-users">
                      <div className="voice-channel-user">
                        <div className="voice-user-avatar">
                          {(appState.user?.display_name || "U")[0]}
                        </div>
                        <span className="voice-user-name">{appState.user?.display_name || "You"}</span>
                      </div>
                    </div>
                  )}
                </div>
              );
            };
            
            return (
              <>
                {/* Uncategorized channels */}
                {uncategorizedChannels.map(ch => renderChannel(ch))}
                
                {/* Categories with their children */}
                {categories.map(cat => {
                  const children = categorizedChannels(cat.id);
                  const isCollapsed = collapsedCategories.has(cat.id);
                  return (
                    <div key={cat.id} className="channel-category">
                      <div
                        className="category-header"
                        onClick={() => toggleCategory(cat.id)}
                      >
                        <span className="category-arrow">{isCollapsed ? '▶' : '▼'}</span>
                        <span className="category-name">{cat.name}</span>
                      </div>
                      {!isCollapsed && children.map(ch => renderChannel(ch))}
                    </div>
                  );
                })}
              </>
            );
          })()}
          
          {/* Import Discord Template Button */}
          {selectedNodeId && hasPermission(selectedNodeId, 'ManageNode') && (
            <div style={{ padding: '4px 8px' }}>
              <button onClick={() => setShowTemplateImport(true)} className="btn btn-outline btn-sm" style={{ width: '100%', fontSize: '11px' }}>
                📥 Import Discord Template
              </button>
            </div>
          )}
          
          {/* Create Channel Button for Admins */}
          {selectedNodeId && hasPermission(selectedNodeId, 'CreateChannel') && (
            <div style={{ marginTop: '4px', padding: '0 8px' }}>
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
                    {(dmChannel.other_user_profile?.display_name || "?")[0].toUpperCase()}
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
        
        {/* Voice Connection Panel */}
        {voiceChannelId && (
          <VoiceConnectionPanel
            channelName={voiceChannelName}
            connectedAt={voiceConnectedAt}
            onDisconnect={() => {
              setVoiceChannelId(null);
              setVoiceChannelName("");
              setVoiceConnectedAt(null);
            }}
          />
        )}

        <div className="user-panel">
          <div className="user-avatar">
            {appState.user?.id ? (
              <img 
                src={`${api.getUserAvatarUrl(appState.user.id)}`}
                alt={(appState.user?.display_name || "U")[0]}
                style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '50%' }}
                onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; (e.target as HTMLImageElement).parentElement!.textContent = (appState.user?.display_name || fingerprint(appState.user?.public_key_hash || ''))?.[0] || "U"; }}
              />
            ) : ((appState.user?.display_name || fingerprint(appState.user?.public_key_hash || ''))?.[0] || "U")}
          </div>
          <div className="user-info">
            <div className="username">{appState.user?.display_name || fingerprint(appState.user?.public_key_hash || '') || "You"}</div>
            <div className="user-status" onClick={() => { setStatusInput(customStatus); setShowStatusPopover(true); }} style={{ cursor: 'pointer' }} title="Click to set custom status">
              {customStatus || (appState.isConnected ? "Online" : "Offline")}
            </div>
          </div>
          <button
            onClick={() => setShowConnectionInfo(true)}
            className="user-panel-settings connection-indicator"
            title={appState.isConnected
              ? `Connected${serverHelloVersion ? ` — v${serverHelloVersion}` : ''}${serverBuildHash ? ` (${serverBuildHash.slice(0, 8)})` : ''}\nTrust: ${getTrustIndicator(getCombinedTrust(CLIENT_BUILD_HASH, serverBuildHash, knownHashes)).label}`
              : 'Disconnected'}
          >
            {appState.isConnected ? getTrustIndicator(getCombinedTrust(CLIENT_BUILD_HASH, serverBuildHash, knownHashes)).emoji : '🔴'}
          </button>
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

        {/* Custom Status Popover */}
        {showStatusPopover && (
          <div className="status-popover">
            <div className="status-popover-header">
              <span>Set Custom Status</span>
              <button onClick={() => setShowStatusPopover(false)} className="status-popover-close">×</button>
            </div>
            <input
              type="text"
              className="status-popover-input"
              placeholder="What's on your mind?"
              value={statusInput}
              onChange={(e) => setStatusInput(e.target.value.slice(0, 128))}
              onKeyDown={(e) => { if (e.key === 'Enter') handleSaveCustomStatus(); if (e.key === 'Escape') setShowStatusPopover(false); }}
              maxLength={128}
              autoFocus
            />
            <div className="status-popover-footer">
              <span className="status-popover-count">{statusInput.length}/128</span>
              <div style={{ display: 'flex', gap: '8px' }}>
                {customStatus && (
                  <button className="status-popover-clear" onClick={() => { setStatusInput(""); setCustomStatus(""); api.updateProfile({ custom_status: "" }, appState.token || '').catch(() => {}); setShowStatusPopover(false); }}>Clear</button>
                )}
                <button className="status-popover-save" onClick={handleSaveCustomStatus}>Save</button>
              </div>
            </div>
          </div>
        )}
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
                    {(selectedDmChannel.other_user_profile?.display_name || "?")[0].toUpperCase()}
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
                <span className="chat-topic">
                  {(() => {
                    const ch = channels.find(c => c.id === selectedChannelId);
                    if (ch?.channel_type === 'voice') return `🔊 Voice channel — ${ch.name}`;
                    if (ch?.topic) return ch.topic;
                    return '';
                  })()}
                </span>
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
            <button
              onClick={() => setShowMemberSidebar(prev => !prev)}
              className={`chat-header-btn ${showMemberSidebar ? 'active' : ''}`}
              title="Toggle member list"
            >
              👥
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
          {appState.messages.map((msg, i) => {
            const prevMsg = i > 0 ? appState.messages[i - 1] : null;
            const isGrouped = prevMsg
              && prevMsg.author === msg.author
              && Math.abs(msg.timestamp - prevMsg.timestamp) < 5 * 60 * 1000
              && !msg.reply_to;

            // Date separator
            const msgDate = new Date(msg.timestamp);
            const prevDate = prevMsg ? new Date(prevMsg.timestamp) : null;
            const showDateSep = !prevDate
              || msgDate.toDateString() !== prevDate.toDateString();

            const formatDateSep = (d: Date) => {
              const now = new Date();
              const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
              const msgDay = new Date(d.getFullYear(), d.getMonth(), d.getDate());
              const diff = today.getTime() - msgDay.getTime();
              if (diff === 0) return 'Today';
              if (diff === 86400000) return 'Yesterday';
              return d.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
            };

            // Relative timestamp
            const formatRelativeTime = (ts: number) => {
              const diff = Date.now() - ts;
              if (diff < 60000) return 'just now';
              if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
              if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
              return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            };

            return (
              <React.Fragment key={msg.id || i}>
                {showDateSep && (
                  <div className="date-separator">
                    <span className="date-separator-text">{formatDateSep(msgDate)}</span>
                  </div>
                )}
                <div className={`message ${msg.reply_to ? 'reply-message' : ''} ${isGrouped ? 'message-grouped' : ''}`} data-message-id={msg.id}>
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
              {!isGrouped && <div className="message-avatar">
                {msg.sender_id ? (
                  <img 
                    src={`${api.getUserAvatarUrl(msg.sender_id)}`}
                    alt={(msg.author || "?")[0]}
                    style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '50%' }}
                    onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; (e.target as HTMLImageElement).parentElement!.textContent = (msg.author || "?")[0]; }}
                  />
                ) : (msg.author || "?")[0]}
              </div>}
              {isGrouped && <div className="message-avatar-spacer"><span className="message-hover-time">{new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span></div>}
              <div className="message-body">
                {!isGrouped && (
                <div className="message-header">
                  <span className="message-author" style={{ color: (() => { const am = members.find(m => displayName(m.user) === msg.author || fingerprint(m.public_key_hash) === msg.author); return am ? getMemberRoleColor(am.user_id) : undefined; })() || undefined }} onContextMenu={(e) => {
                    const authorMember = members.find(m => displayName(m.user) === msg.author || fingerprint(m.public_key_hash) === msg.author);
                    if (authorMember) {
                      handleContextMenu(e, authorMember.user_id, authorMember.public_key_hash, msg.author, authorMember.profile?.bio, authorMember.user);
                    }
                  }}>{msg.author}</span>
                  <span className="message-time">{formatRelativeTime(msg.timestamp)}</span>
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
                      {canDeleteMessage(msg) && (
                        <button
                          onClick={() => msg.pinned_at ? handleUnpinMessage(msg.id) : handlePinMessage(msg.id)}
                          className="message-action-btn"
                          title={msg.pinned_at ? "Unpin message" : "Pin message"}
                        >
                          📌
                        </button>
                      )}
                    </div>
                  )}
                </div>
                )}
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
                      __html: renderMessageMarkdown(msg.content, notificationManager.currentUsername) 
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

                  {hoveredMessageId === msg.id && appState.user && (
                    <div className="add-reaction-container quick-react-bar">
                      {['👍', '❤️', '😂', '🔥', '👀'].map((emoji) => (
                        <button
                          key={emoji}
                          className="quick-react-btn"
                          onClick={() => handleToggleReaction(msg.id, emoji)}
                          title={`React with ${emoji}`}
                        >
                          {emoji}
                        </button>
                      ))}
                      <button 
                        className="add-reaction-btn"
                        onClick={() => setShowEmojiPicker(showEmojiPicker === msg.id ? null : msg.id)}
                        title="More reactions"
                      >
                        +
                      </button>

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
              {/* Read receipt indicators */}
              {selectedChannelId && (() => {
                const receipts = readReceipts.get(selectedChannelId) || [];
                const currentUserId = appState.user?.id;
                const readBy = receipts.filter(
                  r => r.message_id === msg.id && r.user_id !== currentUserId
                );
                if (readBy.length === 0) return null;
                return (
                  <div className="read-receipts" style={{ display: 'flex', gap: '2px', justifyContent: 'flex-end', padding: '2px 8px' }}>
                    {readBy.slice(0, 5).map(r => {
                      const member = members.find(m => m.user_id === r.user_id);
                      const name = member?.profile?.display_name || member?.user?.display_name || r.user_id.substring(0, 6);
                      return (
                        <span
                          key={r.user_id}
                          className="read-receipt-avatar"
                          title={`Read by ${name}`}
                          style={{
                            width: '16px', height: '16px', borderRadius: '50%',
                            backgroundColor: '#5865F2', color: '#fff', fontSize: '8px',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            lineHeight: 1,
                          }}
                        >
                          {name[0]?.toUpperCase()}
                        </span>
                      );
                    })}
                    {readBy.length > 5 && (
                      <span style={{ fontSize: '10px', color: '#8e9297' }}>+{readBy.length - 5}</span>
                    )}
                  </div>
                );
              })()}
            </div>
              </React.Fragment>
            );
          })}

          {/* Scroll to bottom button */}
          {showScrollToBottom && (
            <button className="scroll-to-bottom-btn" onClick={scrollToBottom}>
              ↓ {newMessageCount > 0 && <span className="scroll-to-bottom-count">{newMessageCount}</span>}
            </button>
          )}
          
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
            ref={messageInputRef}
            className="message-input"
            placeholder={`Message ${activeChannel}`}
            value={message}
            rows={1}
            onChange={(e) => {
              setMessage(e.target.value);
              e.target.style.height = 'auto';
              e.target.style.height = Math.min(e.target.scrollHeight, 200) + 'px';
              if (selectedChannelId) {
                sendTypingIndicator(selectedChannelId);
              }
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleSendMessage();
              }
            }}
          />
          <EmojiPickerButton
            isOpen={showInputEmojiPicker}
            onToggle={() => setShowInputEmojiPicker(prev => !prev)}
            onSelect={handleInsertEmoji}
            onClose={() => setShowInputEmojiPicker(false)}
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
        <Suspense fallback={<LoadingSpinner />}>
        <VoiceChat
          ws={ws}
          currentUserId={localStorage.getItem('accord_user_id')}
          channelId={voiceChannelId}
          channelName={voiceChannelName}
          onLeave={() => {
            setVoiceChannelId(null);
            setVoiceChannelName("");
            setVoiceConnectedAt(null);
          }}
        />
        </Suspense>
      )}

      {/* Member sidebar */}
      {showMemberSidebar && <div className="member-sidebar">
        <div className="member-header">Members — {members.filter(m => m.user).length}</div>
        {(() => {
          const currentUserId = localStorage.getItem('accord_user_id');
          const canKick = selectedNodeId && hasPermission(selectedNodeId, 'KickMembers');
          
          const renderMember = (member: NodeMember & { user: User }) => {
            const isCurrentUser = member.user_id === currentUserId;
            const presence = getPresenceStatus(member.user_id);
            return (
              <div key={member.user?.id || member.user_id} className={`member ${presence === 'offline' ? 'member-offline' : ''}`}
                onContextMenu={(e) => handleContextMenu(e, member.user_id, member.public_key_hash, displayName(member.user), member.profile?.bio, member.user)}
              >
                <div className="member-avatar-wrapper">
                  <div className="member-avatar">
                    <img 
                      src={`${api.getUserAvatarUrl(member.user_id)}`}
                      alt={displayName(member.user)[0]}
                      style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '50%' }}
                      onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; (e.target as HTMLImageElement).parentElement!.textContent = displayName(member.user)[0]; }}
                    />
                  </div>
                  <span className={`presence-dot presence-${presence}`} title={presence}></span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span className="member-name" style={{ color: getMemberRoleColor(member.user_id) || undefined }}>{displayName(member.user)}</span>
                    <span className="member-role-badge" title={member.role}>{getRoleBadge(member.role)}</span>
                  </div>
                  {member.profile?.custom_status && (
                    <span className="member-custom-status">{member.profile.custom_status}</span>
                  )}
                </div>
                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  {!isCurrentUser && (
                    <button onClick={(e) => { e.stopPropagation(); openDmWithUser(member.user); }} className="member-action-btn" title="Send DM">DM</button>
                  )}
                  {canKick && !isCurrentUser && (
                    <button onClick={(e) => { e.stopPropagation(); setShowRolePopup({ userId: member.user_id, x: e.clientX, y: e.clientY }); }} className="member-action-btn" title="Manage roles">Roles</button>
                  )}
                  {canKick && !isCurrentUser && (
                    <button onClick={(e) => { e.stopPropagation(); handleKickMember(member.user_id, displayName(member.user)); }} className="member-action-btn danger" title="Kick member">Kick</button>
                  )}
                </div>
              </div>
            );
          };

          // Group by hoisted roles
          const hoistedRoles = nodeRoles.filter(r => r.hoist).sort((a, b) => b.position - a.position);
          const membersWithUser = sortedMembers.filter(m => m.user);
          
          if (hoistedRoles.length === 0) {
            // No roles — show Online/Offline sections
            const online = membersWithUser.filter(m => getPresenceStatus(m.user_id) !== 'offline');
            const offline = membersWithUser.filter(m => getPresenceStatus(m.user_id) === 'offline');
            return (
              <>
                {online.length > 0 && (
                  <>
                    <div className="role-section-header">Online — {online.length}</div>
                    {online.map(m => renderMember(m))}
                  </>
                )}
                {offline.length > 0 && (
                  <>
                    <div className="role-section-header" style={{ color: '#72767d' }}>Offline — {offline.length}</div>
                    {offline.map(m => renderMember(m))}
                  </>
                )}
              </>
            );
          }
          
          // With hoisted roles: group members by highest hoisted role
          const assigned = new Set<string>();
          const sections: { name: string; color?: string | null; members: Array<NodeMember & { user: User }> }[] = [];
          
          for (const role of hoistedRoles) {
            const roleMembers = membersWithUser.filter(m => {
              if (assigned.has(m.user_id)) return false;
              const highest = getMemberHighestHoistedRole(m.user_id);
              return highest?.id === role.id;
            });
            roleMembers.forEach(m => assigned.add(m.user_id));
            sections.push({ name: role.name, color: role.color, members: roleMembers });
          }
          
          // Put all members not assigned to hoisted roles in Online/Offline
          const unassigned = membersWithUser.filter(m => !assigned.has(m.user_id));
          const online = unassigned.filter(m => getPresenceStatus(m.user_id) !== 'offline');
          const offline = unassigned.filter(m => getPresenceStatus(m.user_id) === 'offline');
          
          return (
            <>
              {sections.filter(s => s.members.length > 0).map(s => (
                <React.Fragment key={s.name}>
                  <div className="role-section-header" style={{ color: s.color || undefined }}>{s.name} — {s.members.length}</div>
                  {s.members.map(m => renderMember(m))}
                </React.Fragment>
              ))}
              {online.length > 0 && (
                <>
                  <div className="role-section-header">Online — {online.length}</div>
                  {online.map(m => renderMember(m))}
                </>
              )}
              {offline.length > 0 && (
                <>
                  <div className="role-section-header" style={{ color: '#72767d' }}>Offline — {offline.length}</div>
                  {offline.map(m => renderMember(m))}
                </>
              )}
              {membersWithUser.length === 0 && members.length === 0 && (
                <div className="members-empty">
                  {nodes.length === 0 ? 'Join or create a node to see members' : 'No members loaded'}
                </div>
              )}
            </>
          );
        })()}
      </div>}

      {/* Role Assignment Popup */}
      {showRolePopup && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, zIndex: 1050 }} onClick={() => setShowRolePopup(null)}>
          <div style={{
            position: 'absolute',
            top: Math.min(showRolePopup.y, window.innerHeight - 300),
            left: Math.min(showRolePopup.x, window.innerWidth - 220),
            background: '#2f3136',
            border: '1px solid #40444b',
            borderRadius: '6px',
            padding: '8px',
            minWidth: '200px',
            maxHeight: '280px',
            overflowY: 'auto',
            boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: '12px', color: '#b9bbbe', fontWeight: 600, padding: '4px 8px', marginBottom: '4px' }}>ASSIGN ROLES</div>
            {nodeRoles.length === 0 ? (
              <div style={{ padding: '8px', color: '#72767d', fontSize: '13px' }}>No roles available</div>
            ) : nodeRoles.sort((a, b) => b.position - a.position).map(role => {
              const userHasRole = (memberRolesMap[showRolePopup.userId] || []).some(r => r.id === role.id);
              return (
                <label key={role.id} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '13px', color: '#dcddde' }}
                  onMouseEnter={e => (e.currentTarget.style.background = '#40444b')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                  <input type="checkbox" checked={userHasRole} onChange={() => toggleMemberRole(showRolePopup.userId, role.id, userHasRole)} />
                  <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: role.color || '#99aab5', flexShrink: 0 }} />
                  {role.name}
                </label>
              );
            })}
          </div>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div className="error-toast">
          <span style={{ flex: 1 }}>{error}</span>
          <button onClick={() => setError("")} className="error-toast-close">×</button>
        </div>
      )}

      {/* Join/Create Node Modal — Join is primary, Create is secondary */}
      {showCreateNodeModal && !showJoinNodeModal && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3>Join a Node</h3>
            <p>Enter an invite link to join an existing community.</p>
            <div className="form-group">
              <label className="form-label">Invite Code or Link</label>
              <input type="text" placeholder="accord://host/invite/CODE or just the code" value={joinInviteCode} onChange={(e) => setJoinInviteCode(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && joinInviteCode.trim()) handleJoinNode(); }} className="form-input" />
            </div>
            {joinError && <div className="auth-error">{joinError}</div>}
            <div className="modal-actions">
              <button onClick={handleJoinNode} disabled={joiningNode || !joinInviteCode.trim()} className="btn btn-primary">{joiningNode ? 'Joining...' : 'Join Node'}</button>
              <button onClick={() => { setShowCreateNodeModal(false); setJoinInviteCode(""); setJoinError(""); }} className="btn btn-outline">Cancel</button>
            </div>
            <div style={{ borderTop: '1px solid var(--border)', marginTop: '16px', paddingTop: '16px', textAlign: 'center' }}>
              <p style={{ fontSize: '13px', opacity: 0.7, marginBottom: '8px' }}>Or create your own community</p>
              <button onClick={() => setShowJoinNodeModal(true)} className="btn-ghost"><strong>Create a New Node</strong></button>
            </div>
          </div>
        </div>
      )}

      {/* Create Node Modal (secondary) */}
      {showJoinNodeModal && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3>Create a Node</h3>
            <p>Start a new community and invite others. A #general channel will be created automatically.</p>
            <div className="form-group">
              <label className="form-label">Node Name</label>
              <input type="text" placeholder="My Community" value={newNodeName} onChange={(e) => {
                const val = e.target.value;
                setNewNodeName(val);
                // Detect if user pasted an invite link into the create form
                if (val.includes('invite/') || val.includes('accord://') || val.match(/^[A-Za-z0-9]{6,}$/)) {
                  const parsed = parseInviteLink(val);
                  if (parsed) {
                    // Switch to join flow with the detected invite
                    setNewNodeName("");
                    setJoinInviteCode(val);
                    setShowJoinNodeModal(false); // Go back to join modal
                  }
                }
              }} onKeyDown={(e) => { if (e.key === 'Enter') handleCreateNode(); }} className="form-input" />
              {newNodeName && parseInviteLink(newNodeName) && (
                <p style={{ color: 'var(--accent)', fontSize: '12px', marginTop: '4px' }}>
                  💡 This looks like an invite link — <button className="btn-ghost" style={{ fontSize: '12px', textDecoration: 'underline' }} onClick={() => { setJoinInviteCode(newNodeName); setNewNodeName(""); setShowJoinNodeModal(false); }}>switch to Join?</button>
                </p>
              )}
            </div>
            <div className="form-group">
              <label className="form-label">Description (optional)</label>
              <input type="text" placeholder="What's this node about?" value={newNodeDescription} onChange={(e) => setNewNodeDescription(e.target.value)} className="form-input" />
            </div>
            <div className="modal-actions">
              <button onClick={handleCreateNode} disabled={creatingNode || !newNodeName.trim()} className="btn btn-green">{creatingNode ? 'Creating...' : 'Create Node'}</button>
              <button onClick={() => { setShowJoinNodeModal(false); setNewNodeName(""); setNewNodeDescription(""); }} className="btn btn-outline">Cancel</button>
            </div>
            <div style={{ borderTop: '1px solid var(--border)', marginTop: '16px', paddingTop: '16px', textAlign: 'center' }}>
              <button onClick={() => setShowJoinNodeModal(false)} className="btn-ghost">Have an invite code? <strong>Join a Node</strong></button>
            </div>
          </div>
        </div>
      )}

      {/* Invite Modal */}
      {showInviteModal && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3>Invite Link Generated</h3>
            <p>Share this link to invite others to your node. The relay address is encoded for privacy.</p>
            <div className="modal-code-block" style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.85em' }}>{generatedInvite}</div>
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

      {/* Delete Channel Confirmation Modal */}
      {deleteChannelConfirm && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3>Delete Channel</h3>
            <p>Are you sure you want to delete <strong>#{deleteChannelConfirm.name}</strong>? This action cannot be undone. All messages will be permanently lost.</p>
            <div className="modal-actions">
              <button onClick={() => handleDeleteChannelConfirmed(deleteChannelConfirm.id)} className="btn btn-red">Delete Channel</button>
              <button onClick={() => setDeleteChannelConfirm(null)} className="btn btn-outline">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Discord Template Import Modal */}
      {showTemplateImport && selectedNodeId && (
        <div className="modal-overlay">
          <div className="modal-card" style={{ maxWidth: '480px' }}>
            <h3>📥 Import Discord Template</h3>
            {!templateResult ? (
              <>
                <p style={{ color: '#b9bbbe', fontSize: '14px' }}>Paste a discord.new link, discord.com/template link, or raw template code.</p>
                <div className="form-group">
                  <input
                    type="text"
                    placeholder="discord.new/CODE or template code"
                    value={templateInput}
                    onChange={(e) => setTemplateInput(e.target.value)}
                    className="form-input"
                    disabled={templateImporting}
                  />
                </div>
                {templateError && <div style={{ color: '#f04747', fontSize: '13px', marginBottom: '8px' }}>{templateError}</div>}
                <div className="modal-actions">
                  <button
                    className="btn btn-green"
                    disabled={templateImporting || !templateInput.trim()}
                    onClick={async () => {
                      setTemplateError('');
                      setTemplateImporting(true);
                      try {
                        // Parse template code from URL
                        let code = templateInput.trim();
                        const m1 = code.match(/discord\.new\/([A-Za-z0-9]+)/);
                        const m2 = code.match(/discord\.com\/template\/([A-Za-z0-9]+)/);
                        if (m1) code = m1[1];
                        else if (m2) code = m2[1];
                        
                        const result = await api.importDiscordTemplate(selectedNodeId, code, appState.token || '');
                        setTemplateResult(result);
                      } catch (err: any) {
                        setTemplateError(err.message || 'Import failed');
                      } finally {
                        setTemplateImporting(false);
                      }
                    }}
                  >
                    {templateImporting ? '⏳ Importing...' : 'Import'}
                  </button>
                  <button className="btn btn-outline" onClick={() => { setShowTemplateImport(false); setTemplateInput(''); setTemplateError(''); setTemplateResult(null); }}>Cancel</button>
                </div>
              </>
            ) : (
              <>
                <div style={{ color: '#43b581', marginBottom: '12px', fontSize: '14px' }}>✅ Import complete!</div>
                <div style={{ color: '#dcddde', fontSize: '13px', lineHeight: '1.6' }}>
                  {templateResult.roles_created !== undefined && <div>Roles created: <strong>{templateResult.roles_created}</strong></div>}
                  {templateResult.channels_created !== undefined && <div>Channels created: <strong>{templateResult.channels_created}</strong></div>}
                  {templateResult.categories_created !== undefined && <div>Categories created: <strong>{templateResult.categories_created}</strong></div>}
                </div>
                <div className="modal-actions" style={{ marginTop: '16px' }}>
                  <button className="btn btn-green" onClick={() => {
                    setShowTemplateImport(false);
                    setTemplateInput('');
                    setTemplateResult(null);
                    setTemplateError('');
                    if (selectedNodeId) {
                      loadChannels(selectedNodeId);
                      loadRoles(selectedNodeId);
                    }
                  }}>Done</button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Node Settings Modal */}
      {showNodeSettings && selectedNodeId && (() => {
        const currentNode = nodes.find(n => n.id === selectedNodeId);
        if (!currentNode) return null;
        return (
          <Suspense fallback={<LoadingSpinner />}>
          <NodeSettings
            isOpen={showNodeSettings}
            onClose={() => setShowNodeSettings(false)}
            node={currentNode}
            token={appState.token || ''}
            userRole={userRoles[selectedNodeId] || 'member'}
            onNodeUpdated={(updatedNode) => {
              setNodes(prev => prev.map(n => n.id === updatedNode.id ? updatedNode : n));
            }}
            onLeaveNode={() => {
              setSelectedNodeId(null);
              setChannels([]);
              setMembers([]);
              loadNodes();
            }}
          />
          </Suspense>
        );
      })()}

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
      <Suspense fallback={<LoadingSpinner />}>
      <NotificationSettings
        isOpen={showNotificationSettings}
        onClose={() => setShowNotificationSettings(false)}
        preferences={notificationPreferences}
        onPreferencesChange={handleNotificationPreferencesChange}
      />
      </Suspense>

      {/* Settings Modal */}
      <Suspense fallback={<LoadingSpinner />}>
      <Settings
        isOpen={showSettings}
        onClose={() => setShowSettings(false)}
        onShowShortcuts={() => setShowShortcutsHelp(true)}
        currentUser={appState.user}
        knownHashes={knownHashes}
        serverInfo={{
          version: serverHelloVersion,
          buildHash: serverBuildHash,
          connectedSince,
          relayAddress: api.getBaseUrl(),
          isConnected: appState.isConnected,
        }}
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
      </Suspense>

      {/* Connection Info Modal */}
      {showConnectionInfo && (
        <div className="settings-overlay" onClick={() => setShowConnectionInfo(false)}>
          <div
            className="connection-info-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="connection-info-header">
              <h3>Connection Info</h3>
              <button className="settings-close" onClick={() => setShowConnectionInfo(false)}>×</button>
            </div>
            <div className="connection-info-body">
              <div className="connection-info-row">
                <span className="connection-info-label">Status</span>
                <span className="connection-info-value">
                  {appState.isConnected ? '🟢 Connected' : '🔴 Disconnected'}
                </span>
              </div>
              {serverHelloVersion && (
                <div className="connection-info-row">
                  <span className="connection-info-label">Server Version</span>
                  <span className="connection-info-value">{serverHelloVersion}</span>
                </div>
              )}
              {serverBuildHash && (
                <div className="connection-info-row">
                  <span className="connection-info-label">Build Hash</span>
                  <span
                    className="connection-info-value copyable"
                    title="Click to copy"
                    onClick={() => { navigator.clipboard.writeText(serverBuildHash); }}
                  >
                    <code>{serverBuildHash}</code>
                    <span className="copy-hint">📋</span>
                  </span>
                </div>
              )}
              {connectedSince && (
                <div className="connection-info-row">
                  <span className="connection-info-label">Connected Since</span>
                  <span className="connection-info-value">
                    {new Date(connectedSince).toLocaleString()}
                  </span>
                </div>
              )}
              <div className="connection-info-row">
                <span className="connection-info-label">Relay Address</span>
                <span className="connection-info-value">
                  <code>{api.getBaseUrl()}</code>
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

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
                        {(msg.author || "?")[0]}
                      </div>
                      <span style={{ fontWeight: 600, marginRight: '8px' }}>
                        {msg.author}
                      </span>
                      <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                        {new Date(msg.timestamp).toLocaleDateString()} at {msg.time}
                      </span>
                    </div>
                    <div
                      className="message-content"
                      style={{
                        marginLeft: '32px',
                        lineHeight: '1.4',
                      }}
                      dangerouslySetInnerHTML={{
                        __html: renderMessageMarkdown(msg.content, notificationManager.currentUsername),
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
              {SHORTCUTS.map((s, i) => (
                <div className="shortcut-row" key={i}><kbd>{s.label}</kbd><span>{s.description}</span></div>
              ))}
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