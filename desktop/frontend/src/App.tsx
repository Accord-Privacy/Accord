import React, { useState, useEffect, useCallback, useRef } from "react";
import { api, parseInviteLink, generateInviteLink, storeRelayToken, storeRelayUserId, getRelayToken, getRelayUserId, detectSameOriginRelay } from "./api";
import { AccordWebSocket, ConnectionInfo } from "./ws";
import { AppState, Message, WsIncomingMessage, Node, Channel, NodeMember, User, TypingUser, TypingStartMessage, DmChannelWithInfo, ParsedInviteLink, Role, ReadReceipt, ReadReceiptMessage, InstalledBot, BotResponseMessage, BatchMemberEntry } from "./types";
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
import { storeToken as _storeToken, getToken, clearToken } from "./tokenStorage";

/** Store token in persistent storage AND update the API client */
async function storeToken(token: string, lifetimeMs?: number): Promise<void> {
  api.setToken(token);
  return _storeToken(token, lifetimeMs);
}
import { getRelayManager, RelayManager } from "./RelayManager";
import { StagedFile } from "./FileManager";
import { notificationManager, NotificationPreferences } from "./notifications";
import { SetupWizard, SetupResult } from "./SetupWizard";
import { listIdentities } from "./identityStorage";
import { initHashVerifier, getKnownHashes, onHashListUpdate } from "./hashVerifier";
import { E2EEManager, type PreKeyBundle, SenderKeyStore, isSenderKeyEnvelope, encryptChannelMessage, decryptChannelMessage, buildDistributionMessage, parseDistributionMessage, saveIdentityKeys, loadIdentityKeys, saveSenderKeyStore, loadSenderKeyStore, generateIdentityKeyPair, generateSignedPreKey, generateOneTimePreKeys, buildPreKeyBundle } from "./e2ee";
import { initKeyboardShortcuts } from "./keyboard";
import { initTheme } from "./themes";
import { setCustomEmojis } from "./markdown";
import { setNodeCustomEmojis } from "./customEmojiStore";
import { UpdateBanner } from "./UpdateChecker";
import {
  AppContext,
  MnemonicModal, RecoverModal, KeyBackupScreen,
  ServerList, ChannelSidebar, ChatArea, MemberSidebar, AppModals,
} from "./components";

// Utility: robust clipboard copy that works in non-secure contexts
async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for non-HTTPS contexts
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      ta.style.top = '-9999px';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}

// Helper: truncate a public key hash to a short fingerprint for display
function fingerprint(publicKeyHash: string): string {
  if (!publicKeyHash || publicKeyHash.length < 16) return publicKeyHash || 'unknown';
  return publicKeyHash.substring(0, 8) + '...' + publicKeyHash.substring(publicKeyHash.length - 8);
}

// Initialize theme immediately on module load (before first render)
initTheme();

/** Distribute a sender key to all channel members via WS. */
function distributeSenderKeyToChannel(
  _ws: AccordWebSocket,
  channelId: string,
  _sk: import('./e2ee/senderKeys').SenderKeyPrivate,
  excludeUserId?: string,
) {
  // This is called in the context of the App component where e2eeManagerRef is available.
  // We pass the ws and use a global reference pattern.
  // Note: actual member list iteration happens inside App via the membersRef.
  // This is a simplified version — in production you'd iterate channel members.
  // For now we rely on the server's sender_key_new_member events for distribution.
  console.log(`Sender key rotated for channel ${channelId}, excluding ${excludeUserId}`);
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
  const [copyButtonText, setCopyButtonText] = useState('Copy to Clipboard');
  const [mnemonicConfirmStep, setMnemonicConfirmStep] = useState(0);
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
  const [slowModeCooldown, setSlowModeCooldown] = useState(0); // seconds remaining
  const [slowModeSeconds, setSlowModeSeconds] = useState(0); // channel's slow mode setting
  const [messageError, setMessageError] = useState<string>(''); // auto-mod / slow mode errors
  const [activeChannel, setActiveChannel] = useState("# general");
  const [activeServer, setActiveServer] = useState(0);
  const [serverAvailable, setServerAvailable] = useState(false);
  const [ws, setWs] = useState<AccordWebSocket | null>(null);
  const relayManagerRef = useRef<RelayManager>(getRelayManager());
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
    if (hasStoredKeyPair()) {
      // Have keys — but do we have a valid session?
      const token = localStorage.getItem('accord_auth_token');
      if (token) return false; // Have both keys and token, skip wizard
      // Have keys but no token — show login to get password and re-auth
      return true;
    }
    // Also check localStorage identity index
    const idx = localStorage.getItem('accord_identity_index');
    if (idx) {
      try {
        if (JSON.parse(idx).length > 0) {
          const token = localStorage.getItem('accord_auth_token');
          if (token) return false;
          return true; // Have identity but no token
        }
      } catch {}
    }
    // Check legacy keys
    if (localStorage.getItem('accord_public_key')) {
      const token = localStorage.getItem('accord_auth_token');
      if (token) return false;
      return true;
    }
    return true;
  });

  // Keyboard shortcuts help state
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false);

  // Member sidebar visibility
  const [showMemberSidebar, setShowMemberSidebar] = useState(true);

  // Message input emoji picker state
  const [showInputEmojiPicker, setShowInputEmojiPicker] = useState(false);
  const [stagedFiles, setStagedFiles] = useState<StagedFile[]>([]);
  const messageInputRef = useRef<HTMLTextAreaElement>(null);
  const loadNodesRef = useRef<(() => Promise<void>) | undefined>(undefined);
  const creatingNodeRef = useRef(false);

  // Refs to avoid stale closures in setupWebSocketHandlers
  const membersRef = useRef(members);
  const dmChannelsRef = useRef(dmChannels);
  const nodesRef = useRef(nodes);
  const channelsRef = useRef(channels);
  const selectedChannelIdRef = useRef(selectedChannelId);
  const selectedDmChannelRef = useRef(selectedDmChannel);
  const serverUrlRef = useRef(serverUrl);

  // E2EE manager for 1:1 DM Double Ratchet encryption
  const e2eeManagerRef = useRef<E2EEManager | null>(null);
  const senderKeyStoreRef = useRef<SenderKeyStore>(new SenderKeyStore());
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

  // Profile card popup state
  const [profileCardTarget, setProfileCardTarget] = useState<{ userId: string; x: number; y: number; user?: User; profile?: import('./types').UserProfile; roles?: Role[]; joinedAt?: number; roleColor?: string } | null>(null);

  // User blocking state
  const [blockedUsers, setBlockedUsers] = useState<Set<string>>(new Set());
  const [showBlockConfirm, setShowBlockConfirm] = useState<{ userId: string; displayName: string } | null>(null);

  // Typing indicators state
  const [typingUsers, setTypingUsers] = useState<Map<string, TypingUser[]>>(new Map());
  const [typingTimeouts, setTypingTimeouts] = useState<Map<string, number>>(new Map());
  const [lastTypingSent, setLastTypingSent] = useState<number>(0);
  const typingIndicatorsEnabled = useState(() => 
    localStorage.getItem('accord-typing-indicators') !== 'false'
  )[0];

  // Read receipts state: channelId -> ReadReceipt[]
  const [readReceipts, setReadReceipts] = useState<Map<string, ReadReceipt[]>>(new Map());

  // Bot API v2 state
  const [installedBots, setInstalledBots] = useState<InstalledBot[]>([]);
  const [botResponses, setBotResponses] = useState<BotResponseMessage[]>([]);
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

  // Block/unblock user handlers
  const handleBlockUser = useCallback(async (userId: string) => {
    if (!appState.token) return;
    try {
      await api.blockUser(userId, appState.token);
      setBlockedUsers(prev => new Set(prev).add(userId));
      setShowBlockConfirm(null);
    } catch (err) {
      console.error('Failed to block user:', err);
      setError('Failed to block user');
      setTimeout(() => setError(''), 3000);
    }
  }, [appState.token]);

  const handleUnblockUser = useCallback(async (userId: string) => {
    if (!appState.token) return;
    try {
      await api.unblockUser(userId, appState.token);
      setBlockedUsers(prev => {
        const next = new Set(prev);
        next.delete(userId);
        return next;
      });
    } catch (err) {
      console.error('Failed to unblock user:', err);
      setError('Failed to unblock user');
      setTimeout(() => setError(''), 3000);
    }
  }, [appState.token]);

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
      const userId = localStorage.getItem('accord_user_id') || '';
      const password = passwordRef.current;
      const toBase64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

      // Try to load persisted identity keys
      const storedKeys = password && userId ? loadIdentityKeys(userId, password) : null;
      if (storedKeys) {
        // Existing user — restore persisted keys (no need to republish bundle)
        manager.initializeWithKeys(
          storedKeys.identityKeyPair,
          storedKeys.signedPreKey,
          storedKeys.oneTimePreKeys,
        );
        console.log('E2EE initialized from persisted identity keys');
      } else {
        // Fresh registration — generate keys explicitly so we can persist them
        const identityKeyPair = generateIdentityKeyPair();
        const signedPreKey = generateSignedPreKey();
        const oneTimePreKeys = generateOneTimePreKeys(10);

        manager.initializeWithKeys(identityKeyPair, signedPreKey, oneTimePreKeys);

        // Persist for future logins
        if (password && userId) {
          saveIdentityKeys(userId, { identityKeyPair, signedPreKey, oneTimePreKeys }, password);
        }

        // Publish prekey bundle to server
        const bundle = buildPreKeyBundle(identityKeyPair, signedPreKey, oneTimePreKeys[0]);
        await api.publishKeyBundle(
          toBase64(bundle.identityKey),
          toBase64(bundle.signedPrekey),
          bundle.oneTimePrekey ? [toBase64(bundle.oneTimePrekey)] : [],
          token,
        );
        console.log('E2EE initialized with fresh keys and prekey bundle published');
      }

      e2eeManagerRef.current = manager;

      // Load persisted sender key store
      if (password && userId) {
        const loadedStore = loadSenderKeyStore(userId, password);
        if (loadedStore) {
          senderKeyStoreRef.current = loadedStore;
          console.log('Sender key store loaded from persistence');
        }
      }
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

  // Fetch blocked users on login
  useEffect(() => {
    if (isAuthenticated && appState.token) {
      api.getBlockedUsers(appState.token).then(resp => {
        setBlockedUsers(new Set(resp.blocked_users.map(b => b.user_id)));
      }).catch(err => console.warn('Failed to load blocked users:', err));
    }
  }, [isAuthenticated, appState.token]);

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
          localStorage.setItem('accord_server_url', sameOrigin);
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

  // Keep refs in sync for WebSocket handler closure
  useEffect(() => { membersRef.current = members; }, [members]);
  useEffect(() => { dmChannelsRef.current = dmChannels; }, [dmChannels]);
  useEffect(() => { nodesRef.current = nodes; }, [nodes]);
  useEffect(() => { channelsRef.current = channels; }, [channels]);
  useEffect(() => { selectedChannelIdRef.current = selectedChannelId; }, [selectedChannelId]);
  useEffect(() => { selectedDmChannelRef.current = selectedDmChannel; }, [selectedDmChannel]);
  useEffect(() => { serverUrlRef.current = serverUrl; }, [serverUrl]);

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

    socket.on('error', (err: any) => {
      // Server-sent errors (auto-mod, slow mode) have { type: "error", error: "..." }
      if (err && typeof err === 'object' && err.error && typeof err.error === 'string') {
        // Show as a user-facing message error toast
        setMessageError(err.error);
        setTimeout(() => setMessageError(''), 5000);
      } else {
        setLastConnectionError(err?.message || 'Connection error');
      }
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
          const newSocket = new AccordWebSocket(response.token, serverUrlRef.current.replace(/^http/, "ws"));
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
      let e2eeType: 'double-ratchet' | 'symmetric' | 'sender-keys' | 'none' = 'none';

      // Check if this is a DM message
      const isIncomingDm = data.is_dm || dmChannelsRef.current.some(dm => dm.id === data.channel_id);

      if (isIncomingDm && e2eeManagerRef.current?.isInitialized && data.from) {
        // DM: try Double Ratchet E2EE decryption
        try {
          content = e2eeManagerRef.current.decrypt(data.from, data.encrypted_data);
          isEncrypted = true;
          e2eeType = 'double-ratchet';
        } catch (error) {
          console.warn('E2EE decrypt failed, trying symmetric fallback:', error);
          // Fallback to symmetric
          if (encryptionEnabled && keyPair && data.channel_id) {
            try {
              const channelKey = await getChannelKey(keyPair.privateKey, data.channel_id);
              content = await decryptMessage(channelKey, data.encrypted_data);
              isEncrypted = true;
              e2eeType = 'symmetric';
            } catch (e2) {
              console.warn('Symmetric decrypt also failed:', e2);
            }
          }
        }
      } else if (encryptionEnabled && keyPair && data.channel_id) {
        // Channel: try sender keys first, fall back to symmetric
        if (isSenderKeyEnvelope(data.encrypted_data) && data.from) {
          try {
            content = decryptChannelMessage(
              senderKeyStoreRef.current, data.channel_id, data.from, data.encrypted_data);
            isEncrypted = true;
            e2eeType = 'sender-keys';
          } catch (skError) {
            console.warn('Sender key decrypt failed, trying symmetric fallback:', skError);
            try {
              const channelKey = await getChannelKey(keyPair.privateKey, data.channel_id);
              content = await decryptMessage(channelKey, data.encrypted_data);
              isEncrypted = true;
              e2eeType = 'symmetric';
            } catch (error) {
              console.warn('Failed to decrypt message, showing encrypted data:', error);
            }
          }
        } else {
          try {
            const channelKey = await getChannelKey(keyPair.privateKey, data.channel_id);
            content = await decryptMessage(channelKey, data.encrypted_data);
            isEncrypted = true;
            e2eeType = 'symmetric';
          } catch (error) {
            console.warn('Failed to decrypt message, showing encrypted data:', error);
          }
        }
      }

      // Use display name from server payload, fall back to member list, then fingerprint
      const senderMember = membersRef.current.find(m => m.user_id === data.from);
      const senderName = data.sender_display_name
        || (senderMember && (senderMember.user?.display_name || senderMember.profile?.display_name))
        || fingerprint(senderMember?.public_key_hash || data.from || '');

      const newMessage: Message = {
        id: data.message_id || Math.random().toString(),
        author: senderName,
        content: content,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        timestamp: data.timestamp * 1000,
        channel_id: data.channel_id,
        isEncrypted: isEncrypted,
        e2eeType: e2eeType,
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
      const isDm = data.is_dm || dmChannelsRef.current.some(dm => dm.id === data.channel_id);
      
      if (isDm) {
        // Handle DM message - refresh DM channels to update last message
        loadDmChannels();
        
        // Add to notifications for DM
        const dmChannel = dmChannelsRef.current.find(dm => dm.id === data.channel_id);
        if (dmChannel) {
          notificationManager.addMessage(`dm-${dmChannel.id}`, data.channel_id, newMessage, true);
          setForceUpdate(prev => prev + 1);
        }
      } else {
        // Find which node this channel belongs to for regular messages
        const nodeId = nodesRef.current.find(node => 
          channelsRef.current.some(channel => channel.id === data.channel_id && channel.node_id === node.id)
        )?.id;

        // Add message to notification system
        if (nodeId) {
          notificationManager.addMessage(nodeId, data.channel_id, newMessage);
          setForceUpdate(prev => prev + 1); // Trigger re-render for unread badges
        }
      }

      // Check if this message belongs to the currently selected channel
      const currentChannelId = selectedDmChannelRef.current?.id || selectedChannelIdRef.current;
      const isCurrentChannel = data.channel_id === currentChannelId;

      // Check if user is scrolled to the bottom before adding new message
      const container = messagesContainerRef.current;
      const wasAtBottom = container ? 
        (container.scrollHeight - container.scrollTop - container.clientHeight < 50) : true;

      const currentUserId = localStorage.getItem('accord_user_id');
      const isOwnMessage = data.from === currentUserId;

      if (isCurrentChannel) {
        setAppState(prev => {
          // Dedup: check if message with this ID already exists
          if (data.message_id && prev.messages.some(m => m.id === data.message_id)) {
            return prev;
          }
          if (isOwnMessage) {
            // Replace the oldest optimistic temp message with the real server message
            const tempIdx = prev.messages.findIndex(
              m => m.id.startsWith('temp_') && m.channel_id === data.channel_id && m.sender_id === currentUserId
            );
            if (tempIdx !== -1) {
              const updated = [...prev.messages];
              updated[tempIdx] = newMessage;
              return { ...prev, messages: updated };
            }
            // No temp message found — might be from another tab/device, add it
          }
          return { ...prev, messages: [...prev.messages, newMessage] };
        });
      }

      // Auto-scroll to bottom if user was at the bottom
      if (wasAtBottom && container) {
        setTimeout(() => {
          container.scrollTop = container.scrollHeight;
        }, 0);
        // Send read receipt for the new message since user is at bottom
        if (data.channel_id === selectedChannelIdRef.current && newMessage.id) {
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
          if (isSenderKeyEnvelope(data.encrypted_data) && data.from) {
            try {
              content = decryptChannelMessage(
                senderKeyStoreRef.current, data.channel_id, data.from, data.encrypted_data);
            } catch {
              const channelKey = await getChannelKey(keyPair.privateKey, data.channel_id);
              content = await decryptMessage(channelKey, data.encrypted_data);
            }
          } else {
            const channelKey = await getChannelKey(keyPair.privateKey, data.channel_id);
            content = await decryptMessage(channelKey, data.encrypted_data);
          }
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
        displayName: (data as any).sender_display_name || (data.public_key_hash ? fingerprint(data.public_key_hash) : data.user_id.substring(0, 8)),
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

    // Handle bot responses
    socket.on('bot_response', (data: BotResponseMessage) => {
      setBotResponses(prev => [...prev, data]);
      // Also add as a message in the channel
      const botMsg: Message = {
        id: `bot_${data.invocation_id}_${Date.now()}`,
        author: data.bot_name,
        content: data.content.type === 'text' ? (data.content.text || '') : `[${data.content.title || 'Bot Response'}]`,
        time: new Date(data.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        timestamp: data.timestamp * 1000,
        channel_id: data.channel_id,
        isEncrypted: false,
        e2eeType: 'none',
        display_name: data.bot_name,
        // Store bot metadata in the message for rendering
        _botResponse: data,
      } as any;
      const currentChannelId = selectedDmChannelRef.current?.id || selectedChannelIdRef.current;
      if (data.channel_id === currentChannelId) {
        setAppState(prev => ({ ...prev, messages: [...prev.messages, botMsg] }));
      }
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

    // Handle bulk presence (sent on connect)
    socket.on('presence_bulk', (data: any) => {
      if (data.members && Array.isArray(data.members)) {
        setPresenceMap(prev => {
          const newMap = new Map(prev);
          for (const m of data.members) {
            if (m.user_id && m.status) {
              newMap.set(m.user_id, m.status);
            }
          }
          return newMap;
        });
      }
    });

    socket.on('error', (error: Error) => {
      console.error('WebSocket error:', error);
    });

    // ── Sender Key events ──

    // A peer sent us their sender key (via DR-encrypted DM, distributed by server)
    socket.on('sender_key_distribution' as any, async (data: any) => {
      if (!e2eeManagerRef.current?.isInitialized || !data.payload || !data.from_user_id) return;
      try {
        // Decrypt the DR-encrypted payload
        const decrypted = e2eeManagerRef.current.decrypt(data.from_user_id, data.payload);
        const distMsg = JSON.parse(decrypted);
        if (distMsg.type === 'skdm') {
          const { state } = parseDistributionMessage(distMsg);
          senderKeyStoreRef.current.setPeerKey(distMsg.ch, data.from_user_id, state);
          console.log(`Stored sender key from ${data.from_user_id} for channel ${distMsg.ch}`);
        }
        // ACK the distribution
        if (data.distribution_id) {
          socket.ackSenderKeys([data.distribution_id]);
        }
      } catch (err) {
        console.warn('Failed to process sender key distribution:', err);
      }
    });

    // Server tells us to rotate sender keys (member left/kicked)
    socket.on('sender_key_rotation_required' as any, async (data: any) => {
      if (!data.channel_id || !data.removed_user_id) return;
      const channelId = data.channel_id;
      // Remove the departed user's key
      senderKeyStoreRef.current.removePeerKey(channelId, data.removed_user_id);
      // Rotate our own key and redistribute to remaining members
      if (senderKeyStoreRef.current.hasChannelKeys(channelId)) {
        const newKey = senderKeyStoreRef.current.rotateMyKey(channelId);
        // Distribute new key to all channel members (async, best-effort)
        distributeSenderKeyToChannel(socket, channelId, newKey, data.removed_user_id);
      }
    });

    // A new member joined — send them our sender key
    socket.on('sender_key_new_member' as any, async (data: any) => {
      if (!data.channel_id || !data.new_user_id) return;
      const channelId = data.channel_id;
      const sk = senderKeyStoreRef.current.getMyKey(channelId);
      if (sk && e2eeManagerRef.current?.isInitialized) {
        const distMsg = buildDistributionMessage(channelId, sk);
        try {
          const encrypted = e2eeManagerRef.current.encrypt(data.new_user_id, JSON.stringify(distMsg));
          socket.storeSenderKey(channelId, data.new_user_id, encrypted);
        } catch (err) {
          console.warn(`Failed to send sender key to new member ${data.new_user_id}:`, err);
        }
      }
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
      
      // Register loaded nodes with RelayManager for the current relay
      const currentRelayUrl = api.getBaseUrl();
      const rm = relayManagerRef.current;
      for (const node of (Array.isArray(userNodes) ? userNodes : [])) {
        rm.addNodeToRelay(currentRelayUrl, node.id);
      }

      // Auto-select first node if none selected (use functional update to avoid dep on selectedNodeId)
      if (userNodes.length > 0) {
        setSelectedNodeId(prev => prev ?? userNodes[0].id);
      }
    } catch (error) {
      console.error('Failed to load nodes:', error);
    }
  }, [appState.token, serverAvailable]);

  // Keep ref updated for use in WS handlers (avoids stale closures)
  loadNodesRef.current = loadNodes;

  // Load channels for selected node
  const loadChannels = useCallback(async (nodeId: string) => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const nodeChannels = await api.getNodeChannels(nodeId, appState.token);
      setChannels(Array.isArray(nodeChannels) ? nodeChannels : []);
      
      // Auto-select first channel if none selected
      if (nodeChannels.length > 0) {
        setSelectedChannelId(prev => prev ?? nodeChannels[0].id);
      }
    } catch (error) {
      console.error('Failed to load channels:', error);
      handleApiError(error);
      setChannels([]);
    }
  }, [appState.token, serverAvailable]);

  // Load slow mode setting when channel changes
  useEffect(() => {
    const channelId = selectedChannelId || appState.activeChannel;
    if (!channelId || !appState.token) {
      setSlowModeSeconds(0);
      return;
    }
    api.getSlowMode(channelId, appState.token).then(result => {
      setSlowModeSeconds(result.slow_mode_seconds || 0);
    }).catch(() => setSlowModeSeconds(0));
  }, [selectedChannelId, appState.activeChannel, appState.token]);

  // Slow mode countdown timer
  useEffect(() => {
    if (slowModeCooldown <= 0) return;
    const timer = setInterval(() => {
      setSlowModeCooldown(prev => {
        if (prev <= 1) { clearInterval(timer); return 0; }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [slowModeCooldown]);

  // Load members for selected node (debounced — skip if loaded recently)
  const lastMembersLoadRef = useRef<{ nodeId: string; time: number }>({ nodeId: '', time: 0 });
  const loadMembers = useCallback(async (nodeId: string) => {
    if (!appState.token || !serverAvailable) return;
    
    // Debounce: skip if same node was loaded within 2 seconds
    const now = Date.now();
    if (lastMembersLoadRef.current.nodeId === nodeId && now - lastMembersLoadRef.current.time < 2000) return;
    lastMembersLoadRef.current = { nodeId, time: now };
    
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

  // Decrypt a message's encrypted_payload using sender keys or symmetric channel key
  const decryptPayload = useCallback(async (encrypted: string, channelId: string, senderId?: string): Promise<{ content: string; isEncrypted: boolean }> => {
    if (encryptionEnabled && keyPair && channelId) {
      // Try sender keys first if it looks like a sender key envelope
      if (senderId && isSenderKeyEnvelope(encrypted)) {
        try {
          const content = decryptChannelMessage(
            senderKeyStoreRef.current, channelId, senderId, encrypted);
          return { content, isEncrypted: true };
        } catch {
          // Fall through to symmetric
        }
      }
      try {
        const channelKey = await getChannelKey(keyPair.privateKey, channelId);
        const content = await decryptMessage(channelKey, encrypted);
        return { content, isEncrypted: true };
      } catch {
        // Decryption failed — show raw payload (old key or corrupted)
      }
    }
    return { content: encrypted, isEncrypted: false };
  }, [encryptionEnabled, keyPair]);

  // Map server MessageMetadata to frontend Message type
  const mapServerMessage = useCallback(async (msg: any, channelId: string): Promise<Message> => {
    // Server returns created_at (seconds), encrypted_payload (base64)
    const ts = (msg.created_at || msg.timestamp || 0) * (msg.created_at ? 1000 : 1); // created_at is seconds, timestamp might already be ms
    const payload = msg.encrypted_payload || msg.content || '';
    const senderId = msg.sender_id || msg.from || '';
    const { content, isEncrypted } = await decryptPayload(payload, channelId, senderId);
    const detectedSK = isEncrypted && isSenderKeyEnvelope(payload);
    
    return {
      ...msg,
      content,
      isEncrypted,
      e2eeType: isEncrypted ? (detectedSK ? 'sender-keys' as const : 'symmetric' as const) : 'none' as const,
      author: msg.display_name || msg.author || fingerprint(msg.sender_public_key_hash || msg.sender_id || '') || 'Unknown',
      time: new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      timestamp: ts,
      channel_id: channelId,
      sender_id: msg.sender_id?.toString(),
    };
  }, [decryptPayload]);

  // Load message history for selected channel (initial load)
  const loadMessages = useCallback(async (channelId: string) => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const response = await api.getChannelMessages(channelId, appState.token);
      
      // Format and decrypt messages for display
      const formattedMessages = await Promise.all(
        response.messages.map(msg => mapServerMessage(msg, channelId))
      );
      
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
  }, [appState.token, serverAvailable, mapServerMessage]);

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
      
      // Format and decrypt messages for display
      const formattedMessages = await Promise.all(
        response.messages.map(msg => mapServerMessage(msg, channelId))
      );
      
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
  }, [appState.token, serverAvailable, isLoadingOlderMessages, hasMoreMessages, oldestMessageCursor, mapServerMessage]);

  // Handle staging files for preview before upload
  const handleFilesStaged = useCallback((files: StagedFile[]) => {
    setStagedFiles(prev => [...prev, ...files]);
  }, []);

  const handleRemoveStagedFile = useCallback((index: number) => {
    setStagedFiles(prev => {
      const removed = prev[index];
      if (removed?.previewUrl) URL.revokeObjectURL(removed.previewUrl);
      return prev.filter((_, i) => i !== index);
    });
  }, []);

  const handleClearStagedFiles = useCallback(() => {
    stagedFiles.forEach(f => { if (f.previewUrl) URL.revokeObjectURL(f.previewUrl); });
    setStagedFiles([]);
  }, [stagedFiles]);

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

  // Bot API v2
  const loadBots = useCallback(async (nodeId: string) => {
    try {
      const bots = await api.listBots(nodeId);
      setInstalledBots(bots);
    } catch (err) {
      console.warn('Failed to load bots:', err);
      setInstalledBots([]);
    }
  }, []);

  const handleInvokeBot = useCallback(async (botId: string, command: string, params: Record<string, any>) => {
    const nodeId = selectedNodeId;
    const channelId = selectedDmChannel?.id || selectedChannelId;
    if (!nodeId || !channelId) return;
    try {
      const result = await api.invokeCommand(
        nodeId, botId, command, params, channelId
      );
      console.log('Bot command invoked:', result);
    } catch (err: any) {
      console.error('Bot invoke failed:', err);
      setError(`Bot command failed: ${err.message}`);
    }
  }, [selectedNodeId, selectedDmChannel, selectedChannelId]);

  // Convert a BatchMemberEntry to the NodeMember & { user: User } shape used by the UI
  const batchMemberToUiMember = useCallback((m: BatchMemberEntry, nodeId: string): NodeMember & { user: User } => ({
    node_id: nodeId,
    user_id: m.user_id,
    public_key_hash: '',
    role: m.node_role,
    joined_at: m.joined_at,
    profile: {
      user_id: m.user_id,
      display_name: m.display_name,
      avatar_url: m.avatar_url,
      status: m.status as any,
      custom_status: m.custom_status,
      updated_at: 0,
    },
    user: {
      id: m.user_id,
      public_key_hash: '',
      public_key: '',
      created_at: m.joined_at || 0,
      display_name: m.display_name,
    },
  }), []);

  // Handle node selection — uses batch overview endpoint for a single round-trip
  const handleNodeSelect = useCallback(async (nodeId: string, index: number) => {
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

    // If this node is on a different relay, switch the global api client to that relay
    const rm = relayManagerRef.current;
    const nodeRelay = rm.getRelayForNode(nodeId);
    if (nodeRelay && nodeRelay.url !== api.getBaseUrl()) {
      const conn = rm.getConnection(nodeRelay.url);
      if (conn) {
        // Switch global api to this relay
        api.setBaseUrl(conn.url);
        api.setToken(conn.token!);
        setServerUrl(conn.url);
        // Switch WS to this relay's WS
        if (conn.ws) {
          setWs(conn.ws);
        }
      }
    }
    
    // Try batch overview first, fall back to individual calls
    try {
      const overview = await api.getNodeOverview(nodeId);
      
      // Set channels — map batch shape to Channel shape
      const uiChannels: Channel[] = overview.channels.map(ch => ({
        id: ch.id,
        name: ch.name,
        node_id: ch.node_id,
        members: [],
        created_at: 0,
        parent_id: ch.category_id,
        position: ch.position,
        unread_count: ch.unread_count,
      }));
      setChannels(uiChannels);
      
      // Auto-select first channel
      if (uiChannels.length > 0) {
        setSelectedChannelId(prev => prev ?? uiChannels[0].id);
      }
      
      // Set members — map batch shape to UI shape
      const uiMembers = overview.members.map(m => batchMemberToUiMember(m, nodeId));
      setMembers(uiMembers);
      
      // Set roles
      setNodeRoles(Array.isArray(overview.roles) ? overview.roles : []);
      
      // Build memberRolesMap from batch member data
      const rolesMap: Record<string, Role[]> = {};
      for (const m of overview.members) {
        rolesMap[m.user_id] = (m.roles || []).map(r => ({
          id: r.id,
          node_id: nodeId,
          name: r.name,
          color: r.color,
          position: r.position,
          permissions: 0,
          hoist: r.hoist ?? false,
          mentionable: false,
          created_at: 0,
        }));
      }
      setMemberRolesMap(rolesMap);
      
      // Set current user's role
      const currentUserId = localStorage.getItem('accord_user_id');
      if (currentUserId) {
        const currentMember = overview.members.find(m => m.user_id === currentUserId);
        if (currentMember) {
          setUserRoles(prev => ({ ...prev, [nodeId]: currentMember.node_role }));
        }
      }
      
      // Set presence map from online status
      setPresenceMap(prev => {
        const newMap = new Map(prev);
        for (const m of overview.members) {
          newMap.set(m.user_id, m.status as any);
        }
        return newMap;
      });
      
      // Load bots separately (not in overview)
      loadBots(nodeId);
    } catch (err) {
      console.warn('Batch overview failed, falling back to individual calls:', err);
      // Fallback to individual calls
      loadChannels(nodeId);
      loadMembers(nodeId);
      loadRoles(nodeId);
      loadBots(nodeId);
    }

    // Load custom emojis for the node
    try {
      const emojis = await api.listCustomEmojis(nodeId);
      const getUrl = (hash: string) => api.getEmojiUrl(hash);
      setCustomEmojis(emojis, getUrl);
      setNodeCustomEmojis(emojis, getUrl);
    } catch (err) {
      console.warn('Failed to load custom emojis:', err);
      setCustomEmojis([], () => '');
      setNodeCustomEmojis([], () => '');
    }
  }, [loadChannels, loadMembers, loadRoles, loadBots, batchMemberToUiMember]);

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
    if (!joinInviteCode.trim()) return;
    // Need either an existing token or identity keys to register on a new relay
    if (!appState.token && !publicKey) return;
    setJoiningNode(true);
    setJoinError("");
    try {
      const input = joinInviteCode.trim();
      const parsed = parseInviteLink(input);
      const code = parsed ? parsed.inviteCode : input;

      // Compare relay hosts without scheme to handle http/https mismatch
      const isSameRelay = !parsed || parsed.relayHost === new URL(api.getBaseUrl()).host;
      if (parsed && !isSameRelay) {
        // Invite is for a different relay — connect via RelayManager
        const rm = relayManagerRef.current;
        const pw = passwordRef.current;
        if (!publicKey || !pw) {
          setJoinError("Identity not available — unlock your identity first");
          return;
        }
        const conn = await rm.connectRelay(parsed.relayUrl, publicKey, pw);
        // Join the node on that relay
        const joinResult = await conn.api.joinNodeByInvite(code, conn.token!);
        if (joinResult?.id) {
          rm.addNodeToRelay(parsed.relayUrl, joinResult.id);
        }
        // Set up WS handlers and connect
        if (conn.ws) {
          setupWebSocketHandlers(conn.ws);
          conn.ws.connect();
        }
      } else {
        // Same relay — use existing API client
        let token = appState.token;

        // If no token yet, register + auth on this relay first
        if (!token && publicKey && passwordRef.current) {
          try {
            await api.register(publicKey, passwordRef.current);
          } catch { /* may already be registered */ }
          const response = await api.login(publicKey, passwordRef.current);
          storeToken(response.token);
          localStorage.setItem('accord_user_id', response.user_id);
          token = response.token;
          setAppState(prev => ({
            ...prev,
            token: response.token,
            user: { ...prev.user!, id: response.user_id }
          }));

          // Connect WebSocket if not connected
          if (!ws) {
            const wsBaseUrl = serverUrl.replace(/^http/, 'ws');
            const socket = new AccordWebSocket(response.token, wsBaseUrl);
            setupWebSocketHandlers(socket);
            setWs(socket);
            socket.connect();
          }
        }

        if (!token) {
          setJoinError("Not authenticated — create an identity first");
          return;
        }

        api.setToken(token);
        await api.joinNodeByInvite(code, token);
      }

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
      // Close modal immediately on success
      setShowCreateNodeModal(false);
      setNewNodeName("");
      setNewNodeDescription("");
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
      // Probe both HTTP and HTTPS to find the working scheme
      let workingUrl: string;
      try {
        const { probeServerUrl } = await import("./api");
        workingUrl = await probeServerUrl(parsed.relayUrl);
      } catch {
        workingUrl = parsed.relayUrl;
      }
      api.setBaseUrl(workingUrl);
      const health = await api.health();
      setServerConnected(true);
      setServerAvailable(true);
      setInviteRelayVersion(health.version);
      setServerUrl(workingUrl);

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
              clearChannelKeyCache();
              setKeyPair(existingKeyPair);
              const pk = await exportPublicKey(existingKeyPair.publicKey);
              pkHash = await sha256Hex(pk);
              setPublicKeyHash(pkHash); setActiveIdentity(pkHash);
              setPublicKey(pk);
            }
          }

          let displayName = fingerprint(pkHash);
          try {
            const profile = await api.getUserProfile(existingUserId, existingToken);
            if (profile?.display_name) displayName = profile.display_name;
          } catch { /* fallback to fingerprint */ }

          setAppState(prev => ({
            ...prev,
            isAuthenticated: true,
            token: existingToken,
            user: { id: existingUserId, public_key_hash: pkHash, public_key: '', created_at: 0, display_name: displayName }
          }));
          setIsAuthenticated(true);

          // Join node via invite code
          let joinedNodeId: string | undefined;
          try {
            const joinResult = await api.joinNodeByInvite(parsed.inviteCode, existingToken);
            joinedNodeId = joinResult?.id;
          } catch (_e) {
            // May already be a member, that's fine
          }

          // Register relay with RelayManager
          const rm = relayManagerRef.current;
          if (joinedNodeId) {
            rm.addNodeToRelay(parsed.relayUrl, joinedNodeId);
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
        clearChannelKeyCache();
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
      let joinedNodeId: string | undefined;
      try {
        const joinResult = await api.joinNodeByInvite(parsedInvite.inviteCode, response.token);
        joinedNodeId = joinResult?.id;
      } catch (_e) {
        // May already be a member
      }

      // Register relay + node with RelayManager
      if (joinedNodeId) {
        relayManagerRef.current.addNodeToRelay(parsedInvite.relayUrl, joinedNodeId);
      }

      let displayName = fingerprint(pkHash);
      try {
        const profile = await api.getUserProfile(response.user_id, response.token);
        if (profile?.display_name) displayName = profile.display_name;
      } catch { /* new account, fingerprint is fine */ }

      setAppState(prev => ({
        ...prev,
        isAuthenticated: true,
        token: response.token,
        user: { id: response.user_id, public_key_hash: pkHash, public_key: publicKeyToUse, created_at: 0, display_name: displayName }
      }));
      setIsAuthenticated(true);

      notificationManager.setCurrentUsername(displayName);

      // Initialize WebSocket
      const socket = new AccordWebSocket(response.token, serverUrl.replace(/^http/, "ws"));
      setupWebSocketHandlers(socket);
      setWs(socket);
      socket.connect();

      // Show mnemonic backup modal, then land in app
      setShowMnemonicModal(true);
      setMnemonicConfirmStep(0);
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
          clearChannelKeyCache();
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
          // Try password-based decryption first (use stored hash for namespaced lookup)
          let existingKeyPair = await loadKeyWithPassword(password, storedHash || undefined);
          if (!existingKeyPair) {
            existingKeyPair = await loadKeyFromStorage(storedHash || undefined);
          }
          if (existingKeyPair) {
            pkToUse = await exportPublicKey(existingKeyPair.publicKey);
            clearChannelKeyCache();
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
            clearChannelKeyCache();
            setKeyPair(existingKeyPair);
            // Re-save with password for future logins
            await saveKeyWithPassword(existingKeyPair, password, pkHash);
            // Also save with token-based encryption so session restore works without password
            await saveKeyToStorage(existingKeyPair, pkHash);
          }
        }
        setHasExistingKey(true);
        // Save public key unencrypted so we can identify the user after logout
        localStorage.setItem('accord_public_key_plain', pkToUse);
        localStorage.setItem('accord_public_key_hash', pkHash);
        
        let displayName = fingerprint(pkHash);
        try {
          const profile = await api.getUserProfile(response.user_id, response.token);
          if (profile?.display_name) displayName = profile.display_name;
        } catch { /* fallback to fingerprint */ }

        setAppState(prev => ({
          ...prev,
          isAuthenticated: true,
          token: response.token,
          user: { id: response.user_id, public_key_hash: pkHash, public_key: pkToUse, created_at: 0, display_name: displayName }
        }));
        setIsAuthenticated(true);

        // Set display name for notification system
        notificationManager.setCurrentUsername(displayName);

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
            clearChannelKeyCache();
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
        setMnemonicConfirmStep(0);

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
      clearChannelKeyCache();
      setKeyPair(recoveredKeyPair);
      setPublicKey(pk);
      passwordRef.current = recoverPassword;
      
      setPublicKeyHash(pkHash); setActiveIdentity(pkHash);
      
      storeToken(response.token);
      localStorage.setItem('accord_user_id', response.user_id);
      // Persist server URL so needsRelayUrl guard doesn't re-show welcome screen
      if (serverUrl && !localStorage.getItem('accord_server_url')) {
        localStorage.setItem('accord_server_url', serverUrl);
      }
      
      setAppState(prev => ({
        ...prev,
        isAuthenticated: true,
        token: response.token,
        user: { id: response.user_id, public_key_hash: pkHash, public_key: pk, created_at: 0, display_name: fingerprint(pkHash) }
      }));
      setIsAuthenticated(true);
      setShowRecoverModal(false);
      setShowWelcomeScreen(false);
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
    // Persist sender key store before clearing state
    const userId = localStorage.getItem('accord_user_id') || '';
    const password = passwordRef.current;
    if (password && userId) {
      saveSenderKeyStore(userId, senderKeyStoreRef.current, password);
    }

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
    
    // Show setup wizard for re-entry (login with existing keys or create new)
    setShowSetupWizard(true);
    setShowWelcomeScreen(false);
    setInviteLinkInput("");
    setParsedInvite(null);
    setInviteError("");
  };

  // Handle sending messages
  const handleSendMessage = async () => {
    if (!message.trim() && stagedFiles.length === 0) return;

    // Upload any staged files first
    const channelForUpload = selectedDmChannel?.id || selectedChannelId || appState.activeChannel;
    if (stagedFiles.length > 0 && channelForUpload && appState.token) {
      for (const sf of stagedFiles) {
        try {
          let fileToUpload = sf.file;
          let encryptedFilename: string | undefined;

          if (encryptionEnabled && keyPair) {
            try {
              const channelKey = await getChannelKey(keyPair.privateKey, channelForUpload);
              const { encryptFile: ef, encryptFilename: efn } = await import('./crypto');
              const fileBuffer = await sf.file.arrayBuffer();
              const encryptedBuffer = await ef(channelKey, fileBuffer);
              encryptedFilename = await efn(channelKey, sf.file.name);
              fileToUpload = new File([encryptedBuffer], 'encrypted_file', { type: 'application/octet-stream' });
            } catch (error) {
              console.warn('Failed to encrypt file, uploading plaintext:', error);
            }
          }

          await api.uploadFile(channelForUpload, fileToUpload, appState.token, encryptedFilename);
        } catch (error) {
          console.error(`Failed to upload ${sf.name}:`, error);
        }
      }
      // Clean up previews
      stagedFiles.forEach(f => { if (f.previewUrl) URL.revokeObjectURL(f.previewUrl); });
      setStagedFiles([]);
    }

    // If only files were staged with no message text, we're done
    if (!message.trim()) return;

    // Determine which channel to use - DM channel takes priority
    const channelToUse = selectedDmChannel?.id || selectedChannelId || appState.activeChannel;
    
    if (ws && ws.isSocketConnected() && channelToUse) {
      // Send via WebSocket if connected and we have an active channel
      try {
        let messageToSend = message;
        let isEncrypted = false;
        let e2eeType: 'double-ratchet' | 'symmetric' | 'sender-keys' | 'none' = 'none';

        // Encrypt: use E2EE (Double Ratchet) for DMs, symmetric for channels
        const isDmSend = !!selectedDmChannel;
        if (isDmSend && e2eeManagerRef.current?.isInitialized && appState.token) {
          // DM: use Double Ratchet E2EE
          try {
            const recipientId = selectedDmChannel!.other_user.id;
            await ensureE2EESession(recipientId, appState.token);
            messageToSend = e2eeManagerRef.current.encrypt(recipientId, message);
            isEncrypted = true;
            e2eeType = 'double-ratchet';
          } catch (error) {
            console.warn('E2EE encrypt failed, falling back to symmetric:', error);
            // Fallback to symmetric encryption
            if (encryptionEnabled && keyPair) {
              try {
                const channelKey = await getChannelKey(keyPair.privateKey, channelToUse);
                messageToSend = await encryptMessage(channelKey, message);
                isEncrypted = true;
                e2eeType = 'symmetric';
              } catch (e2) {
                console.warn('Symmetric encrypt also failed, sending plaintext:', e2);
              }
            }
          }
        } else if (encryptionEnabled && keyPair && channelToUse) {
          // Channel: try sender keys first, fall back to symmetric
          if (senderKeyStoreRef.current.hasChannelKeys(channelToUse)) {
            try {
              const { encryptFn } = encryptChannelMessage(senderKeyStoreRef.current, channelToUse);
              messageToSend = encryptFn(message);
              isEncrypted = true;
              e2eeType = 'sender-keys';
            } catch (skError) {
              console.warn('Sender key encrypt failed, falling back to symmetric:', skError);
            }
          }
          if (!isEncrypted) {
            // Symmetric fallback
            try {
              const channelKey = await getChannelKey(keyPair.privateKey, channelToUse);
              messageToSend = await encryptMessage(channelKey, message);
              isEncrypted = true;
              e2eeType = 'symmetric';
            } catch (error) {
              console.warn('Failed to encrypt message, sending plaintext:', error);
            }
          }
        }

        // Pass reply_to if we're replying to a message
        ws.sendChannelMessage(channelToUse, messageToSend, replyingTo?.id);

        // Add to local messages for immediate display (temp_ prefix for dedup)
        const newMessage: Message = {
          id: `temp_${Date.now()}_${Math.random()}`,
          author: appState.user?.display_name || fingerprint(appState.user?.public_key_hash || '') || "You",
          content: message, // Show original plaintext locally
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          timestamp: Date.now(),
          channel_id: channelToUse,
          sender_id: localStorage.getItem('accord_user_id') || undefined,
          isEncrypted: isEncrypted,
          e2eeType: e2eeType,
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

    // Start slow mode cooldown if active
    if (slowModeSeconds > 0) {
      setSlowModeCooldown(slowModeSeconds);
    }
  };

  // Message editing functionality removed

  // Handle saving message edit
  const handleSaveEdit = async () => {
    if (!editingMessageId || !editingContent.trim() || !appState.user) return;

    try {
      let messageToSend = editingContent;

      // Encrypt message if encryption is enabled and we have keys
      if (encryptionEnabled && keyPair && selectedChannelId) {
        // Try sender keys first
        if (senderKeyStoreRef.current.hasChannelKeys(selectedChannelId)) {
          try {
            const { encryptFn } = encryptChannelMessage(senderKeyStoreRef.current, selectedChannelId);
            messageToSend = encryptFn(editingContent);
          } catch (skError) {
            console.warn('Sender key encrypt failed for edit, falling back:', skError);
            try {
              const channelKey = await getChannelKey(keyPair.privateKey, selectedChannelId);
              messageToSend = await encryptMessage(channelKey, editingContent);
            } catch (error) {
              console.warn('Failed to encrypt edited message:', error);
              setError('Failed to encrypt message');
              return;
            }
          }
        } else {
          try {
            const channelKey = await getChannelKey(keyPair.privateKey, selectedChannelId);
            messageToSend = await encryptMessage(channelKey, editingContent);
          } catch (error) {
            console.warn('Failed to encrypt edited message:', error);
            setError('Failed to encrypt message');
            return;
          }
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

  // Check for existing session on mount (runs once when server becomes available)
  const sessionCheckedRef = useRef(false);
  useEffect(() => {
    if (sessionCheckedRef.current || !serverAvailable || isAuthenticated) return;
    sessionCheckedRef.current = true;

    const checkExistingSession = async () => {
      const token = await getToken();
      const userId = localStorage.getItem('accord_user_id');
      
      if (token && userId && serverAvailable) {
        api.setToken(token);
        setShowWelcomeScreen(false);
        // Load existing keys if available
        let existingKeyPair: CryptoKeyPair | null = null;
        if (encryptionEnabled) {
          // Set active identity so namespaced storage keys are used
          const storedHash = localStorage.getItem('accord_public_key_hash');
          if (storedHash) setActiveIdentity(storedHash);
          existingKeyPair = await loadKeyFromStorage(storedHash || undefined);
          if (existingKeyPair) {
            clearChannelKeyCache();
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
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serverAvailable]);

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

  // Build context value for all child components
  const contextValue: import('./components/AppContext').AppContextType = {
    // Server connection
    serverUrl, setServerUrl, serverAvailable, serverConnecting, serverVersion,
    showServerScreen, setShowServerScreen,

    // Welcome / Invite flow
    showWelcomeScreen, setShowWelcomeScreen,
    welcomeMode, setWelcomeMode,
    inviteLinkInput, setInviteLinkInput,
    inviteError, setInviteError,
    inviteConnecting, inviteRelayVersion, inviteNeedsRegister,
    invitePassword, setInvitePassword, inviteJoining,

    // Auth
    isAuthenticated, isLoginMode, setIsLoginMode,
    password, setPassword, publicKey,
    authError, setAuthError, publicKeyHash, hasExistingKey,

    // Mnemonic / Recovery
    showMnemonicModal, setShowMnemonicModal,
    mnemonicPhrase, setMnemonicPhrase,
    copyButtonText, setCopyButtonText,
    mnemonicConfirmStep, setMnemonicConfirmStep,
    showRecoverModal, setShowRecoverModal,
    recoverMnemonic, setRecoverMnemonic,
    recoverPassword, setRecoverPassword,
    recoverError, setRecoverError, recoverLoading,
    showKeyBackup, setShowKeyBackup,

    // Encryption
    keyPair, encryptionEnabled,

    // App state
    appState, setAppState, message, setMessage,
    slowModeCooldown, slowModeSeconds, messageError,
    activeChannel, activeServer, ws, connectionInfo,
    lastConnectionError, setLastConnectionError,

    // Reply
    replyingTo, setReplyingTo,

    // Data
    nodes, channels, members, selectedNodeId, selectedChannelId,

    // Message pagination
    isLoadingOlderMessages, hasMoreMessages, messagesContainerRef,

    // Message editing
    editingMessageId, setEditingMessageId,
    editingContent, setEditingContent,
    showDeleteConfirm, setShowDeleteConfirm,

    // Roles
    userRoles, nodeRoles, memberRolesMap,
    showCreateChannelForm, setShowCreateChannelForm,
    newChannelName, setNewChannelName,
    newChannelType, setNewChannelType,
    showInviteModal, setShowInviteModal,
    generatedInvite, setGeneratedInvite,
    error, setError,

    // Voice
    voiceChannelId, setVoiceChannelId,
    voiceChannelName, setVoiceChannelName,
    voiceConnectedAt, setVoiceConnectedAt,

    // Custom status
    customStatus, showStatusPopover, setShowStatusPopover,
    statusInput, setStatusInput,

    // Pinned
    showPinnedPanel, setShowPinnedPanel, pinnedMessages,

    // Reactions
    showEmojiPicker, setShowEmojiPicker,
    hoveredMessageId, setHoveredMessageId,

    // Notifications
    notificationPreferences, showNotificationSettings, setShowNotificationSettings,
    forceUpdate,

    // Search
    showSearchOverlay, setShowSearchOverlay,

    // DMs
    dmChannels, selectedDmChannel,
    showDmChannelCreate, setShowDmChannelCreate,

    // Node creation
    showCreateNodeModal, setShowCreateNodeModal,
    showJoinNodeModal, setShowJoinNodeModal,
    joinInviteCode, setJoinInviteCode,
    joiningNode, joinError, setJoinError,
    newNodeName, setNewNodeName,
    newNodeDescription, setNewNodeDescription,
    creatingNode,

    // Settings
    showSettings, setShowSettings,
    showNodeSettings, setShowNodeSettings,

    // Trust
    serverBuildHash, serverHelloVersion, knownHashes,
    connectedSince, showConnectionInfo, setShowConnectionInfo,

    // Categories
    collapsedCategories, setCollapsedCategories,

    // Template import
    showTemplateImport, setShowTemplateImport,
    templateInput, setTemplateInput,
    templateImporting, setTemplateImporting,
    templateResult, setTemplateResult,
    templateError, setTemplateError,

    // Delete channel
    deleteChannelConfirm, setDeleteChannelConfirm,

    // Display name
    showDisplayNamePrompt, setShowDisplayNamePrompt,
    displayNameInput, setDisplayNameInput,
    displayNameSaving,

    // Setup wizard
    showSetupWizard,

    // Keyboard shortcuts
    showShortcutsHelp, setShowShortcutsHelp,

    // Member sidebar
    showMemberSidebar, setShowMemberSidebar,

    // Emoji picker / files
    showInputEmojiPicker, setShowInputEmojiPicker,
    stagedFiles, messageInputRef,

    // Scroll
    showScrollToBottom, newMessageCount,

    // Presence
    presenceMap,

    // Context menu
    contextMenu, setContextMenu,

    // Profile card
    profileCardTarget, setProfileCardTarget,

    // Blocking
    blockedUsers,
    showBlockConfirm, setShowBlockConfirm,

    // Typing
    typingUsers,

    // Read receipts
    readReceipts,

    // Message density
    messageDensity,

    // Role popup
    showRolePopup, setShowRolePopup,

    // ---- Handlers ----
    handleAuth, handleLogout, handleSendMessage,
    handleSaveEdit, handleCancelEdit, handleDeleteMessage,
    handleReply, handleCancelReply,
    handleAddReaction, handleRemoveReaction, handleToggleReaction,
    handlePinMessage, handleUnpinMessage,
    handleStartEdit, handleNodeSelect, handleChannelSelect,
    handleCreateChannel, handleGenerateInvite,
    handleKickMember, handleDeleteChannelConfirmed,
    handleJoinNode, handleCreateNode,
    handleDmChannelSelect, openDmWithUser,
    handleSaveDisplayName, handleSaveCustomStatus,
    handleServerConnect, handleInviteLinkSubmit, handleInviteRegister,
    handleRecover,
    handleNotificationPreferencesChange,
    handleNavigateToMessage,
    handleBlockUser, handleUnblockUser,
    handleScroll, scrollToBottom, scrollToMessage,
    handleFilesStaged, handleRemoveStagedFile, handleClearStagedFiles,
    handleInsertEmoji, handleContextMenu, togglePinnedPanel,
    toggleMemberRole, sendTypingIndicator, formatTypingUsers,
    loadChannels, loadRoles, loadNodes, loadDmChannels, loadBots,

    // Bots
    installedBots, botResponses, handleInvokeBot,

    // Permission helpers
    hasPermission, getRoleBadge, canDeleteMessage, getPresenceStatus,
    getMemberRoleColor, getMemberHighestHoistedRole, sortedMembers,

    // Utility
    fingerprint, displayName, copyToClipboard,

    // Channel helpers
    getChannelTypeNum, sortedChannels, categories,
    uncategorizedChannels, categorizedChannels, toggleCategory,
    servers,

    // Constants
    COMMON_EMOJIS,
  };

  // ---- Early returns for auth/setup screens ----
  if (showMnemonicModal) {
    return (
      <AppContext.Provider value={contextValue}>
        <MnemonicModal />
      </AppContext.Provider>
    );
  }

  if (showRecoverModal) {
    return (
      <AppContext.Provider value={contextValue}>
        <RecoverModal />
      </AppContext.Provider>
    );
  }

  if (showKeyBackup) {
    return (
      <AppContext.Provider value={contextValue}>
        <KeyBackupScreen />
      </AppContext.Provider>
    );
  }

  if (showSetupWizard) {
    const handleSetupComplete = async (result: SetupResult) => {
      try {
        // Store identity
        clearChannelKeyCache();
        setKeyPair(result.keyPair);
        setPublicKey(result.publicKey);
        setPublicKeyHash(result.publicKeyHash);
        setActiveIdentity(result.publicKeyHash);
        passwordRef.current = result.password;
        if (result.mnemonic) setMnemonicPhrase(result.mnemonic);

        // Save key with password-based wrapping
        await saveKeyWithPassword(result.keyPair, result.password, result.publicKeyHash);

        // Store mesh preference
        if (result.meshEnabled) {
          localStorage.setItem('accord_mesh_enabled', 'true');
        }

        const chosenDisplayName = result.displayName || fingerprint(result.publicKeyHash);

        // If relay URL provided (backward compat or login with existing relay), connect to it
        if (result.relayUrl) {
          const relayUrl = result.relayUrl;
          localStorage.setItem('accord_server_url', relayUrl);
          api.setBaseUrl(relayUrl);
          setServerUrl(relayUrl);

          // Register on the relay (may already exist from previous session)
          try {
            await api.register(result.publicKey, result.password, result.displayName);
          } catch { /* already registered — that's fine */ }
          const response = await api.login(result.publicKey, result.password);
          storeToken(response.token);
          localStorage.setItem('accord_user_id', response.user_id);

          if (result.displayName) {
            try { await api.updateProfile({ display_name: result.displayName }, response.token); } catch {}
          }

          await saveKeyToStorage(result.keyPair, result.publicKeyHash);

          setAppState(prev => ({
            ...prev,
            isAuthenticated: true,
            token: response.token,
            user: { id: response.user_id, public_key_hash: result.publicKeyHash, public_key: result.publicKey, created_at: Date.now() / 1000, display_name: chosenDisplayName }
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

          setServerAvailable(true);
          setTimeout(() => { loadNodes(); loadDmChannels(); }, 100);
        } else {
          // Identity-only creation: no explicit relay URL provided
          // But if we detected a same-origin relay, auto-register with it
          const detectedRelay = localStorage.getItem('accord_server_url');
          if (detectedRelay) {
            api.setBaseUrl(detectedRelay);
          }
          if (detectedRelay && await api.testConnection()) {
            try {
              await api.register(result.publicKey, result.password, result.displayName);
              const response = await api.login(result.publicKey, result.password);
              storeToken(response.token);
              localStorage.setItem('accord_user_id', response.user_id);

              if (result.displayName) {
                try { await api.updateProfile({ display_name: result.displayName }, response.token); } catch {}
              }

              await saveKeyToStorage(result.keyPair, result.publicKeyHash);

              setAppState(prev => ({
                ...prev,
                isAuthenticated: true,
                token: response.token,
                user: { id: response.user_id, public_key_hash: result.publicKeyHash, public_key: result.publicKey, created_at: Date.now() / 1000, display_name: chosenDisplayName }
              }));
              setIsAuthenticated(true);
              setServerAvailable(true);

              // Connect WebSocket
              const wsBaseUrl = detectedRelay.replace(/^http/, 'ws');
              const socket = new AccordWebSocket(response.token, wsBaseUrl);
              setupWebSocketHandlers(socket);
              setWs(socket);
              socket.connect();

              setTimeout(() => { loadNodes(); loadDmChannels(); }, 100);
            } catch {
              // Registration failed — proceed without relay (user can join later via invite)
              setAppState(prev => ({
                ...prev,
                isAuthenticated: true,
                user: { id: '', public_key_hash: result.publicKeyHash, public_key: result.publicKey, created_at: Date.now() / 1000, display_name: chosenDisplayName }
              }));
              setIsAuthenticated(true);
            }
          } else {
            // No relay available — pure offline identity
            setAppState(prev => ({
              ...prev,
              isAuthenticated: true,
              user: { id: '', public_key_hash: result.publicKeyHash, public_key: result.publicKey, created_at: Date.now() / 1000, display_name: chosenDisplayName }
            }));
            setIsAuthenticated(true);
          }
        }

        setHasExistingKey(true);
        setShowSetupWizard(false);
        setShowWelcomeScreen(false);

        // Prompt for display name only if not already set during setup
        if (!result.displayName) {
          setShowDisplayNamePrompt(true);
        }
      } catch (e: any) {
        setAuthError(e.message || "Setup failed");
        // Stay on setup wizard so user can retry
      }
    };

    return (
      <SetupWizard
        onComplete={handleSetupComplete}
      />
    );
  }

  // If not authenticated, show SetupWizard (handles both create and login)
  if (!isAuthenticated) {
    if (!showSetupWizard) {
      // Edge case: have token but isAuthenticated not set yet (session check pending)
      // Show a loading state briefly
      return (
        <AppContext.Provider value={contextValue}>
          <div className="app" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text)' }}>
            Connecting...
          </div>
        </AppContext.Provider>
      );
    }
    // SetupWizard is already rendered above in the render chain
    return null;
  }

  // ---- Main authenticated app ----
  return (
    <AppContext.Provider value={contextValue}>
      <div className="app">
        <UpdateBanner />
        <ServerList />
        <ChannelSidebar />
        <ChatArea />
        <MemberSidebar />
        <AppModals />
      </div>
    </AppContext.Provider>
  );
}

export default App;
