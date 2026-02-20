import React, { createContext, useContext } from "react";
import { AppState, Message, Node, Channel, NodeMember, User, TypingUser, DmChannelWithInfo, Role, ReadReceipt, InstalledBot, BotResponseMessage } from "../types";
import { ConnectionInfo } from "../ws";
import { NotificationPreferences } from "../notifications";
import { AccordWebSocket } from "../ws";
import { StagedFile } from "../FileManager";

export interface AppContextType {
  // Server connection
  serverUrl: string;
  setServerUrl: React.Dispatch<React.SetStateAction<string>>;
  serverAvailable: boolean;
  serverConnecting: boolean;
  serverVersion: string;
  showServerScreen: boolean;
  setShowServerScreen: React.Dispatch<React.SetStateAction<boolean>>;

  // Welcome / Invite flow
  showWelcomeScreen: boolean;
  setShowWelcomeScreen: React.Dispatch<React.SetStateAction<boolean>>;
  welcomeMode: 'choose' | 'invite' | 'admin' | 'recover';
  setWelcomeMode: React.Dispatch<React.SetStateAction<'choose' | 'invite' | 'admin' | 'recover'>>;
  inviteLinkInput: string;
  setInviteLinkInput: React.Dispatch<React.SetStateAction<string>>;
  inviteError: string;
  setInviteError: React.Dispatch<React.SetStateAction<string>>;
  inviteConnecting: boolean;
  inviteRelayVersion: string;
  inviteNeedsRegister: boolean;
  invitePassword: string;
  setInvitePassword: React.Dispatch<React.SetStateAction<string>>;
  inviteJoining: boolean;

  // Auth
  isAuthenticated: boolean;
  isLoginMode: boolean;
  setIsLoginMode: React.Dispatch<React.SetStateAction<boolean>>;
  password: string;
  setPassword: React.Dispatch<React.SetStateAction<string>>;
  publicKey: string;
  authError: string;
  setAuthError: React.Dispatch<React.SetStateAction<string>>;
  publicKeyHash: string;
  hasExistingKey: boolean;

  // Mnemonic / Recovery
  showMnemonicModal: boolean;
  setShowMnemonicModal: React.Dispatch<React.SetStateAction<boolean>>;
  mnemonicPhrase: string;
  setMnemonicPhrase: React.Dispatch<React.SetStateAction<string>>;
  copyButtonText: string;
  setCopyButtonText: React.Dispatch<React.SetStateAction<string>>;
  mnemonicConfirmStep: number;
  setMnemonicConfirmStep: React.Dispatch<React.SetStateAction<number>>;
  showRecoverModal: boolean;
  setShowRecoverModal: React.Dispatch<React.SetStateAction<boolean>>;
  recoverMnemonic: string;
  setRecoverMnemonic: React.Dispatch<React.SetStateAction<string>>;
  recoverPassword: string;
  setRecoverPassword: React.Dispatch<React.SetStateAction<string>>;
  recoverError: string;
  setRecoverError: React.Dispatch<React.SetStateAction<string>>;
  recoverLoading: boolean;
  showKeyBackup: boolean;
  setShowKeyBackup: React.Dispatch<React.SetStateAction<boolean>>;

  // Encryption
  keyPair: CryptoKeyPair | null;
  encryptionEnabled: boolean;

  // App state
  appState: AppState;
  setAppState: React.Dispatch<React.SetStateAction<AppState>>;
  message: string;
  setMessage: React.Dispatch<React.SetStateAction<string>>;
  slowModeCooldown: number;
  slowModeSeconds: number;
  messageError: string;
  activeChannel: string;
  activeServer: number;
  ws: AccordWebSocket | null;
  connectionInfo: ConnectionInfo;
  lastConnectionError: string;
  setLastConnectionError: React.Dispatch<React.SetStateAction<string>>;

  // Reply
  replyingTo: Message | null;
  setReplyingTo: React.Dispatch<React.SetStateAction<Message | null>>;

  // Data
  nodes: Node[];
  channels: Channel[];
  members: Array<NodeMember & { user: User }>;
  selectedNodeId: string | null;
  selectedChannelId: string | null;

  // Message pagination
  isLoadingOlderMessages: boolean;
  hasMoreMessages: boolean;
  messagesContainerRef: React.RefObject<HTMLDivElement | null>;

  // Message editing
  editingMessageId: string | null;
  setEditingMessageId: React.Dispatch<React.SetStateAction<string | null>>;
  editingContent: string;
  setEditingContent: React.Dispatch<React.SetStateAction<string>>;
  showDeleteConfirm: string | null;
  setShowDeleteConfirm: React.Dispatch<React.SetStateAction<string | null>>;

  // Roles
  userRoles: Record<string, 'admin' | 'moderator' | 'member'>;
  nodeRoles: Role[];
  memberRolesMap: Record<string, Role[]>;
  showCreateChannelForm: boolean;
  setShowCreateChannelForm: React.Dispatch<React.SetStateAction<boolean>>;
  newChannelName: string;
  setNewChannelName: React.Dispatch<React.SetStateAction<string>>;
  newChannelType: string;
  setNewChannelType: React.Dispatch<React.SetStateAction<string>>;
  showInviteModal: boolean;
  setShowInviteModal: React.Dispatch<React.SetStateAction<boolean>>;
  generatedInvite: string;
  setGeneratedInvite: React.Dispatch<React.SetStateAction<string>>;
  error: string;
  setError: React.Dispatch<React.SetStateAction<string>>;

  // Voice
  voiceChannelId: string | null;
  setVoiceChannelId: React.Dispatch<React.SetStateAction<string | null>>;
  voiceChannelName: string;
  setVoiceChannelName: React.Dispatch<React.SetStateAction<string>>;
  voiceConnectedAt: number | null;
  setVoiceConnectedAt: React.Dispatch<React.SetStateAction<number | null>>;

  // Custom status
  customStatus: string;
  showStatusPopover: boolean;
  setShowStatusPopover: React.Dispatch<React.SetStateAction<boolean>>;
  statusInput: string;
  setStatusInput: React.Dispatch<React.SetStateAction<string>>;

  // Pinned
  showPinnedPanel: boolean;
  setShowPinnedPanel: React.Dispatch<React.SetStateAction<boolean>>;
  pinnedMessages: Message[];

  // Reactions
  showEmojiPicker: string | null;
  setShowEmojiPicker: React.Dispatch<React.SetStateAction<string | null>>;
  hoveredMessageId: string | null;
  setHoveredMessageId: React.Dispatch<React.SetStateAction<string | null>>;

  // Notifications
  notificationPreferences: NotificationPreferences;
  showNotificationSettings: boolean;
  setShowNotificationSettings: React.Dispatch<React.SetStateAction<boolean>>;
  forceUpdate: number;

  // Search
  showSearchOverlay: boolean;
  setShowSearchOverlay: React.Dispatch<React.SetStateAction<boolean>>;

  // DMs
  dmChannels: DmChannelWithInfo[];
  selectedDmChannel: DmChannelWithInfo | null;
  showDmChannelCreate: boolean;
  setShowDmChannelCreate: React.Dispatch<React.SetStateAction<boolean>>;

  // Node creation
  showCreateNodeModal: boolean;
  setShowCreateNodeModal: React.Dispatch<React.SetStateAction<boolean>>;
  showJoinNodeModal: boolean;
  setShowJoinNodeModal: React.Dispatch<React.SetStateAction<boolean>>;
  joinInviteCode: string;
  setJoinInviteCode: React.Dispatch<React.SetStateAction<string>>;
  joiningNode: boolean;
  joinError: string;
  setJoinError: React.Dispatch<React.SetStateAction<string>>;
  newNodeName: string;
  setNewNodeName: React.Dispatch<React.SetStateAction<string>>;
  newNodeDescription: string;
  setNewNodeDescription: React.Dispatch<React.SetStateAction<string>>;
  creatingNode: boolean;

  // Settings
  showSettings: boolean;
  setShowSettings: React.Dispatch<React.SetStateAction<boolean>>;
  showNodeSettings: boolean;
  setShowNodeSettings: React.Dispatch<React.SetStateAction<boolean>>;

  // Trust
  serverBuildHash: string;
  serverHelloVersion: string;
  knownHashes: any;
  connectedSince: number | null;
  showConnectionInfo: boolean;
  setShowConnectionInfo: React.Dispatch<React.SetStateAction<boolean>>;

  // Categories
  collapsedCategories: Set<string>;
  setCollapsedCategories: React.Dispatch<React.SetStateAction<Set<string>>>;

  // Template import
  showTemplateImport: boolean;
  setShowTemplateImport: React.Dispatch<React.SetStateAction<boolean>>;
  templateInput: string;
  setTemplateInput: React.Dispatch<React.SetStateAction<string>>;
  templateImporting: boolean;
  setTemplateImporting: React.Dispatch<React.SetStateAction<boolean>>;
  templateResult: any;
  setTemplateResult: React.Dispatch<React.SetStateAction<any>>;
  templateError: string;
  setTemplateError: React.Dispatch<React.SetStateAction<string>>;

  // Delete channel
  deleteChannelConfirm: { id: string; name: string } | null;
  setDeleteChannelConfirm: React.Dispatch<React.SetStateAction<{ id: string; name: string } | null>>;

  // Display name
  showDisplayNamePrompt: boolean;
  setShowDisplayNamePrompt: React.Dispatch<React.SetStateAction<boolean>>;
  displayNameInput: string;
  setDisplayNameInput: React.Dispatch<React.SetStateAction<string>>;
  displayNameSaving: boolean;

  // Setup wizard
  showSetupWizard: boolean;

  // Keyboard shortcuts
  showShortcutsHelp: boolean;
  setShowShortcutsHelp: React.Dispatch<React.SetStateAction<boolean>>;

  // Member sidebar
  showMemberSidebar: boolean;
  setShowMemberSidebar: React.Dispatch<React.SetStateAction<boolean>>;

  // Emoji picker / files
  showInputEmojiPicker: boolean;
  setShowInputEmojiPicker: React.Dispatch<React.SetStateAction<boolean>>;
  stagedFiles: StagedFile[];
  messageInputRef: React.RefObject<HTMLTextAreaElement | null>;

  // Scroll
  showScrollToBottom: boolean;
  newMessageCount: number;

  // Presence
  presenceMap: Map<string, import('../types').PresenceStatus>;

  // Context menu
  contextMenu: { x: number; y: number; userId: string; publicKeyHash: string; displayName: string; bio?: string; user?: User } | null;
  setContextMenu: React.Dispatch<React.SetStateAction<{ x: number; y: number; userId: string; publicKeyHash: string; displayName: string; bio?: string; user?: User } | null>>;

  // Profile card
  profileCardTarget: { userId: string; x: number; y: number; user?: User; profile?: import('../types').UserProfile; roles?: Role[]; joinedAt?: number; roleColor?: string } | null;
  setProfileCardTarget: React.Dispatch<React.SetStateAction<{ userId: string; x: number; y: number; user?: User; profile?: import('../types').UserProfile; roles?: Role[]; joinedAt?: number; roleColor?: string } | null>>;

  // Blocking
  blockedUsers: Set<string>;
  showBlockConfirm: { userId: string; displayName: string } | null;
  setShowBlockConfirm: React.Dispatch<React.SetStateAction<{ userId: string; displayName: string } | null>>;

  // Typing
  typingUsers: Map<string, TypingUser[]>;

  // Read receipts
  readReceipts: Map<string, ReadReceipt[]>;

  // Bots
  installedBots: InstalledBot[];
  botResponses: BotResponseMessage[];
  loadBots: (nodeId: string) => Promise<void>;
  handleInvokeBot: (botId: string, command: string, params: Record<string, any>) => Promise<void>;

  // Message density
  messageDensity: string;

  // Role popup
  showRolePopup: { userId: string; x: number; y: number } | null;
  setShowRolePopup: React.Dispatch<React.SetStateAction<{ userId: string; x: number; y: number } | null>>;

  // ---- Handlers ----
  handleAuth: () => Promise<void>;
  handleLogout: () => void;
  handleSendMessage: () => Promise<void>;
  handleSaveEdit: () => Promise<void>;
  handleCancelEdit: () => void;
  handleDeleteMessage: (messageId: string) => Promise<void>;
  handleReply: (message: Message) => void;
  handleCancelReply: () => void;
  handleAddReaction: (messageId: string, emoji: string) => Promise<void>;
  handleRemoveReaction: (messageId: string, emoji: string) => Promise<void>;
  handleToggleReaction: (messageId: string, emoji: string) => Promise<void>;
  handlePinMessage: (messageId: string) => Promise<void>;
  handleUnpinMessage: (messageId: string) => Promise<void>;
  handleStartEdit: (messageId: string, content: string) => void;
  handleNodeSelect: (nodeId: string, index: number) => void;
  handleChannelSelect: (channelId: string, channelName: string) => void;
  handleCreateChannel: () => Promise<void>;
  handleGenerateInvite: () => Promise<void>;
  handleKickMember: (userId: string, username: string) => Promise<void>;
  handleDeleteChannelConfirmed: (channelId: string) => Promise<void>;
  handleJoinNode: () => Promise<void>;
  handleCreateNode: () => Promise<void>;
  handleDmChannelSelect: (dmChannel: DmChannelWithInfo) => void;
  openDmWithUser: (user: User) => Promise<void>;
  handleSaveDisplayName: () => Promise<void>;
  handleSaveCustomStatus: () => Promise<void>;
  handleServerConnect: () => Promise<void>;
  handleInviteLinkSubmit: () => Promise<void>;
  handleInviteRegister: () => Promise<void>;
  handleRecover: () => Promise<void>;
  handleNotificationPreferencesChange: (preferences: NotificationPreferences) => void;
  handleNavigateToMessage: (channelId: string, messageId: string) => void;
  handleBlockUser: (userId: string) => Promise<void>;
  handleUnblockUser: (userId: string) => Promise<void>;
  handleScroll: (e: React.UIEvent<HTMLDivElement>) => void;
  scrollToBottom: () => void;
  scrollToMessage: (messageId: string) => void;
  handleFilesStaged: (files: StagedFile[]) => void;
  handleRemoveStagedFile: (index: number) => void;
  handleClearStagedFiles: () => void;
  handleInsertEmoji: (emoji: string) => void;
  handleContextMenu: (e: React.MouseEvent, userId: string, publicKeyHash: string, name: string, bio?: string, user?: User) => void;
  togglePinnedPanel: () => void;
  toggleMemberRole: (userId: string, roleId: string, hasRole: boolean) => Promise<void>;
  sendTypingIndicator: (channelId: string) => void;
  formatTypingUsers: (channelId: string) => string;
  loadChannels: (nodeId: string) => Promise<void>;
  loadRoles: (nodeId: string) => Promise<void>;
  loadNodes: () => Promise<void>;
  loadDmChannels: () => Promise<void>;

  // Permission helpers
  hasPermission: (nodeId: string, permission: 'CreateChannel' | 'DeleteChannel' | 'ManageMembers' | 'KickMembers' | 'ManageInvites' | 'ManageNode') => boolean;
  getRoleBadge: (role: 'admin' | 'moderator' | 'member') => string;
  canDeleteMessage: (message: Message) => boolean;
  getPresenceStatus: (userId: string) => import('../types').PresenceStatus;
  getMemberRoleColor: (userId: string) => string | undefined;
  getMemberHighestHoistedRole: (userId: string) => Role | undefined;
  sortedMembers: Array<NodeMember & { user: User }>;

  // Utility
  fingerprint: (publicKeyHash: string) => string;
  displayName: (u: User | undefined) => string;
  copyToClipboard: (text: string) => Promise<boolean>;

  // Channel helpers
  getChannelTypeNum: (ch: Channel) => number;
  sortedChannels: Channel[];
  categories: Channel[];
  uncategorizedChannels: Channel[];
  categorizedChannels: (catId: string) => Channel[];
  toggleCategory: (catId: string) => void;
  servers: string[];

  // Constants
  COMMON_EMOJIS: string[];
}

export const AppContext = createContext<AppContextType>(null as any);

export function useAppContext() {
  return useContext(AppContext);
}
