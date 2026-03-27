import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act, waitFor } from '@testing-library/react';
import { ChatArea } from '../components/ChatArea';
import { AppContext } from '../components/AppContext';
import type { AppContextType } from '../components/AppContext';
import type { Channel, User, Message, DmChannelWithInfo } from '../types';
import { PresenceStatus } from '../types';
import '../notifications';

// Mock dependencies
vi.mock('../api', () => ({
  api: {
    getUserAvatarUrl: vi.fn((userId: string) => `https://example.com/avatar/${userId}`),
    updateChannel: vi.fn(() => Promise.resolve()),
    previewInvite: vi.fn(() => Promise.resolve({
      node_name: 'Test Node',
      node_id: 'node-123',
      member_count: 5,
      server_build_hash: 'hash123',
    })),
    joinNodeByInvite: vi.fn(() => Promise.resolve()),
    setToken: vi.fn(),
  },
  parseInviteLink: vi.fn((link: string) => {
    if (link.includes('invite/')) {
      return { relayUrl: 'https://relay.com', inviteCode: 'ABC123' };
    }
    return null;
  }),
}));

vi.mock('../avatarColor', () => ({
  avatarColor: vi.fn((_userId: string) => '#ff5733'),
}));

vi.mock('../buildHash', () => ({
  verifyBuildHash: vi.fn(() => 'verified'),
  getTrustIndicator: vi.fn(() => ({ emoji: '✓', label: 'Verified', color: 'green' })),
}));

vi.mock('../notifications', () => ({
  notificationManager: {
    currentUsername: 'TestUser',
  },
}));

vi.mock('../markdown', () => ({
  renderMessageMarkdown: vi.fn((content: string) => content),
}));

vi.mock('../FileManager', () => ({
  FileUploadButton: () => <button>Upload File</button>,
  FileList: () => <div>File List</div>,
  FileDropZone: ({ children }: { children: React.ReactNode }) => <div data-testid="file-drop-zone">{children}</div>,
  FileAttachment: ({ file }: { file: any }) => <div>File: {file.encrypted_filename}</div>,
  StagedFilesPreview: ({ files }: { files: any[] }) => files.length > 0 ? <div data-testid="staged-files">{files.length} files</div> : null,
}));

vi.mock('../EmojiPicker', () => ({
  EmojiPickerButton: ({ onSelect }: { onSelect: (emoji: string) => void }) => (
    <button onClick={() => onSelect('😀')}>Emoji</button>
  ),
}));

vi.mock('../GifPicker', () => ({
  GifPickerButton: ({ onSelect }: { onSelect: (url: string) => void }) => (
    <button onClick={() => onSelect('https://gif.com/test.gif')}>GIF</button>
  ),
}));

vi.mock('../customEmojiStore', () => ({
  getNodeCustomEmojis: vi.fn(() => []),
  getCustomEmojiUrl: vi.fn(),
  subscribeCustomEmojis: vi.fn(() => vi.fn()),
}));

vi.mock('../LinkPreview', () => ({
  LinkPreview: () => <div>Link Preview</div>,
  extractAllUrls: vi.fn(() => []),
}));

vi.mock('../LoadingSpinner', () => ({
  LoadingSpinner: () => <div>Loading...</div>,
}));

vi.mock('./ConnectionBanner', () => ({
  ConnectionBanner: () => <div data-testid="connection-banner">Connection Banner</div>,
}));

vi.mock('./BotPanel', () => ({
  SlashCommandAutocomplete: () => null,
  CommandParamForm: () => null,
  BotResponseRenderer: () => null,
}));

vi.mock('./MentionAutocomplete', () => ({
  MentionAutocomplete: () => null,
}));

vi.mock('./SlashCommandPopup', () => ({
  SlashCommandPopup: () => null,
}));

vi.mock('../hooks/useMentionAutocomplete', () => ({
  useMentionAutocomplete: vi.fn(() => ({
    mentionState: { active: false, items: [], selectedIndex: 0, triggerChar: '@' },
    handleMentionInput: vi.fn(),
    handleMentionKeyDown: vi.fn(() => false),
    selectMentionItem: vi.fn(),
    dismissMention: vi.fn(),
  })),
}));

vi.mock('../hooks/useSlashCommands', () => ({
  useSlashCommands: vi.fn(() => ({
    slashState: { active: false, items: [], selectedIndex: 0 },
    handleSlashInput: vi.fn(),
    handleSlashKeyDown: vi.fn(() => false),
    selectSlashItem: vi.fn(),
    dismissSlash: vi.fn(),
    processSlashCommand: vi.fn(() => false),
  })),
}));

vi.mock('./ImageLightbox', () => ({
  ImageLightbox: () => <div data-testid="lightbox">Lightbox</div>,
}));

vi.mock('./ImageGrid', () => ({
  ImageGrid: () => <div>Image Grid</div>,
  getNonImageFiles: vi.fn((files) => files),
  hasImageGrid: vi.fn(() => false),
}));

vi.mock('./MediaEmbeds', () => ({
  MediaEmbeds: () => null,
}));

vi.mock('./MessageContextMenu', () => ({
  MessageContextMenu: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock('./SavedMessagesPanel', () => ({
  SavedMessagesPanel: () => <div data-testid="saved-messages-panel">Saved Messages</div>,
}));

vi.mock('./MessagePreview', () => ({
  MessagePreview: () => null,
}));

vi.mock('../hooks/useBookmarks', () => ({
  useBookmarks: vi.fn(() => ({
    bookmarks: [],
    addBookmark: vi.fn(),
    removeBookmark: vi.fn(),
    isBookmarked: vi.fn(() => false),
  })),
}));

// Mock VoiceChat as a lazy component
vi.mock('../VoiceChat', () => ({
  VoiceChat: () => <div data-testid="voice-chat">Voice Chat</div>,
}));

const mockUser = (id: string, displayName: string): User => ({
  id,
  public_key_hash: `hash-${id}`,
  public_key: `key-${id}`,
  created_at: Date.now(),
  display_name: displayName,
});

const mockMessage = (id: string, author: string, content: string, timestamp: number = Date.now()): Message => ({
  id,
  author,
  content,
  timestamp,
  channel_id: 'channel-1',
  sender_id: 'user-1',
});

const mockChannel = (id: string, name: string): Channel => ({
  id,
  name,
  node_id: 'node-1',
  members: [],
  created_at: Date.now(),
  channel_type: 'text',
  parent_id: null,
  position: 0,
  topic: null,
  nsfw: false,
  icon_emoji: null,
});

const mockDmChannel = (userId: string, displayName: string): DmChannelWithInfo => ({
  id: `dm-${userId}`,
  user1_id: 'user-1',
  user2_id: userId,
  other_user: { id: userId, public_key_hash: `hash-${userId}`, public_key: `key-${userId}`, created_at: Date.now() },
  other_user_profile: { user_id: userId, display_name: displayName, status: PresenceStatus.Online, updated_at: Date.now() },
  unread_count: 0,
  created_at: Date.now(),
});

const createMockContext = (overrides: Partial<AppContextType> = {}): AppContextType => ({
  nodes: [{ id: 'node-1', name: 'Test Node', owner_id: 'owner-1', created_at: Date.now(), members: [], channel_count: 1 }],
  channels: [mockChannel('channel-1', 'general')],
  members: [{ node_id: 'node-1', user_id: 'user-1', public_key_hash: 'hash-1', role: 'member', joined_at: Date.now(), user: mockUser('user-1', 'TestUser'), profile: { user_id: 'user-1', display_name: 'TestUser', status: PresenceStatus.Online, updated_at: Date.now() } }],
  selectedNodeId: 'node-1',
  selectedChannelId: 'channel-1',
  selectedDmChannel: null,
  activeChannel: 'general',
  message: '',
  setMessage: vi.fn(),
  handleSendMessage: vi.fn(),
  handleChannelSelect: vi.fn(),
  scrollToMessage: vi.fn(),
  scrollToBottom: vi.fn(),
  handleScroll: vi.fn(),
  showScrollToBottom: false,
  newMessageCount: 0,
  appState: {
    user: mockUser('user-1', 'TestUser'),
    isConnected: true,
    messages: [],
    token: 'test-token',
    activeChannel: 'channel-1',
  } as any,
  messageInputRef: { current: null } as any,
  messagesContainerRef: { current: null } as any,
  ws: null,
  connectionInfo: {} as any,
  encryptionEnabled: false,
  keyPair: null,
  hasExistingKey: false,
  pinnedMessages: [],
  showPinnedPanel: false,
  togglePinnedPanel: vi.fn(),
  showMemberSidebar: false,
  setShowMemberSidebar: vi.fn(),
  setShowSearchOverlay: vi.fn(),
  setMobileSidebarOpen: vi.fn(),
  displayName: vi.fn((user) => user.display_name || 'Unknown'),
  fingerprint: vi.fn((hash) => `fp-${hash}`),
  getPresenceStatus: vi.fn(() => PresenceStatus.Online),
  voiceChannelId: null,
  setVoiceChannelId: vi.fn(),
  voiceChannelName: '',
  setVoiceChannelName: vi.fn(),
  voiceConnectedAt: null,
  setVoiceConnectedAt: vi.fn(),
  setVoiceMuted: vi.fn(),
  setVoiceDeafened: vi.fn(),
  handleToggleReaction: vi.fn(),
  handleReply: vi.fn(),
  handleStartEdit: vi.fn(),
  handleSaveEdit: vi.fn(),
  handleCancelEdit: vi.fn(),
  handleDeleteMessage: vi.fn(),
  handlePinMessage: vi.fn(),
  handleUnpinMessage: vi.fn(),
  handleRetryMessage: vi.fn(),
  setShowDeleteConfirm: vi.fn(),
  setShowPinConfirm: vi.fn(),
  showDeleteConfirm: null,
  showPinConfirm: null,
  editingMessageId: null,
  editingContent: '',
  setEditingContent: vi.fn(),
  replyingTo: null,
  handleCancelReply: vi.fn(),
  canDeleteMessage: vi.fn(() => false),
  messageDensity: 'comfortable',
  isLoadingOlderMessages: false,
  hasMoreMessages: true,
  blockedUsers: new Set(),
  showEmojiPicker: null,
  setShowEmojiPicker: vi.fn(),
  showInputEmojiPicker: false,
  setShowInputEmojiPicker: vi.fn(),
  showGifPicker: false,
  setShowGifPicker: vi.fn(),
  handleInsertEmoji: vi.fn(),
  handleAddReaction: vi.fn(),
  COMMON_EMOJIS: ['👍', '❤️', '😂', '😮', '😢', '🎉'],
  readReceipts: new Map(),
  getMemberRoleColor: vi.fn(() => undefined),
  memberRolesMap: {},
  setProfileCardTarget: vi.fn(),
  handleContextMenu: vi.fn(),
  openThread: vi.fn(),
  serverAvailable: true,
  handleFilesStaged: vi.fn(),
  handleRemoveStagedFile: vi.fn(),
  handleClearStagedFiles: vi.fn(),
  stagedFiles: [],
  uploadProgress: null,
  messageError: null,
  slowModeSeconds: 0,
  slowModeCooldown: 0,
  sendTypingIndicator: vi.fn(),
  getTypingUsersForChannel: vi.fn(() => []),
  formatTypingUsers: vi.fn(() => ''),
  handleInvokeBot: vi.fn(),
  installedBots: [],
  inviteLinkInput: '',
  setInviteLinkInput: vi.fn(),
  joinInviteCode: '',
  loadNodes: vi.fn(),
  hasPermission: vi.fn(() => false),
  loadChannels: vi.fn(),
  setError: vi.fn(),
  knownHashes: [],
  dmChannels: [],
  ...overrides,
} as any);

describe('ChatArea', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Empty state (no nodes)', () => {
    it('renders welcome screen when no nodes joined', () => {
      const ctx = createMockContext({ nodes: [] });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText('Welcome to Accord!')).toBeInTheDocument();
      expect(screen.getByText(/Join a Node to start chatting/i)).toBeInTheDocument();
    });

    it('shows invite input field on welcome screen', () => {
      const ctx = createMockContext({ nodes: [] });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByPlaceholderText('Paste invite link here...')).toBeInTheDocument();
    });

    it('updates invite link input on change', () => {
      const setInviteLinkInput = vi.fn();
      const ctx = createMockContext({ nodes: [], setInviteLinkInput });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText('Paste invite link here...');
      fireEvent.change(input, { target: { value: 'https://invite/ABC123' } });
      expect(setInviteLinkInput).toHaveBeenCalledWith('https://invite/ABC123');
    });

    it('previews invite when Preview button is clicked', async () => {
      const { api } = await import('../api');
      const ctx = createMockContext({ nodes: [], inviteLinkInput: 'https://invite/ABC123' });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const previewBtn = screen.getByText('Preview →');
      await act(async () => {
        fireEvent.click(previewBtn);
      });
      expect(api.previewInvite).toHaveBeenCalled();
    });
  });

  describe('Chat header', () => {
    it('renders chat header with channel name', () => {
      const ctx = createMockContext();
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText('general')).toBeInTheDocument();
    });

    it('renders DM header with user info', () => {
      const dmChannel = mockDmChannel('user-2', 'OtherUser');
      const ctx = createMockContext({ selectedDmChannel: dmChannel, selectedChannelId: null });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(container.querySelector('.chat-channel-name')).toHaveTextContent('OtherUser');
    });

    it('shows pinned messages button', () => {
      const ctx = createMockContext();
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByRole('button', { name: 'Pinned Messages' })).toBeInTheDocument();
    });

    it('toggles pinned panel when button is clicked', () => {
      const togglePinnedPanel = vi.fn();
      const ctx = createMockContext({ togglePinnedPanel });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const pinnedBtn = screen.getByRole('button', { name: 'Pinned Messages' });
      fireEvent.click(pinnedBtn);
      expect(togglePinnedPanel).toHaveBeenCalled();
    });

    it('shows saved messages button', () => {
      const ctx = createMockContext();
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByRole('button', { name: 'Saved Messages' })).toBeInTheDocument();
    });

    it('shows E2EE indicator when encryption enabled', () => {
      const ctx = createMockContext({ encryptionEnabled: true, keyPair: {} as any });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText('E2EE')).toBeInTheDocument();
    });

    it('shows search button', () => {
      const ctx = createMockContext();
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByRole('button', { name: 'Search messages' })).toBeInTheDocument();
    });

    it('opens search overlay when search button is clicked', () => {
      const setShowSearchOverlay = vi.fn();
      const ctx = createMockContext({ setShowSearchOverlay });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const searchBtn = screen.getByRole('button', { name: 'Search messages' });
      fireEvent.click(searchBtn);
      expect(setShowSearchOverlay).toHaveBeenCalledWith(true);
    });

    it('toggles member sidebar when button is clicked', () => {
      const setShowMemberSidebar = vi.fn();
      const ctx = createMockContext({ setShowMemberSidebar });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const memberBtn = screen.getByRole('button', { name: 'Toggle member list' });
      fireEvent.click(memberBtn);
      expect(setShowMemberSidebar).toHaveBeenCalled();
    });
  });

  describe('Message rendering', () => {
    it('renders empty state when no messages', () => {
      const ctx = createMockContext({ appState: { ...createMockContext().appState, messages: [] } as any });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText('No messages yet')).toBeInTheDocument();
      expect(screen.getByText('Be the first to send a message in this channel!')).toBeInTheDocument();
    });

    it('renders message with author and content', () => {
      const msg = mockMessage('msg-1', 'TestUser', 'Hello world!');
      const ctx = createMockContext({ appState: { ...createMockContext().appState, messages: [msg] } as any });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText('TestUser')).toBeInTheDocument();
      expect(screen.getByText('Hello world!')).toBeInTheDocument();
    });

    it('renders multiple messages', () => {
      const messages = [
        mockMessage('msg-1', 'TestUser', 'First message', Date.now() - 1000),
        mockMessage('msg-2', 'TestUser', 'Second message', Date.now()),
      ];
      const ctx = createMockContext({ appState: { ...createMockContext().appState, messages } as any });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText('First message')).toBeInTheDocument();
      expect(screen.getByText('Second message')).toBeInTheDocument();
    });

    it('groups consecutive messages from same author', () => {
      const messages = [
        mockMessage('msg-1', 'TestUser', 'First', Date.now() - 1000),
        mockMessage('msg-2', 'TestUser', 'Second', Date.now()),
      ];
      const ctx = createMockContext({ appState: { ...createMockContext().appState, messages } as any });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const groupedMessages = container.querySelectorAll('.message-grouped');
      expect(groupedMessages.length).toBeGreaterThan(0);
    });

    it('shows edited indicator when message is edited', () => {
      const msg = { ...mockMessage('msg-1', 'TestUser', 'Edited content'), edited_at: Date.now() };
      const ctx = createMockContext({ appState: { ...createMockContext().appState, messages: [msg] } as any });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(container.querySelector('.message-edited')).toBeInTheDocument();
    });

    it('shows pinned badge when message is pinned', () => {
      const msg = { ...mockMessage('msg-1', 'TestUser', 'Pinned message'), pinned_at: Date.now() };
      const ctx = createMockContext({ appState: { ...createMockContext().appState, messages: [msg] } as any });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(container.querySelector('.message-pinned-badge')).toBeInTheDocument();
    });

    it('renders reactions on messages', () => {
      const msg = {
        ...mockMessage('msg-1', 'TestUser', 'Message with reactions'),
        reactions: [{ emoji: '👍', count: 3, users: ['user-1', 'user-2', 'user-3'], created_at: Date.now() }],
      };
      const ctx = createMockContext({ appState: { ...createMockContext().appState, messages: [msg] } as any });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(container.querySelector('.reaction')).toBeInTheDocument();
      expect(screen.getByText('3')).toBeInTheDocument();
    });

    it('toggles reaction when reaction button is clicked', () => {
      const handleToggleReaction = vi.fn();
      const msg = {
        ...mockMessage('msg-1', 'TestUser', 'Message'),
        reactions: [{ emoji: '👍', count: 1, users: ['user-2'], created_at: Date.now() }],
      };
      const ctx = createMockContext({
        appState: { ...createMockContext().appState, messages: [msg] } as any,
        handleToggleReaction,
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const reaction = container.querySelector('.reaction');
      fireEvent.click(reaction!);
      expect(handleToggleReaction).toHaveBeenCalledWith('msg-1', '👍');
    });

    it('shows reply preview when message has reply_to', () => {
      const msg = {
        ...mockMessage('msg-1', 'TestUser', 'Reply message'),
        reply_to: 'msg-0',
        replied_message: {
          id: 'msg-0',
          sender_id: 'user-2',
          sender_public_key_hash: 'hash-2',
          encrypted_payload: '',
          created_at: Date.now() - 5000,
          content: 'Original message',
        },
      };
      const ctx = createMockContext({ appState: { ...createMockContext().appState, messages: [msg] } as any });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(container.querySelector('.reply-preview')).toBeInTheDocument();
      expect(screen.getByText('Original message')).toBeInTheDocument();
    });

    it('scrolls to replied message when reply preview is clicked', () => {
      const scrollToMessage = vi.fn();
      const msg = {
        ...mockMessage('msg-1', 'TestUser', 'Reply'),
        reply_to: 'msg-0',
        replied_message: {
          id: 'msg-0',
          sender_id: 'user-2',
          sender_public_key_hash: 'hash-2',
          encrypted_payload: '',
          created_at: Date.now(),
          content: 'Original',
        },
      };
      const ctx = createMockContext({
        appState: { ...createMockContext().appState, messages: [msg] } as any,
        scrollToMessage,
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const replyPreview = container.querySelector('.reply-preview');
      fireEvent.click(replyPreview!);
      expect(scrollToMessage).toHaveBeenCalledWith('msg-0');
    });

    it('filters out messages from blocked users', () => {
      const messages = [
        mockMessage('msg-1', 'TestUser', 'Visible', Date.now()),
        { ...mockMessage('msg-2', 'BlockedUser', 'Hidden', Date.now()), sender_id: 'blocked-user' },
      ];
      const ctx = createMockContext({
        appState: { ...createMockContext().appState, messages } as any,
        blockedUsers: new Set(['blocked-user']),
      });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText('Visible')).toBeInTheDocument();
      expect(screen.queryByText('Hidden')).not.toBeInTheDocument();
    });
  });

  describe('Message actions', () => {
    it('shows message actions on hover', () => {
      const msg = mockMessage('msg-1', 'TestUser', 'Message');
      const ctx = createMockContext({ appState: { ...createMockContext().appState, messages: [msg] } as any });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(container.querySelector('.message-actions')).toBeInTheDocument();
    });

    it('calls handleReply when reply button is clicked', () => {
      const handleReply = vi.fn();
      const msg = mockMessage('msg-1', 'TestUser', 'Message');
      const ctx = createMockContext({
        appState: { ...createMockContext().appState, messages: [msg] } as any,
        handleReply,
      });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const replyBtn = screen.getByRole('button', { name: 'Reply' });
      fireEvent.click(replyBtn);
      expect(handleReply).toHaveBeenCalledWith(msg);
    });

    it('shows edit button for own messages', () => {
      const msg = mockMessage('msg-1', 'TestUser', 'My message');
      const ctx = createMockContext({
        appState: {
          ...createMockContext().appState,
          messages: [msg],
          user: mockUser('user-1', 'TestUser'),
        } as any,
      });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByRole('button', { name: 'Edit message' })).toBeInTheDocument();
    });

    it('calls handleStartEdit when edit button is clicked', () => {
      const handleStartEdit = vi.fn();
      const msg = mockMessage('msg-1', 'TestUser', 'My message');
      const ctx = createMockContext({
        appState: {
          ...createMockContext().appState,
          messages: [msg],
          user: mockUser('user-1', 'TestUser'),
        } as any,
        handleStartEdit,
      });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const editBtn = screen.getByRole('button', { name: 'Edit message' });
      fireEvent.click(editBtn);
      expect(handleStartEdit).toHaveBeenCalledWith('msg-1', 'My message');
    });

    it('shows delete button for own messages', () => {
      const msg = mockMessage('msg-1', 'TestUser', 'My message');
      const ctx = createMockContext({
        appState: {
          ...createMockContext().appState,
          messages: [msg],
          user: mockUser('user-1', 'TestUser'),
        } as any,
      });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByRole('button', { name: 'Delete message' })).toBeInTheDocument();
    });

    it('opens delete confirmation when delete button is clicked', () => {
      const setShowDeleteConfirm = vi.fn();
      const msg = mockMessage('msg-1', 'TestUser', 'My message');
      const ctx = createMockContext({
        appState: {
          ...createMockContext().appState,
          messages: [msg],
          user: mockUser('user-1', 'TestUser'),
        } as any,
        setShowDeleteConfirm,
      });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const deleteBtn = screen.getByRole('button', { name: 'Delete message' });
      fireEvent.click(deleteBtn);
      expect(setShowDeleteConfirm).toHaveBeenCalledWith('msg-1');
    });
  });

  describe('Message editing', () => {
    it('shows edit interface when editing', () => {
      const msg = mockMessage('msg-1', 'TestUser', 'Original content');
      const ctx = createMockContext({
        appState: { ...createMockContext().appState, messages: [msg] } as any,
        editingMessageId: 'msg-1',
        editingContent: 'Original content',
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(container.querySelector('.message-edit-container')).toBeInTheDocument();
      expect(container.querySelector('.message-edit-input')).toBeInTheDocument();
    });

    it('updates editing content on change', () => {
      const setEditingContent = vi.fn();
      const msg = mockMessage('msg-1', 'TestUser', 'Original');
      const ctx = createMockContext({
        appState: { ...createMockContext().appState, messages: [msg] } as any,
        editingMessageId: 'msg-1',
        editingContent: 'Original',
        setEditingContent,
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const input = container.querySelector('.message-edit-input') as HTMLTextAreaElement;
      fireEvent.change(input, { target: { value: 'Updated content' } });
      expect(setEditingContent).toHaveBeenCalledWith('Updated content');
    });

    it('saves edit on Enter key', () => {
      const handleSaveEdit = vi.fn();
      const msg = mockMessage('msg-1', 'TestUser', 'Original');
      const ctx = createMockContext({
        appState: { ...createMockContext().appState, messages: [msg] } as any,
        editingMessageId: 'msg-1',
        editingContent: 'Updated',
        handleSaveEdit,
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const input = container.querySelector('.message-edit-input') as HTMLTextAreaElement;
      fireEvent.keyDown(input, { key: 'Enter', shiftKey: false });
      expect(handleSaveEdit).toHaveBeenCalled();
    });

    it('cancels edit on Escape key', () => {
      const handleCancelEdit = vi.fn();
      const msg = mockMessage('msg-1', 'TestUser', 'Original');
      const ctx = createMockContext({
        appState: { ...createMockContext().appState, messages: [msg] } as any,
        editingMessageId: 'msg-1',
        editingContent: 'Updated',
        handleCancelEdit,
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const input = container.querySelector('.message-edit-input') as HTMLTextAreaElement;
      fireEvent.keyDown(input, { key: 'Escape' });
      expect(handleCancelEdit).toHaveBeenCalled();
    });
  });

  describe('Message input', () => {
    it('renders message input textarea', () => {
      const ctx = createMockContext();
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByPlaceholderText(/Message general/i)).toBeInTheDocument();
    });

    it('updates message state on input change', () => {
      const setMessage = vi.fn();
      const ctx = createMockContext({ setMessage });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText(/Message general/i) as HTMLTextAreaElement;
      fireEvent.change(input, { target: { value: 'Hello!' } });
      expect(setMessage).toHaveBeenCalledWith('Hello!');
    });

    it('sends message on Enter key', () => {
      const handleSendMessage = vi.fn();
      const ctx = createMockContext({ message: 'Test message', handleSendMessage });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText(/Message general/i) as HTMLTextAreaElement;
      fireEvent.keyDown(input, { key: 'Enter', shiftKey: false });
      expect(handleSendMessage).toHaveBeenCalled();
    });

    it('sends typing indicator on input', () => {
      const sendTypingIndicator = vi.fn();
      const setMessage = vi.fn();
      const ctx = createMockContext({ sendTypingIndicator, setMessage });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText(/Message general/i) as HTMLTextAreaElement;
      fireEvent.change(input, { target: { value: 'Typing...' } });
      expect(sendTypingIndicator).toHaveBeenCalledWith('channel-1');
    });

    it('shows reply preview when replying', () => {
      const replyingTo = mockMessage('msg-1', 'OtherUser', 'Original message');
      const ctx = createMockContext({ replyingTo });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText(/Replying to/i)).toBeInTheDocument();
      expect(screen.getByText('OtherUser')).toBeInTheDocument();
    });

    it('cancels reply when cancel button is clicked', () => {
      const handleCancelReply = vi.fn();
      const replyingTo = mockMessage('msg-1', 'OtherUser', 'Original');
      const ctx = createMockContext({ replyingTo, handleCancelReply });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const cancelBtn = screen.getByRole('button', { name: 'Cancel reply' });
      fireEvent.click(cancelBtn);
      expect(handleCancelReply).toHaveBeenCalled();
    });

    it('shows send button', () => {
      const ctx = createMockContext();
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(container.querySelector('.send-btn')).toBeInTheDocument();
    });

    it('calls handleSendMessage when send button is clicked', () => {
      const handleSendMessage = vi.fn();
      const ctx = createMockContext({ message: 'Test', handleSendMessage });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const sendBtn = screen.getByRole('button', { name: 'Send message' });
      fireEvent.click(sendBtn);
      expect(handleSendMessage).toHaveBeenCalled();
    });

    it('disables input when in slow mode', () => {
      const ctx = createMockContext({ slowModeCooldown: 5 });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText(/wait 5s/i) as HTMLTextAreaElement;
      expect(input).toBeDisabled();
    });

    it('shows slow mode toast when active', () => {
      const ctx = createMockContext({ slowModeCooldown: 3 });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText(/wait 3s/i)).toBeInTheDocument();
    });
  });

  describe('Scroll behavior', () => {
    it('shows scroll to bottom button when not at bottom', () => {
      const ctx = createMockContext({ showScrollToBottom: true, newMessageCount: 5 });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(container.querySelector('.scroll-to-bottom-fab')).toBeInTheDocument();
    });

    it('scrolls to bottom when button is clicked', () => {
      const scrollToBottom = vi.fn();
      const ctx = createMockContext({ showScrollToBottom: true, scrollToBottom });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const btn = container.querySelector('.scroll-to-bottom-fab');
      fireEvent.click(btn!);
      expect(scrollToBottom).toHaveBeenCalled();
    });

    it('shows new message count badge on scroll button', () => {
      const ctx = createMockContext({ showScrollToBottom: true, newMessageCount: 3 });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const badge = container.querySelector('.scroll-to-bottom-badge');
      expect(badge?.textContent).toBe('3');
    });

    it('shows unread banner when there are new messages', () => {
      const ctx = createMockContext({ showScrollToBottom: true, newMessageCount: 2 });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText(/2 new messages/i)).toBeInTheDocument();
    });

    it('scrolls to bottom when unread banner is clicked', () => {
      const scrollToBottom = vi.fn();
      const ctx = createMockContext({ showScrollToBottom: true, newMessageCount: 2, scrollToBottom });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const banner = screen.getByText(/2 new messages/i);
      fireEvent.click(banner);
      expect(scrollToBottom).toHaveBeenCalled();
    });
  });

  describe('File uploads', () => {
    it('shows staged files preview when files are staged', () => {
      const stagedFiles = [{ name: 'test.png', size: 1024 }];
      const ctx = createMockContext({ stagedFiles: stagedFiles as any });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByTestId('staged-files')).toBeInTheDocument();
    });

    it('shows upload progress bar when uploading', () => {
      const uploadProgress = { fileName: 'test.png', percentage: 50, current: 1, totalFiles: 1 };
      const ctx = createMockContext({ uploadProgress: uploadProgress as any });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(container.querySelector('.upload-progress-bar-container')).toBeInTheDocument();
      expect(screen.getByText(/Uploading test.png/i)).toBeInTheDocument();
      expect(screen.getByText('50%')).toBeInTheDocument();
    });
  });

  describe('Loading states', () => {
    it('shows loading indicator for older messages', () => {
      const ctx = createMockContext({ isLoadingOlderMessages: true });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText('Loading older messages...')).toBeInTheDocument();
    });

    it('shows beginning of channel message when no more messages', () => {
      const msg = mockMessage('msg-1', 'TestUser', 'First message');
      const ctx = createMockContext({
        appState: { ...createMockContext().appState, messages: [msg] } as any,
        hasMoreMessages: false,
      });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      expect(screen.getByText(/Welcome to general!/i)).toBeInTheDocument();
    });
  });

  describe('Voice chat', () => {
    it('renders voice chat component when connected to voice', async () => {
      const ctx = createMockContext({ voiceChannelId: 'vc-1', voiceChannelName: 'Voice Chat' });
      render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      await waitFor(() => {
        expect(screen.getByTestId('voice-chat')).toBeInTheDocument();
      });
    });
  });

  describe('Date separators', () => {
    it('shows date separator between messages on different days', () => {
      const yesterday = Date.now() - 86400000;
      const today = Date.now();
      const messages = [
        mockMessage('msg-1', 'TestUser', 'Yesterday', yesterday),
        mockMessage('msg-2', 'TestUser', 'Today', today),
      ];
      const ctx = createMockContext({ appState: { ...createMockContext().appState, messages } as any });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <ChatArea />
        </AppContext.Provider>
      );
      const separators = container.querySelectorAll('.date-separator');
      expect(separators.length).toBeGreaterThan(0);
    });
  });
});
