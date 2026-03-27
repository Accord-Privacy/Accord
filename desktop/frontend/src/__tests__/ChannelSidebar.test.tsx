import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { ChannelSidebar, VoiceConnectionPanel } from '../components/ChannelSidebar';
import { AppContext } from '../components/AppContext';
import type { AppContextType } from '../components/AppContext';
import type { Channel, User } from '../types';
import * as notificationsModule from '../notifications';

// Mock dependencies
vi.mock('../api', () => ({
  api: {
    getUserAvatarUrl: vi.fn((_userId: string) => `https://example.com/avatar/${_userId}`),
    reorderChannels: vi.fn(() => Promise.resolve()),
  },
}));

vi.mock('../WhatsNew', () => ({
  hasUnseenChangelog: vi.fn(() => false),
}));

vi.mock('../notifications', () => ({
  notificationManager: {
    getChannelUnreads: vi.fn(() => ({ count: 0, mentions: 0 })),
    markChannelAsRead: vi.fn(),
  },
  muteManager: {
    isChannelMuted: vi.fn(() => false),
    isEffectivelyMuted: vi.fn(() => false),
    muteChannel: vi.fn(),
    unmuteChannel: vi.fn(),
    isNodeMuted: vi.fn(() => false),
  },
  MUTE_DURATIONS: [
    { label: '15 minutes', minutes: 15 },
    { label: '1 hour', minutes: 60 },
    { label: '8 hours', minutes: 480 },
  ],
}));

vi.mock('../avatarColor', () => ({
  avatarColor: vi.fn((_userId: string) => '#ff5733'),
}));

vi.mock('./ThreadsPanel', () => ({
  hasActiveThreads: vi.fn(() => false),
}));

// Mock ServerHeader component
vi.mock('../components/ServerHeader', () => ({
  ServerHeader: () => <div data-testid="server-header">Server Header</div>,
}));

// Mock BotPanel component
vi.mock('../components/BotPanel', () => ({
  BotPanel: () => <div data-testid="bot-panel">Bot Panel</div>,
}));

const mockTextChannel = (id: string, name: string, parentId: string | null = null): Channel => ({
  id,
  name,
  node_id: 'node-1',
  members: [],
  created_at: Date.now(),
  channel_type: 'text',
  parent_id: parentId,
  position: 0,
  topic: null,
  nsfw: false,
  icon_emoji: null,
});

const mockVoiceChannel = (id: string, name: string, parentId: string | null = null): Channel => ({
  id,
  name,
  node_id: 'node-1',
  members: [],
  created_at: Date.now(),
  channel_type: 'voice',
  parent_id: parentId,
  position: 0,
  topic: null,
  nsfw: false,
  icon_emoji: null,
});

const mockCategory = (id: string, name: string): Channel => ({
  id,
  name,
  node_id: 'node-1',
  members: [],
  created_at: Date.now(),
  channel_type: 'category',
  parent_id: null,
  position: 0,
  topic: null,
  nsfw: false,
  icon_emoji: null,
});

const mockUser = (id: string, displayName: string): User => ({
  id,
  public_key_hash: `hash-${id}`,
  public_key: `key-${id}`,
  created_at: Date.now(),
  display_name: displayName,
});

const createMockContext = (overrides: Partial<AppContextType> = {}): AppContextType => ({
  nodes: [],
  channels: [],
  members: [],
  selectedNodeId: 'node-1',
  selectedChannelId: null,
  activeServer: 0,
  activeChannel: '',
  ws: null,
  connectionInfo: {} as any,
  lastConnectionError: '',
  setLastConnectionError: vi.fn(),
  uncategorizedChannels: [],
  categories: [],
  categorizedChannels: vi.fn(() => []),
  collapsedCategories: new Set(),
  toggleCategory: vi.fn(),
  hasPermission: vi.fn(() => false),
  handleChannelSelect: vi.fn(),
  getChannelTypeNum: vi.fn((ch: Channel) => {
    if (ch.channel_type === 'voice') return 2;
    if (ch.channel_type === 'category') return 4;
    return 0;
  }),
  voiceChannelId: null,
  setVoiceChannelId: vi.fn(),
  voiceChannelName: '',
  setVoiceChannelName: vi.fn(),
  voiceConnectedAt: null,
  setVoiceConnectedAt: vi.fn(),
  voiceMuted: false,
  setVoiceMuted: vi.fn(),
  voiceDeafened: false,
  setVoiceDeafened: vi.fn(),
  voiceChannelUsers: [],
  setDeleteChannelConfirm: vi.fn(),
  showCreateChannelForm: false,
  setShowCreateChannelForm: vi.fn(),
  newChannelName: '',
  setNewChannelName: vi.fn(),
  newChannelType: 'text',
  setNewChannelType: vi.fn(),
  newChannelTopic: '',
  setNewChannelTopic: vi.fn(),
  newChannelCategoryId: '',
  setNewChannelCategoryId: vi.fn(),
  handleCreateChannel: vi.fn(),
  loadChannels: vi.fn(),
  dmChannels: [],
  selectedDmChannel: null,
  handleDmChannelSelect: vi.fn(),
  showDmChannelCreate: false,
  setShowDmChannelCreate: vi.fn(),
  getPresenceStatus: vi.fn(() => 'online'),
  appState: {
    user: mockUser('user-1', 'Test User'),
    isConnected: true,
    messages: [],
  } as any,
  userPresenceStatus: 'online',
  handleSetPresenceStatus: vi.fn(),
  showStatusPicker: false,
  setShowStatusPicker: vi.fn(),
  customStatus: '',
  statusInput: '',
  setStatusInput: vi.fn(),
  showStatusPopover: false,
  setShowStatusPopover: vi.fn(),
  handleSaveCustomStatus: vi.fn(),
  setShowSettings: vi.fn(),
  forceUpdate: 0,
  setForceUpdate: vi.fn(),
  fingerprint: vi.fn((hash: string) => `fp-${hash}`),
  ...overrides,
} as any);

describe('ChannelSidebar', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.setItem('accord_user_id', 'user-1');
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders channel sidebar with ServerHeader', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByTestId('server-header')).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Channel sidebar' })).toBeInTheDocument();
  });

  it('renders uncategorized channels section', () => {
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('CHANNELS')).toBeInTheDocument();
    expect(screen.getByText('general')).toBeInTheDocument();
  });

  it('renders text channel with hash symbol', () => {
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(container.querySelector('.channel-hash')).toBeInTheDocument();
  });

  it('renders voice channel with speaker icon', () => {
    const channels = [mockVoiceChannel('ch-1', 'Voice Chat')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('Voice Chat')).toBeInTheDocument();
    expect(container.querySelector('.channel-voice-text')).toBeInTheDocument();
  });

  it('applies active class to selected channel', () => {
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      selectedChannelId: 'ch-1',
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel.active');
    expect(channel).toBeInTheDocument();
  });

  it('calls handleChannelSelect when text channel is clicked', () => {
    const handleChannelSelect = vi.fn();
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      handleChannelSelect,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = screen.getByText('general');
    fireEvent.click(channel.closest('.channel-item-inner')!);
    expect(handleChannelSelect).toHaveBeenCalledWith('ch-1', '#general');
  });

  it('displays unread badge for channels with unreads', () => {
    (notificationsModule.notificationManager.getChannelUnreads as any).mockReturnValue({
      count: 5,
      mentions: 0,
    });
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      selectedChannelId: null,
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(container.querySelector('.unread-badge')).toBeInTheDocument();
    expect(container.querySelector('.unread-badge')?.textContent).toBe('5');
  });

  it('displays mention badge for channels with mentions', () => {
    (notificationsModule.notificationManager.getChannelUnreads as any).mockReturnValue({
      count: 5,
      mentions: 3,
    });
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      selectedChannelId: null,
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(container.querySelector('.mention-badge')).toBeInTheDocument();
    expect(container.querySelector('.mention-badge')?.textContent).toBe('3');
  });

  it('displays 9+ for mention counts over 9', () => {
    (notificationsModule.notificationManager.getChannelUnreads as any).mockReturnValue({
      count: 15,
      mentions: 12,
    });
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(container.querySelector('.mention-badge')?.textContent).toBe('9+');
  });

  it('displays 99+ for unread counts over 99', () => {
    (notificationsModule.notificationManager.getChannelUnreads as any).mockReturnValue({
      count: 150,
      mentions: 0,
    });
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(container.querySelector('.unread-badge')?.textContent).toBe('99+');
  });

  it('hides unread indicators for muted channels', () => {
    (notificationsModule.notificationManager.getChannelUnreads as any).mockReturnValue({
      count: 5,
      mentions: 2,
    });
    (notificationsModule.muteManager.isEffectivelyMuted as any).mockReturnValue(true);
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(container.querySelector('.unread-badge')).not.toBeInTheDocument();
    expect(container.querySelector('.mention-badge')).not.toBeInTheDocument();
  });

  it('displays muted icon for muted channels', () => {
    (notificationsModule.muteManager.isEffectivelyMuted as any).mockReturnValue(true);
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(container.querySelector('.channel-muted-icon')).toBeInTheDocument();
  });

  it('toggles category collapse when header is clicked', () => {
    const toggleCategory = vi.fn();
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      toggleCategory,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const categoryHeader = screen.getByText('CHANNELS').closest('.category-header');
    fireEvent.click(categoryHeader!);
    expect(toggleCategory).toHaveBeenCalledWith('__uncategorized__');
  });

  it('renders categories with their channels', () => {
    const category = mockCategory('cat-1', 'Important');
    const channels = [mockTextChannel('ch-1', 'announcements', 'cat-1')];
    const ctx = createMockContext({
      categories: [category],
      categorizedChannels: vi.fn((catId) => (catId === 'cat-1' ? channels : [])),
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('Important')).toBeInTheDocument();
    expect(screen.getByText('announcements')).toBeInTheDocument();
  });

  it('hides category children when collapsed', () => {
    const category = mockCategory('cat-1', 'Important');
    const channels = [mockTextChannel('ch-1', 'announcements', 'cat-1')];
    const ctx = createMockContext({
      categories: [category],
      categorizedChannels: vi.fn(() => channels),
      collapsedCategories: new Set(['cat-1']),
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('Important')).toBeInTheDocument();
    expect(screen.queryByText('announcements')).not.toBeInTheDocument();
  });

  it('displays create channel button with permission', () => {
    const ctx = createMockContext({
      hasPermission: vi.fn((_nodeId, perm) => perm === 'CreateChannel'),
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByRole('button', { name: 'Create Channel' })).toBeInTheDocument();
  });

  it('opens create channel form when button is clicked', () => {
    const setShowCreateChannelForm = vi.fn();
    const ctx = createMockContext({
      hasPermission: vi.fn(() => true),
      setShowCreateChannelForm,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const createBtn = screen.getByRole('button', { name: 'Create Channel' });
    fireEvent.click(createBtn);
    expect(setShowCreateChannelForm).toHaveBeenCalledWith(true);
  });

  it('renders create channel form with inputs', () => {
    const ctx = createMockContext({
      hasPermission: vi.fn(() => true),
      showCreateChannelForm: true,
      newChannelName: 'new-channel',
      newChannelTopic: 'A new topic',
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByPlaceholderText('Channel name')).toHaveValue('new-channel');
    expect(screen.getByPlaceholderText('Topic (optional)')).toHaveValue('A new topic');
  });

  it('updates channel name input', () => {
    const setNewChannelName = vi.fn();
    const ctx = createMockContext({
      hasPermission: vi.fn(() => true),
      showCreateChannelForm: true,
      setNewChannelName,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const input = screen.getByPlaceholderText('Channel name');
    fireEvent.change(input, { target: { value: 'test-channel' } });
    expect(setNewChannelName).toHaveBeenCalledWith('test-channel');
  });

  it('switches channel type to voice', () => {
    const setNewChannelType = vi.fn();
    const ctx = createMockContext({
      hasPermission: vi.fn(() => true),
      showCreateChannelForm: true,
      setNewChannelType,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const voiceBtn = screen.getByTitle('Voice Channel');
    fireEvent.click(voiceBtn);
    expect(setNewChannelType).toHaveBeenCalledWith('voice');
  });

  it('calls handleCreateChannel when Create button is clicked', () => {
    const handleCreateChannel = vi.fn();
    const ctx = createMockContext({
      hasPermission: vi.fn(() => true),
      showCreateChannelForm: true,
      handleCreateChannel,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const createBtn = screen.getByText('Create');
    fireEvent.click(createBtn);
    expect(handleCreateChannel).toHaveBeenCalled();
  });

  it('cancels create channel form and resets fields', () => {
    const setShowCreateChannelForm = vi.fn();
    const setNewChannelName = vi.fn();
    const ctx = createMockContext({
      hasPermission: vi.fn(() => true),
      showCreateChannelForm: true,
      setShowCreateChannelForm,
      setNewChannelName,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const cancelBtn = screen.getByText('Cancel');
    fireEvent.click(cancelBtn);
    expect(setShowCreateChannelForm).toHaveBeenCalledWith(false);
    expect(setNewChannelName).toHaveBeenCalledWith('');
  });

  it('displays delete button for channels with permission', () => {
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      hasPermission: vi.fn((_nodeId, perm) => perm === 'DeleteChannel'),
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(container.querySelector('.channel-delete-btn')).toBeInTheDocument();
  });

  it('opens delete confirmation when delete button is clicked', () => {
    const setDeleteChannelConfirm = vi.fn();
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      hasPermission: vi.fn(() => true),
      setDeleteChannelConfirm,
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const deleteBtn = container.querySelector('.channel-delete-btn');
    fireEvent.click(deleteBtn!);
    expect(setDeleteChannelConfirm).toHaveBeenCalledWith({ id: 'ch-1', name: 'general' });
  });

  it('connects to voice channel when voice channel is clicked', () => {
    const setVoiceChannelId = vi.fn();
    const setVoiceChannelName = vi.fn();
    const setVoiceConnectedAt = vi.fn();
    const channels = [mockVoiceChannel('vc-1', 'Voice Chat')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      setVoiceChannelId,
      setVoiceChannelName,
      setVoiceConnectedAt,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const voiceChannel = screen.getByText('Voice Chat').closest('.channel-item-inner');
    fireEvent.click(voiceChannel!);
    expect(setVoiceChannelId).toHaveBeenCalledWith('vc-1');
    expect(setVoiceChannelName).toHaveBeenCalledWith('Voice Chat');
    expect(setVoiceConnectedAt).toHaveBeenCalled();
  });

  it('displays voice connected indicator for connected voice channel', () => {
    const channels = [mockVoiceChannel('vc-1', 'Voice Chat')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      voiceChannelId: 'vc-1',
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(container.querySelector('.voice-channel-connected-dot')).toBeInTheDocument();
    expect(container.querySelector('.channel.voice-connected')).toBeInTheDocument();
  });

  it('displays voice channel users when connected', () => {
    const channels = [mockVoiceChannel('vc-1', 'Voice Chat')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      voiceChannelId: 'vc-1',
      voiceChannelUsers: [
        { userId: 'u1', displayName: 'User One', isSpeaking: false, isMuted: false },
        { userId: 'u2', displayName: 'User Two', isSpeaking: true, isMuted: false },
      ],
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('User One')).toBeInTheDocument();
    expect(screen.getByText('User Two')).toBeInTheDocument();
  });

  it('opens context menu on channel right-click', () => {
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel');
    fireEvent.contextMenu(channel!);
    expect(container.querySelector('.context-menu')).toBeInTheDocument();
  });

  it('displays Mark as Read in channel context menu', () => {
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel');
    fireEvent.contextMenu(channel!);
    expect(screen.getByText('Mark as Read')).toBeInTheDocument();
  });

  it('marks channel as read when menu item is clicked', () => {
    const channels = [mockTextChannel('ch-1', 'general')];
    const setForceUpdate = vi.fn();
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      setForceUpdate,
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel');
    fireEvent.contextMenu(channel!);
    const markReadBtn = screen.getByText('Mark as Read');
    fireEvent.click(markReadBtn);
    expect(notificationsModule.notificationManager.markChannelAsRead).toHaveBeenCalledWith(
      'node-1',
      'ch-1'
    );
  });

  it('displays Mute Channel submenu in context menu', () => {
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel');
    fireEvent.contextMenu(channel!);
    const muteItem = screen.getByText('Mute Channel');
    expect(muteItem).toBeInTheDocument();
    fireEvent.mouseEnter(muteItem);
    expect(screen.getByText('15 minutes')).toBeInTheDocument();
    expect(screen.getByText('1 hour')).toBeInTheDocument();
  });

  it('mutes channel when duration is selected', () => {
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel');
    fireEvent.contextMenu(channel!);
    const muteItem = screen.getByText('Mute Channel');
    fireEvent.mouseEnter(muteItem);
    const duration = screen.getByText('15 minutes');
    fireEvent.click(duration);
    expect(notificationsModule.muteManager.muteChannel).toHaveBeenCalledWith('ch-1', 15);
  });

  it('displays Unmute Channel when channel is muted', () => {
    (notificationsModule.muteManager.isChannelMuted as any).mockReturnValue(true);
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel');
    fireEvent.contextMenu(channel!);
    expect(screen.getByText('Unmute Channel')).toBeInTheDocument();
  });

  it('unmutes channel when Unmute Channel is clicked', () => {
    (notificationsModule.muteManager.isChannelMuted as any).mockReturnValue(true);
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel');
    fireEvent.contextMenu(channel!);
    const unmuteBtn = screen.getByText('Unmute Channel');
    fireEvent.click(unmuteBtn);
    expect(notificationsModule.muteManager.unmuteChannel).toHaveBeenCalledWith('ch-1');
  });

  it('closes context menu on Escape key', () => {
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel');
    fireEvent.contextMenu(channel!);
    expect(container.querySelector('.context-menu')).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(container.querySelector('.context-menu')).not.toBeInTheDocument();
  });

  it('closes context menu when clicking outside', () => {
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({ uncategorizedChannels: channels });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel');
    fireEvent.contextMenu(channel!);
    expect(container.querySelector('.context-menu')).toBeInTheDocument();
    fireEvent.mouseDown(document.body);
    expect(container.querySelector('.context-menu')).not.toBeInTheDocument();
  });

  it('supports keyboard navigation with Enter key for text channel', () => {
    const handleChannelSelect = vi.fn();
    const channels = [mockTextChannel('ch-1', 'general')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      handleChannelSelect,
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel');
    fireEvent.keyDown(channel!, { key: 'Enter' });
    expect(handleChannelSelect).toHaveBeenCalledWith('ch-1', '#general');
  });

  it('supports keyboard navigation with Space key for voice channel', () => {
    const setVoiceChannelId = vi.fn();
    const channels = [mockVoiceChannel('vc-1', 'Voice Chat')];
    const ctx = createMockContext({
      uncategorizedChannels: channels,
      setVoiceChannelId,
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const channel = container.querySelector('.channel');
    fireEvent.keyDown(channel!, { key: ' ' });
    expect(setVoiceChannelId).toHaveBeenCalledWith('vc-1');
  });

  it('renders DM section with create button', () => {
    const setShowDmChannelCreate = vi.fn();
    const ctx = createMockContext({ setShowDmChannelCreate });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('Direct Messages')).toBeInTheDocument();
    const addBtn = screen.getByRole('button', { name: 'Create direct message' });
    fireEvent.click(addBtn);
    expect(setShowDmChannelCreate).toHaveBeenCalledWith(true);
  });

  it('displays custom status in status popover', () => {
    const ctx = createMockContext({
      showStatusPopover: true,
      statusInput: 'Working hard',
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByPlaceholderText("What's on your mind?")).toHaveValue('Working hard');
  });

  it('closes status popover on Escape key', () => {
    const setShowStatusPopover = vi.fn();
    const ctx = createMockContext({
      showStatusPopover: true,
      setShowStatusPopover,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const popover = screen.getByRole('dialog', { name: 'Set Custom Status' });
    fireEvent.keyDown(popover, { key: 'Escape' });
    expect(setShowStatusPopover).toHaveBeenCalledWith(false);
  });

  it('saves custom status when Save button is clicked', () => {
    const handleSaveCustomStatus = vi.fn();
    const ctx = createMockContext({
      showStatusPopover: true,
      handleSaveCustomStatus,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    const saveBtn = screen.getByText('Save');
    fireEvent.click(saveBtn);
    expect(handleSaveCustomStatus).toHaveBeenCalled();
  });

  it('renders user panel with current user info', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <ChannelSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('Test User')).toBeInTheDocument();
  });
});

describe('VoiceConnectionPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('renders voice connection panel with channel name', () => {
    const onDisconnect = vi.fn();
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <VoiceConnectionPanel
          channelName="Voice Chat"
          connectedAt={Date.now()}
          onDisconnect={onDisconnect}
        />
      </AppContext.Provider>
    );
    expect(screen.getByText('Voice Connected')).toBeInTheDocument();
    expect(screen.getByText('Voice Chat')).toBeInTheDocument();
  });

  it('displays elapsed time counter', () => {
    const onDisconnect = vi.fn();
    const ctx = createMockContext();
    const now = Date.now();
    vi.setSystemTime(now);
    render(
      <AppContext.Provider value={ctx}>
        <VoiceConnectionPanel
          channelName="Voice Chat"
          connectedAt={now - 65000}
          onDisconnect={onDisconnect}
        />
      </AppContext.Provider>
    );
    // Initially shows 00:00
    expect(screen.getByText('00:00')).toBeInTheDocument();
    // Advance time by 1 second to trigger the interval
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    // After 1 second interval fires, timer should update to 01:06 (65s + 1s advanced)
    expect(screen.getByText('01:06')).toBeInTheDocument();
  });

  it('toggles mute when mute button is clicked', () => {
    const onDisconnect = vi.fn();
    const setVoiceMuted = vi.fn();
    const ctx = createMockContext({
      voiceMuted: false,
      setVoiceMuted,
    });
    render(
      <AppContext.Provider value={ctx}>
        <VoiceConnectionPanel
          channelName="Voice Chat"
          connectedAt={Date.now()}
          onDisconnect={onDisconnect}
        />
      </AppContext.Provider>
    );
    const muteBtn = screen.getByTitle('Mute');
    fireEvent.click(muteBtn);
    expect(setVoiceMuted).toHaveBeenCalledWith(true);
  });

  it('toggles deafen when deafen button is clicked', () => {
    const onDisconnect = vi.fn();
    const setVoiceDeafened = vi.fn();
    const setVoiceMuted = vi.fn();
    const ctx = createMockContext({
      voiceDeafened: false,
      setVoiceDeafened,
      setVoiceMuted,
    });
    render(
      <AppContext.Provider value={ctx}>
        <VoiceConnectionPanel
          channelName="Voice Chat"
          connectedAt={Date.now()}
          onDisconnect={onDisconnect}
        />
      </AppContext.Provider>
    );
    const deafenBtn = screen.getByTitle('Deafen');
    fireEvent.click(deafenBtn);
    expect(setVoiceDeafened).toHaveBeenCalledWith(true);
    expect(setVoiceMuted).toHaveBeenCalledWith(true);
  });

  it('calls onDisconnect when disconnect button is clicked', () => {
    const onDisconnect = vi.fn();
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <VoiceConnectionPanel
          channelName="Voice Chat"
          connectedAt={Date.now()}
          onDisconnect={onDisconnect}
        />
      </AppContext.Provider>
    );
    const disconnectBtn = screen.getByTitle('Disconnect');
    fireEvent.click(disconnectBtn);
    expect(onDisconnect).toHaveBeenCalled();
  });
});
