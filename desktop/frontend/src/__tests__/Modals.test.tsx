import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { AppModals } from '../components/Modals';
import { AppContext } from '../components/AppContext';
import type { AppContextType } from '../components/AppContext';
import type { NodeMember, User, Role } from '../types';
// Node, Channel removed — unused

// Mock the API module
vi.mock('../api', () => ({
  api: {
    joinNode: vi.fn(),
    createNode: vi.fn(),
    generateInvite: vi.fn(),
    deleteChannel: vi.fn(),
    importDiscordTemplate: vi.fn(),
    getBaseUrl: vi.fn(() => 'https://relay.example.com'),
    unpinMessage: vi.fn(),
    getUserAvatarUrl: vi.fn((_userId: string) => `https://example.com/avatar/${_userId}`),
  },
  parseInviteLink: (val: string) => {
    if (val.includes('invite/') || val.match(/^[A-Za-z0-9]{6,}$/)) {
      return { code: val };
    }
    return null;
  },
}));

// Mock markdown renderer
vi.mock('../markdown', () => ({
  renderMessageMarkdown: (content: string, _username?: string) => content,
}));

// Mock notifications
vi.mock('../notifications', () => ({
  notificationManager: { currentUsername: 'testuser' },
}));

// Mock lazy-loaded components
vi.mock('../SearchOverlay', () => ({
  SearchOverlay: () => <div data-testid="search-overlay">Search Overlay</div>,
}));

vi.mock('../LoadingSpinner', () => ({
  LoadingSpinner: () => <div data-testid="loading-spinner">Loading...</div>,
}));

vi.mock('../ProfileCard', () => ({
  ProfileCard: () => <div data-testid="profile-card">Profile Card</div>,
}));

vi.mock('../LinkPreview', () => ({
  LinkPreview: () => <div>Link Preview</div>,
  extractFirstUrl: (content: string) => {
    const match = content.match(/https?:\/\/[^\s]+/);
    return match ? match[0] : null;
  },
}));

vi.mock('../keyboard', () => ({
  SHORTCUT_GROUPS: [
    {
      title: 'Navigation',
      shortcuts: [{ label: 'Ctrl+K', description: 'Search' }],
    },
  ],
}));

vi.mock('../NodeSettings', () => ({
  NodeSettings: () => <div data-testid="node-settings">Node Settings</div>,
}));

vi.mock('../NotificationSettings', () => ({
  NotificationSettings: () => <div data-testid="notification-settings">Notification Settings</div>,
}));

vi.mock('../Settings', () => ({
  Settings: () => <div data-testid="settings">Settings</div>,
}));

vi.mock('../avatarColor', () => ({
  avatarColor: (_userId: string) => '#ff5733',
}));

vi.mock('./Icon', () => ({
  Icon: ({ name, size }: { name: string; size?: number }) => (
    <span data-testid={`icon-${name}`} data-size={size}>{name}</span>
  ),
}));

const mockUser = (id: string): User => ({
  id,
  public_key_hash: `hash-${id}`,
  public_key: `key-${id}`,
  created_at: Date.now(),
  display_name: `User ${id}`,
});


const createMockContext = (overrides: Partial<AppContextType> = {}): AppContextType => ({
  nodes: [],
  channels: [],
  members: [],
  selectedNodeId: null,
  selectedChannelId: null,
  activeServer: 0,
  activeChannel: '',
  ws: null,
  connectionInfo: {} as any,
  lastConnectionError: '',
  setLastConnectionError: vi.fn(),
  appState: { token: 'test-token', user: mockUser('user-1'), isConnected: true } as any,
  // Modal states
  showJoinNodeModal: false,
  setShowJoinNodeModal: vi.fn(),
  showCreateNodeModal: false,
  setShowCreateNodeModal: vi.fn(),
  showInviteModal: false,
  setShowInviteModal: vi.fn(),
  deleteChannelConfirm: null,
  setDeleteChannelConfirm: vi.fn(),
  showTemplateImport: false,
  setShowTemplateImport: vi.fn(),
  showDmChannelCreate: false,
  setShowDmChannelCreate: vi.fn(),
  showDisplayNamePrompt: false,
  setShowDisplayNamePrompt: vi.fn(),
  showRolePopup: null,
  setShowRolePopup: vi.fn(),
  showBlockConfirm: null,
  setShowBlockConfirm: vi.fn(),
  showShortcutsHelp: false,
  setShowShortcutsHelp: vi.fn(),
  showConnectionInfo: false,
  setShowConnectionInfo: vi.fn(),
  showPinnedPanel: false,
  setShowPinnedPanel: vi.fn(),
  showSearchOverlay: false,
  setShowSearchOverlay: vi.fn(),
  showNodeSettings: false,
  setShowNodeSettings: vi.fn(),
  showNotificationSettings: false,
  setShowNotificationSettings: vi.fn(),
  showSettings: false,
  setShowSettings: vi.fn(),
  error: '',
  setError: vi.fn(),
  // Join/Create node
  joinInviteCode: '',
  setJoinInviteCode: vi.fn(),
  joinError: '',
  setJoinError: vi.fn(),
  joiningNode: false,
  handleJoinNode: vi.fn(),
  newNodeName: '',
  setNewNodeName: vi.fn(),
  newNodeDescription: '',
  setNewNodeDescription: vi.fn(),
  creatingNode: false,
  handleCreateNode: vi.fn(),
  // Invite
  generatedInvite: '',
  setGeneratedInvite: vi.fn(),
  inviteCopied: false,
  setInviteCopied: vi.fn(),
  inviteGenerating: false,
  inviteExpiry: '24',
  setInviteExpiry: vi.fn(),
  inviteMaxUses: '',
  setInviteMaxUses: vi.fn(),
  handleGenerateInviteWithOptions: vi.fn(),
  copyToClipboard: vi.fn((_text: string) => Promise.resolve(true)),
  // Template import
  templateInput: '',
  setTemplateInput: vi.fn(),
  templateError: '',
  setTemplateError: vi.fn(),
  templateResult: null,
  setTemplateResult: vi.fn(),
  templateImporting: false,
  setTemplateImporting: vi.fn(),
  loadChannels: vi.fn(),
  loadRoles: vi.fn(),
  // Display name
  displayNameInput: '',
  setDisplayNameInput: vi.fn(),
  displayNameSaving: false,
  handleSaveDisplayName: vi.fn(),
  // Roles
  nodeRoles: [],
  memberRolesMap: {},
  toggleMemberRole: vi.fn(),
  // Members
  displayName: vi.fn((user: User | undefined) => user?.display_name || user?.id || 'Unknown'),
  getPresenceStatus: vi.fn(() => 'online'),
  getRoleBadge: vi.fn(() => ''),
  openDmWithUser: vi.fn(),
  getMemberRoleColor: vi.fn(() => null),
  // Profile card
  profileCardTarget: null,
  setProfileCardTarget: vi.fn(),
  // Context menu
  contextMenu: null,
  setContextMenu: vi.fn(),
  fingerprint: vi.fn((hash: string) => hash.slice(0, 8)),
  // Block
  blockedUsers: new Set(),
  handleBlockUser: vi.fn(),
  handleUnblockUser: vi.fn(),
  // Pinned messages
  pinnedMessages: [],
  canDeleteMessage: vi.fn(() => false),
  scrollToMessage: vi.fn(),
  // Thread
  threadParentMessage: null,
  closeThread: vi.fn(),
  threadMessages: [],
  threadLoading: false,
  // Connection info
  serverHelloVersion: '1.0.0',
  serverBuildHash: 'abc123',
  connectedSince: Date.now(),
  handleLogout: vi.fn(),
  setServerUrl: vi.fn(),
  notificationPreferences: {} as any,
  handleNotificationPreferencesChange: vi.fn(),
  knownHashes: [],
  handleNavigateToMessage: vi.fn(),
  keyPair: null,
  encryptionEnabled: false,
  userRoles: {},
  hasPermission: vi.fn(() => false),
  ...overrides,
} as any);

describe('AppModals', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.setItem('accord_user_id', 'user-1');
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  describe('Error Toast', () => {
    it('displays error message when error is set', () => {
      const ctx = createMockContext({ error: 'Something went wrong' });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });

    it('closes error toast when close button is clicked', () => {
      const setError = vi.fn();
      const ctx = createMockContext({ error: 'Test error', setError });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const closeButton = screen.getByRole('button', { name: /×/i });
      fireEvent.click(closeButton);
      expect(setError).toHaveBeenCalledWith('');
    });
  });

  describe('Join Node Modal', () => {
    it('renders join node modal when showJoinNodeModal is true', () => {
      const ctx = createMockContext({ showJoinNodeModal: true });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByLabelText('Join a Node')).toBeInTheDocument();
      expect(screen.getByPlaceholderText(/accord:\/\/host\/invite\/CODE/i)).toBeInTheDocument();
    });

    it('does not render when showCreateNodeModal is also true', () => {
      const ctx = createMockContext({ showJoinNodeModal: true, showCreateNodeModal: true });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.queryByLabelText('Join a Node')).not.toBeInTheDocument();
    });

    it('updates invite code on input change', () => {
      const setJoinInviteCode = vi.fn();
      const ctx = createMockContext({ showJoinNodeModal: true, setJoinInviteCode });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText(/accord:\/\/host\/invite\/CODE/i);
      fireEvent.change(input, { target: { value: 'ABC123' } });
      expect(setJoinInviteCode).toHaveBeenCalledWith('ABC123');
    });

    it('displays join error when present', () => {
      const ctx = createMockContext({ showJoinNodeModal: true, joinError: 'Invalid invite code' });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByText('Invalid invite code')).toBeInTheDocument();
    });

    it('calls handleJoinNode when Join button is clicked', () => {
      const handleJoinNode = vi.fn();
      const ctx = createMockContext({
        showJoinNodeModal: true,
        joinInviteCode: 'ABC123',
        handleJoinNode,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const joinButton = screen.getByRole('button', { name: /Join Node/i });
      fireEvent.click(joinButton);
      expect(handleJoinNode).toHaveBeenCalled();
    });

    it('calls handleJoinNode on Enter key press', () => {
      const handleJoinNode = vi.fn();
      const ctx = createMockContext({
        showJoinNodeModal: true,
        joinInviteCode: 'ABC123',
        handleJoinNode,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText(/accord:\/\/host\/invite\/CODE/i);
      fireEvent.keyDown(input, { key: 'Enter' });
      expect(handleJoinNode).toHaveBeenCalled();
    });

    it('disables Join button when invite code is empty', () => {
      const ctx = createMockContext({ showJoinNodeModal: true, joinInviteCode: '' });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const joinButton = screen.getByRole('button', { name: /Join Node/i });
      expect(joinButton).toBeDisabled();
    });

    it('opens create node modal when Create a New Node is clicked', () => {
      const setShowCreateNodeModal = vi.fn();
      const ctx = createMockContext({ showJoinNodeModal: true, setShowCreateNodeModal });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const createButton = screen.getByText('Create a New Node');
      fireEvent.click(createButton);
      expect(setShowCreateNodeModal).toHaveBeenCalledWith(true);
    });

    it('closes modal on Cancel button click', () => {
      const setShowJoinNodeModal = vi.fn();
      const setJoinInviteCode = vi.fn();
      const setJoinError = vi.fn();
      const ctx = createMockContext({
        showJoinNodeModal: true,
        setShowJoinNodeModal,
        setJoinInviteCode,
        setJoinError,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const cancelButton = screen.getByRole('button', { name: /Cancel/i });
      fireEvent.click(cancelButton);
      expect(setShowJoinNodeModal).toHaveBeenCalledWith(false);
      expect(setJoinInviteCode).toHaveBeenCalledWith('');
      expect(setJoinError).toHaveBeenCalledWith('');
    });

    it('closes modal on Escape key press', () => {
      const setShowJoinNodeModal = vi.fn();
      const ctx = createMockContext({ showJoinNodeModal: true, setShowJoinNodeModal });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const overlay = screen.getByRole('dialog');
      fireEvent.keyDown(overlay, { key: 'Escape' });
      expect(setShowJoinNodeModal).toHaveBeenCalledWith(false);
    });
  });

  describe('Create Node Modal', () => {
    it('renders create node modal when showCreateNodeModal is true', () => {
      const ctx = createMockContext({ showCreateNodeModal: true });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByLabelText('Create a Node')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('My Community')).toBeInTheDocument();
    });

    it('updates node name on input change', () => {
      const setNewNodeName = vi.fn();
      const ctx = createMockContext({ showCreateNodeModal: true, setNewNodeName });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText('My Community');
      fireEvent.change(input, { target: { value: 'My New Server' } });
      expect(setNewNodeName).toHaveBeenCalledWith('My New Server');
    });

    it('updates node description on input change', () => {
      const setNewNodeDescription = vi.fn();
      const ctx = createMockContext({ showCreateNodeModal: true, setNewNodeDescription });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText("What's this node about?");
      fireEvent.change(input, { target: { value: 'A gaming community' } });
      expect(setNewNodeDescription).toHaveBeenCalledWith('A gaming community');
    });

    it('calls handleCreateNode when Create button is clicked', () => {
      const handleCreateNode = vi.fn();
      const ctx = createMockContext({
        showCreateNodeModal: true,
        newNodeName: 'Test Server',
        handleCreateNode,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const createButton = screen.getByRole('button', { name: /Create Node/i });
      fireEvent.click(createButton);
      expect(handleCreateNode).toHaveBeenCalled();
    });

    it('calls handleCreateNode on Enter key press', () => {
      const handleCreateNode = vi.fn();
      const ctx = createMockContext({
        showCreateNodeModal: true,
        newNodeName: 'Test Server',
        handleCreateNode,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText('My Community');
      fireEvent.keyDown(input, { key: 'Enter' });
      expect(handleCreateNode).toHaveBeenCalled();
    });

    it('disables Create button when node name is empty', () => {
      const ctx = createMockContext({ showCreateNodeModal: true, newNodeName: '' });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const createButton = screen.getByRole('button', { name: /Create Node/i });
      expect(createButton).toBeDisabled();
    });

    it('switches to join modal when Join a Node is clicked', () => {
      const setShowCreateNodeModal = vi.fn();
      const ctx = createMockContext({ showCreateNodeModal: true, setShowCreateNodeModal });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const joinButton = screen.getByText('Join a Node');
      fireEvent.click(joinButton);
      expect(setShowCreateNodeModal).toHaveBeenCalledWith(false);
    });

    it('closes modal on Cancel button click', () => {
      const setShowCreateNodeModal = vi.fn();
      const setNewNodeName = vi.fn();
      const setNewNodeDescription = vi.fn();
      const ctx = createMockContext({
        showCreateNodeModal: true,
        setShowCreateNodeModal,
        setNewNodeName,
        setNewNodeDescription,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const cancelButton = screen.getByRole('button', { name: /Cancel/i });
      fireEvent.click(cancelButton);
      expect(setShowCreateNodeModal).toHaveBeenCalledWith(false);
      expect(setNewNodeName).toHaveBeenCalledWith('');
      expect(setNewNodeDescription).toHaveBeenCalledWith('');
    });

    it('closes modal on Escape key press', () => {
      const setShowCreateNodeModal = vi.fn();
      const ctx = createMockContext({ showCreateNodeModal: true, setShowCreateNodeModal });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const overlay = screen.getByRole('dialog');
      fireEvent.keyDown(overlay, { key: 'Escape' });
      expect(setShowCreateNodeModal).toHaveBeenCalledWith(false);
    });
  });

  describe('Invite Modal', () => {
    it('renders invite modal when showInviteModal is true', () => {
      const ctx = createMockContext({
        showInviteModal: true,
        generatedInvite: 'https://example.com/invite/ABC123',
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByLabelText('Invite People')).toBeInTheDocument();
      expect(screen.getByText('https://example.com/invite/ABC123')).toBeInTheDocument();
    });

    it('displays loading state while generating invite', () => {
      const ctx = createMockContext({ showInviteModal: true, inviteGenerating: true });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const loadingText = container.querySelector('.invite-link-loading');
      expect(loadingText).toHaveTextContent('Generating...');
    });

    it('copies invite to clipboard when Copy button is clicked', async () => {
      const copyToClipboard = vi.fn() as unknown as (_text: string) => Promise<boolean>;
      (copyToClipboard as any).mockResolvedValue(true);
      const setInviteCopied = vi.fn();
      const ctx = createMockContext({
        showInviteModal: true,
        generatedInvite: 'https://example.com/invite/ABC123',
        copyToClipboard,
        setInviteCopied,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const copyButton = screen.getByRole('button', { name: /Copy/i });
      fireEvent.click(copyButton);
      await waitFor(() => {
        expect(copyToClipboard).toHaveBeenCalledWith('https://example.com/invite/ABC123');
      });
    });

    it('updates invite expiry selection', () => {
      const setInviteExpiry = vi.fn();
      const ctx = createMockContext({ showInviteModal: true, setInviteExpiry });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const expirySelect = container.querySelector('.invite-options-row .form-select') as HTMLSelectElement;
      expect(expirySelect).toBeTruthy();
      fireEvent.change(expirySelect, { target: { value: '168' } });
      expect(setInviteExpiry).toHaveBeenCalledWith('168');
    });

    it('updates invite max uses selection', () => {
      const setInviteMaxUses = vi.fn();
      const ctx = createMockContext({ showInviteModal: true, setInviteMaxUses });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const selects = container.querySelectorAll('.invite-options-row .form-select');
      const maxUsesSelect = selects[1] as HTMLSelectElement;
      expect(maxUsesSelect).toBeTruthy();
      fireEvent.change(maxUsesSelect, { target: { value: '10' } });
      expect(setInviteMaxUses).toHaveBeenCalledWith('10');
    });

    it('generates new invite when button is clicked', () => {
      const handleGenerateInviteWithOptions = vi.fn();
      const ctx = createMockContext({
        showInviteModal: true,
        inviteExpiry: '24',
        inviteMaxUses: '5',
        handleGenerateInviteWithOptions,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const generateButton = screen.getByRole('button', { name: /Generate New Link/i });
      fireEvent.click(generateButton);
      expect(handleGenerateInviteWithOptions).toHaveBeenCalledWith('24', '5');
    });

    it('closes modal on close button click', () => {
      const setShowInviteModal = vi.fn();
      const setGeneratedInvite = vi.fn();
      const setInviteCopied = vi.fn();
      const ctx = createMockContext({
        showInviteModal: true,
        setShowInviteModal,
        setGeneratedInvite,
        setInviteCopied,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const closeButton = screen.getByRole('button', { name: /Close/i });
      fireEvent.click(closeButton);
      expect(setShowInviteModal).toHaveBeenCalledWith(false);
      expect(setGeneratedInvite).toHaveBeenCalledWith('');
      expect(setInviteCopied).toHaveBeenCalledWith(false);
    });

    it('closes modal on Escape key press', () => {
      const setShowInviteModal = vi.fn();
      const ctx = createMockContext({ showInviteModal: true, setShowInviteModal });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const overlay = screen.getByRole('dialog');
      fireEvent.keyDown(overlay, { key: 'Escape' });
      expect(setShowInviteModal).toHaveBeenCalledWith(false);
    });
  });

  describe('Delete Channel Confirmation', () => {
    it('renders delete confirmation when deleteChannelConfirm is set', () => {
      const ctx = createMockContext({
        deleteChannelConfirm: { id: 'channel-1', name: 'general' },
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByLabelText('Delete Channel')).toBeInTheDocument();
      expect(screen.getByText(/Are you sure you want to delete/i)).toBeInTheDocument();
      expect(screen.getByText('#general')).toBeInTheDocument();
    });

    it('calls handleDeleteChannelConfirmed when Delete button is clicked', () => {
      const handleDeleteChannelConfirmed = vi.fn();
      const ctx = createMockContext({
        deleteChannelConfirm: { id: 'channel-1', name: 'general' },
        handleDeleteChannelConfirmed,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const deleteButton = screen.getByRole('button', { name: /Delete Channel/i });
      fireEvent.click(deleteButton);
      expect(handleDeleteChannelConfirmed).toHaveBeenCalledWith('channel-1');
    });

    it('closes confirmation on Cancel button click', () => {
      const setDeleteChannelConfirm = vi.fn();
      const ctx = createMockContext({
        deleteChannelConfirm: { id: 'channel-1', name: 'general' },
        setDeleteChannelConfirm,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const cancelButton = screen.getByRole('button', { name: /Cancel/i });
      fireEvent.click(cancelButton);
      expect(setDeleteChannelConfirm).toHaveBeenCalledWith(null);
    });

    it('closes confirmation on Escape key press', () => {
      const setDeleteChannelConfirm = vi.fn();
      const ctx = createMockContext({
        deleteChannelConfirm: { id: 'channel-1', name: 'general' },
        setDeleteChannelConfirm,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const dialog = screen.getByRole('alertdialog');
      fireEvent.keyDown(dialog, { key: 'Escape' });
      expect(setDeleteChannelConfirm).toHaveBeenCalledWith(null);
    });
  });

  describe('Template Import Modal', () => {
    it('renders template import modal when showTemplateImport is true', () => {
      const ctx = createMockContext({
        showTemplateImport: true,
        selectedNodeId: 'node-1',
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByLabelText('Import Discord Template')).toBeInTheDocument();
      expect(screen.getByPlaceholderText(/discord.new/i)).toBeInTheDocument();
    });

    it('updates template input on change', () => {
      const setTemplateInput = vi.fn();
      const ctx = createMockContext({
        showTemplateImport: true,
        selectedNodeId: 'node-1',
        setTemplateInput,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText(/discord.new/i);
      fireEvent.change(input, { target: { value: 'discord.new/ABC123' } });
      expect(setTemplateInput).toHaveBeenCalledWith('discord.new/ABC123');
    });

    it('displays template error when present', () => {
      const ctx = createMockContext({
        showTemplateImport: true,
        selectedNodeId: 'node-1',
        templateError: 'Invalid template code',
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByText('Invalid template code')).toBeInTheDocument();
    });

    it('imports template when Import button is clicked', async () => {
      const { api } = await import('../api');
      const setTemplateResult = vi.fn();
      const setTemplateError = vi.fn();
      const setTemplateImporting = vi.fn();
      vi.mocked(api.importDiscordTemplate).mockResolvedValue({
        roles_created: 3,
        channels_created: 5,
        categories_created: 2,
      });
      const ctx = createMockContext({
        showTemplateImport: true,
        selectedNodeId: 'node-1',
        templateInput: 'ABC123',
        setTemplateResult,
        setTemplateError,
        setTemplateImporting,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const importButton = screen.getByRole('button', { name: /Import/i });
      await act(async () => {
        fireEvent.click(importButton);
        // Wait for async operations
        await new Promise(resolve => setTimeout(resolve, 0));
      });
      await waitFor(() => {
        expect(setTemplateImporting).toHaveBeenCalledWith(true);
      });
    });

    it('displays import results after successful import', () => {
      const ctx = createMockContext({
        showTemplateImport: true,
        selectedNodeId: 'node-1',
        templateResult: { roles_created: 3, channels_created: 5, categories_created: 2 },
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByText('✅ Import complete!')).toBeInTheDocument();
      expect(screen.getByText(/Roles created/i)).toBeInTheDocument();
      expect(screen.getByText('3')).toBeInTheDocument();
    });

    it('closes modal on Cancel button click', () => {
      const setShowTemplateImport = vi.fn();
      const ctx = createMockContext({
        showTemplateImport: true,
        selectedNodeId: 'node-1',
        setShowTemplateImport,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const cancelButton = screen.getByRole('button', { name: /Cancel/i });
      fireEvent.click(cancelButton);
      expect(setShowTemplateImport).toHaveBeenCalledWith(false);
    });

    it('closes modal on Escape key press', () => {
      const setShowTemplateImport = vi.fn();
      const ctx = createMockContext({
        showTemplateImport: true,
        selectedNodeId: 'node-1',
        setShowTemplateImport,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const overlay = screen.getByRole('dialog');
      fireEvent.keyDown(overlay, { key: 'Escape' });
      expect(setShowTemplateImport).toHaveBeenCalledWith(false);
    });
  });

  describe('DM Create Modal', () => {
    it('renders DM create modal when showDmChannelCreate is true', () => {
      const mockMember: NodeMember & { user: User } = {
        node_id: 'node-1',
        user_id: 'user-2',
        public_key_hash: 'hash-2',
        role: 'member',
        joined_at: Date.now(),
        user: mockUser('user-2'),
      };
      const ctx = createMockContext({
        showDmChannelCreate: true,
        members: [mockMember],
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByLabelText('New Direct Message')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Search members...')).toBeInTheDocument();
    });

    it('filters members based on search input', () => {
      const mockMembers: (NodeMember & { user: User })[] = [
        {
          node_id: 'node-1',
          user_id: 'user-2',
          public_key_hash: 'hash-2',
          role: 'member',
          joined_at: Date.now(),
          user: { ...mockUser('user-2'), display_name: 'Alice' },
        },
        {
          node_id: 'node-1',
          user_id: 'user-3',
          public_key_hash: 'hash-3',
          role: 'member',
          joined_at: Date.now(),
          user: { ...mockUser('user-3'), display_name: 'Bob' },
        },
      ];
      const ctx = createMockContext({
        showDmChannelCreate: true,
        members: mockMembers,
        displayName: vi.fn((user: User | undefined) => user?.display_name || user?.id || 'Unknown'),
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const searchInput = screen.getByPlaceholderText('Search members...');
      fireEvent.change(searchInput, { target: { value: 'Alice' } });
      // Check for Alice in the DM list items
      const dmItems = container.querySelectorAll('.dm-create-user-name');
      const names = Array.from(dmItems).map(item => item.textContent);
      expect(names).toContain('Alice');
      expect(names).not.toContain('Bob');
    });

    it('opens DM when member is clicked', () => {
      const openDmWithUser = vi.fn();
      const setShowDmChannelCreate = vi.fn();
      const mockMember: NodeMember & { user: User } = {
        node_id: 'node-1',
        user_id: 'user-2',
        public_key_hash: 'hash-2',
        role: 'member',
        joined_at: Date.now(),
        user: mockUser('user-2'),
      };
      const ctx = createMockContext({
        showDmChannelCreate: true,
        members: [mockMember],
        openDmWithUser,
        setShowDmChannelCreate,
        displayName: vi.fn(() => 'User user-2'),
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const memberItem = container.querySelector('.dm-create-item');
      expect(memberItem).toBeTruthy();
      fireEvent.click(memberItem!);
      expect(openDmWithUser).toHaveBeenCalledWith(mockMember.user);
      expect(setShowDmChannelCreate).toHaveBeenCalledWith(false);
    });

    it('closes modal when close button is clicked', () => {
      const setShowDmChannelCreate = vi.fn();
      const ctx = createMockContext({
        showDmChannelCreate: true,
        setShowDmChannelCreate,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const closeButton = screen.getByRole('button', { name: /Close/i });
      fireEvent.click(closeButton);
      expect(setShowDmChannelCreate).toHaveBeenCalledWith(false);
    });

    it('closes modal on Escape key press', () => {
      const setShowDmChannelCreate = vi.fn();
      const ctx = createMockContext({
        showDmChannelCreate: true,
        setShowDmChannelCreate,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const overlay = screen.getByRole('dialog');
      fireEvent.keyDown(overlay, { key: 'Escape' });
      expect(setShowDmChannelCreate).toHaveBeenCalledWith(false);
    });
  });

  describe('Display Name Prompt', () => {
    it('renders display name prompt when showDisplayNamePrompt is true', () => {
      const ctx = createMockContext({ showDisplayNamePrompt: true });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByLabelText('Set Your Display Name')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Enter a display name...')).toBeInTheDocument();
    });

    it('updates display name input on change', () => {
      const setDisplayNameInput = vi.fn();
      const ctx = createMockContext({ showDisplayNamePrompt: true, setDisplayNameInput });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText('Enter a display name...');
      fireEvent.change(input, { target: { value: 'John Doe' } });
      expect(setDisplayNameInput).toHaveBeenCalledWith('John Doe');
    });

    it('calls handleSaveDisplayName when Save button is clicked', () => {
      const handleSaveDisplayName = vi.fn();
      const ctx = createMockContext({
        showDisplayNamePrompt: true,
        displayNameInput: 'John Doe',
        handleSaveDisplayName,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const saveButton = screen.getByRole('button', { name: /Save/i });
      fireEvent.click(saveButton);
      expect(handleSaveDisplayName).toHaveBeenCalled();
    });

    it('calls handleSaveDisplayName on Enter key press', () => {
      const handleSaveDisplayName = vi.fn();
      const ctx = createMockContext({
        showDisplayNamePrompt: true,
        displayNameInput: 'John Doe',
        handleSaveDisplayName,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const input = screen.getByPlaceholderText('Enter a display name...');
      fireEvent.keyDown(input, { key: 'Enter' });
      expect(handleSaveDisplayName).toHaveBeenCalled();
    });

    it('disables Save button when input is empty', () => {
      const ctx = createMockContext({
        showDisplayNamePrompt: true,
        displayNameInput: '',
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const saveButton = screen.getByRole('button', { name: /Save/i });
      expect(saveButton).toBeDisabled();
    });

    it('closes modal on Skip button click', () => {
      const setShowDisplayNamePrompt = vi.fn();
      const ctx = createMockContext({
        showDisplayNamePrompt: true,
        setShowDisplayNamePrompt,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const skipButton = screen.getByRole('button', { name: /Skip/i });
      fireEvent.click(skipButton);
      expect(setShowDisplayNamePrompt).toHaveBeenCalledWith(false);
    });

    it('closes modal on Escape key press', () => {
      const setShowDisplayNamePrompt = vi.fn();
      const ctx = createMockContext({
        showDisplayNamePrompt: true,
        setShowDisplayNamePrompt,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const overlay = screen.getByRole('dialog');
      fireEvent.keyDown(overlay, { key: 'Escape' });
      expect(setShowDisplayNamePrompt).toHaveBeenCalledWith(false);
    });
  });

  describe('Block Confirmation', () => {
    it('renders block confirmation when showBlockConfirm is set', () => {
      const ctx = createMockContext({
        showBlockConfirm: { userId: 'user-2', displayName: 'Alice' },
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByLabelText('Block User')).toBeInTheDocument();
      expect(screen.getByText('Alice')).toBeInTheDocument();
      expect(screen.getByText(/Are you sure you want to block/i)).toBeInTheDocument();
    });

    it('calls handleBlockUser when Block button is clicked', () => {
      const handleBlockUser = vi.fn();
      const ctx = createMockContext({
        showBlockConfirm: { userId: 'user-2', displayName: 'Alice' },
        handleBlockUser,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const blockButton = screen.getByRole('button', { name: /Block/i });
      fireEvent.click(blockButton);
      expect(handleBlockUser).toHaveBeenCalledWith('user-2');
    });

    it('closes confirmation on Cancel button click', () => {
      const setShowBlockConfirm = vi.fn();
      const ctx = createMockContext({
        showBlockConfirm: { userId: 'user-2', displayName: 'Alice' },
        setShowBlockConfirm,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const cancelButton = screen.getByRole('button', { name: /Cancel/i });
      fireEvent.click(cancelButton);
      expect(setShowBlockConfirm).toHaveBeenCalledWith(null);
    });

    it('closes confirmation on overlay click', () => {
      const setShowBlockConfirm = vi.fn();
      const ctx = createMockContext({
        showBlockConfirm: { userId: 'user-2', displayName: 'Alice' },
        setShowBlockConfirm,
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const overlay = container.querySelector('.modal-overlay');
      fireEvent.click(overlay!);
      expect(setShowBlockConfirm).toHaveBeenCalledWith(null);
    });

    it('closes confirmation on Escape key press', () => {
      const setShowBlockConfirm = vi.fn();
      const ctx = createMockContext({
        showBlockConfirm: { userId: 'user-2', displayName: 'Alice' },
        setShowBlockConfirm,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const dialog = screen.getByRole('alertdialog');
      fireEvent.keyDown(dialog, { key: 'Escape' });
      expect(setShowBlockConfirm).toHaveBeenCalledWith(null);
    });
  });

  describe('Connection Info Modal', () => {
    it('renders connection info when showConnectionInfo is true', () => {
      const ctx = createMockContext({
        showConnectionInfo: true,
        serverHelloVersion: '1.2.3',
        serverBuildHash: 'abc123def456',
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByLabelText('Connection Info')).toBeInTheDocument();
      expect(screen.getByText('Connected')).toBeInTheDocument();
      expect(screen.getByText('1.2.3')).toBeInTheDocument();
    });

    it('displays disconnected status when not connected', () => {
      const ctx = createMockContext({
        showConnectionInfo: true,
        appState: { isConnected: false } as any,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByText('Disconnected')).toBeInTheDocument();
    });

    it('displays relay address', () => {
      const ctx = createMockContext({ showConnectionInfo: true });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByText('https://relay.example.com')).toBeInTheDocument();
    });

    it('closes modal on close button click', () => {
      const setShowConnectionInfo = vi.fn();
      const ctx = createMockContext({
        showConnectionInfo: true,
        setShowConnectionInfo,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const closeButton = screen.getByRole('button', { name: /×/i });
      fireEvent.click(closeButton);
      expect(setShowConnectionInfo).toHaveBeenCalledWith(false);
    });

    it('closes modal on Escape key press', () => {
      const setShowConnectionInfo = vi.fn();
      const ctx = createMockContext({
        showConnectionInfo: true,
        setShowConnectionInfo,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const dialog = screen.getByRole('dialog');
      fireEvent.keyDown(dialog, { key: 'Escape' });
      expect(setShowConnectionInfo).toHaveBeenCalledWith(false);
    });
  });

  describe('Keyboard Shortcuts Help', () => {
    it('renders shortcuts help when showShortcutsHelp is true', () => {
      const ctx = createMockContext({ showShortcutsHelp: true });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByLabelText('Keyboard Shortcuts')).toBeInTheDocument();
      expect(screen.getByText('Navigation')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+K')).toBeInTheDocument();
    });

    it('closes modal on Close button click', () => {
      const setShowShortcutsHelp = vi.fn();
      const ctx = createMockContext({
        showShortcutsHelp: true,
        setShowShortcutsHelp,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const closeButton = screen.getByRole('button', { name: /Close/i });
      fireEvent.click(closeButton);
      expect(setShowShortcutsHelp).toHaveBeenCalledWith(false);
    });

    it('closes modal on overlay click', () => {
      const setShowShortcutsHelp = vi.fn();
      const ctx = createMockContext({
        showShortcutsHelp: true,
        setShowShortcutsHelp,
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const overlay = container.querySelector('.modal-overlay');
      fireEvent.click(overlay!);
      expect(setShowShortcutsHelp).toHaveBeenCalledWith(false);
    });

    it('closes modal on Escape key press', () => {
      const setShowShortcutsHelp = vi.fn();
      const ctx = createMockContext({
        showShortcutsHelp: true,
        setShowShortcutsHelp,
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const dialog = screen.getByRole('dialog');
      fireEvent.keyDown(dialog, { key: 'Escape' });
      expect(setShowShortcutsHelp).toHaveBeenCalledWith(false);
    });
  });

  describe('Role Assignment Popup', () => {
    it('renders role popup when showRolePopup is set', () => {
      const mockRole: Role = {
        id: 'role-1',
        node_id: 'node-1',
        name: 'Moderator',
        color: '#ff0000',
        position: 1,
        permissions: 0,
        hoist: false,
        mentionable: false,
        created_at: Date.now(),
      };
      const ctx = createMockContext({
        showRolePopup: { userId: 'user-2', x: 100, y: 200 },
        nodeRoles: [mockRole],
        memberRolesMap: {},
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByText('ASSIGN ROLES')).toBeInTheDocument();
      expect(screen.getByText('Moderator')).toBeInTheDocument();
    });

    it('displays empty state when no roles are available', () => {
      const ctx = createMockContext({
        showRolePopup: { userId: 'user-2', x: 100, y: 200 },
        nodeRoles: [],
      });
      render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      expect(screen.getByText('No roles available')).toBeInTheDocument();
    });

    it('toggles member role when checkbox is clicked', () => {
      const toggleMemberRole = vi.fn();
      const mockRole: Role = {
        id: 'role-1',
        node_id: 'node-1',
        name: 'Moderator',
        color: '#ff0000',
        position: 1,
        permissions: 0,
        hoist: false,
        mentionable: false,
        created_at: Date.now(),
      };
      const ctx = createMockContext({
        showRolePopup: { userId: 'user-2', x: 100, y: 200 },
        nodeRoles: [mockRole],
        memberRolesMap: { 'user-2': [] },
        toggleMemberRole,
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const label = container.querySelector('.role-popup-label');
      expect(label).toBeTruthy();
      const checkbox = label?.querySelector('input[type="checkbox"]') as HTMLInputElement;
      expect(checkbox).toBeTruthy();
      expect(checkbox.checked).toBe(false);
      fireEvent.click(checkbox);
      expect(toggleMemberRole).toHaveBeenCalledWith('user-2', 'role-1', false);
    });

    it('closes popup on overlay click', () => {
      const setShowRolePopup = vi.fn();
      const ctx = createMockContext({
        showRolePopup: { userId: 'user-2', x: 100, y: 200 },
        nodeRoles: [],
        setShowRolePopup,
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const overlay = container.querySelector('.role-popup-overlay');
      fireEvent.click(overlay!);
      expect(setShowRolePopup).toHaveBeenCalledWith(null);
    });

    it('closes popup on Escape key press', () => {
      const setShowRolePopup = vi.fn();
      const ctx = createMockContext({
        showRolePopup: { userId: 'user-2', x: 100, y: 200 },
        nodeRoles: [],
        setShowRolePopup,
      });
      const { container } = render(
        <AppContext.Provider value={ctx}>
          <AppModals />
        </AppContext.Provider>
      );
      const overlay = container.querySelector('.role-popup-overlay');
      fireEvent.keyDown(overlay!, { key: 'Escape' });
      expect(setShowRolePopup).toHaveBeenCalledWith(null);
    });
  });
});
