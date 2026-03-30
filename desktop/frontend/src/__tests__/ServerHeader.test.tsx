import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ServerHeader } from '../components/ServerHeader';
import { AppContext } from '../components/AppContext';
import type { AppContextType } from '../components/AppContext';
import type { Node } from '../types';

// Mock the api module
vi.mock('../api', () => ({
  api: {
    leaveNode: vi.fn(),
  },
}));

// Get the mock after the module is mocked
const { api } = await import('../api');
const mockLeaveNode = vi.mocked(api.leaveNode);

const mockNode: Node = {
  id: 'node-1',
  name: 'Test Server',
  owner_id: 'owner-1',
  created_at: Date.now(),
};

const createMockContext = (overrides: Partial<AppContextType> = {}): AppContextType => ({
  nodes: [],
  channels: [],
  members: [],
  selectedNodeId: 'node-1',
  selectedChannelId: null,
  activeServer: 0,
  activeChannel: '',
  ws: null,
  connectionInfo: { status: 'connected' } as any,
  lastConnectionError: '',
  setLastConnectionError: vi.fn(),
  servers: ['Test Server'],
  hasPermission: vi.fn(() => false),
  handleGenerateInvite: vi.fn(),
  setShowNodeSettings: vi.fn(),
  setNewChannelCategoryId: vi.fn(),
  setShowCreateChannelForm: vi.fn(),
  setNewChannelType: vi.fn(),
  setShowNotificationSettings: vi.fn(),
  appState: { token: 'test-token', isConnected: true } as any,
  loadNodes: vi.fn(),
  serverAvailable: true,
  ...overrides,
} as any);

describe('ServerHeader', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders server name from servers array', () => {
    const ctx = createMockContext({ servers: ['My Server'] });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    expect(screen.getByText('My Server')).toBeInTheDocument();
  });

  it('displays dropdown arrow when node is selected', () => {
    const ctx = createMockContext();
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    const arrow = container.querySelector('.server-header-arrow');
    expect(arrow).toBeInTheDocument();
    expect(arrow?.textContent).toBe('▼');
  });

  it('does not display dropdown arrow when no node is selected', () => {
    const ctx = createMockContext({ selectedNodeId: null });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    const arrow = container.querySelector('.server-header-arrow');
    expect(arrow).not.toBeInTheDocument();
  });

  it('displays verified badge when current node exists', () => {
    const ctx = createMockContext({ nodes: [mockNode], selectedNodeId: 'node-1' });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    const badge = screen.getByTitle('Verified');
    expect(badge.textContent).toBe('✓');
  });

  it('does not display verified badge when no node is selected', () => {
    const ctx = createMockContext({ selectedNodeId: null });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    expect(screen.queryByTitle('Verified')).not.toBeInTheDocument();
  });

  it('displays connection status when reconnecting', () => {
    const ctx = createMockContext({
      connectionInfo: { status: 'reconnecting' } as any,
      nodes: [mockNode],
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    expect(screen.getByText('Reconnecting...')).toBeInTheDocument();
  });

  it('displays offline status when disconnected', () => {
    const ctx = createMockContext({
      connectionInfo: { status: 'disconnected' } as any,
      appState: { isConnected: false } as any,
      nodes: [mockNode],
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    expect(screen.getByText('Offline')).toBeInTheDocument();
  });

  it('opens dropdown when header button is clicked', () => {
    const ctx = createMockContext();
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    const button = screen.getByRole('button', { expanded: false });
    fireEvent.click(button);
    expect(container.querySelector('.server-header-dropdown')).toBeInTheDocument();
  });

  it('does not open dropdown when no node is selected', () => {
    const ctx = createMockContext({ selectedNodeId: null });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    const button = screen.getByRole('button');
    fireEvent.click(button);
    expect(container.querySelector('.server-header-dropdown')).not.toBeInTheDocument();
  });

  it('displays Invite People option when user has permission', () => {
    const ctx = createMockContext({
      hasPermission: vi.fn((_nodeId, perm) => perm === 'ManageInvites'),
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    expect(screen.getByText('Invite People')).toBeInTheDocument();
  });

  it('displays Node Settings option when user has permission', () => {
    const ctx = createMockContext({
      hasPermission: vi.fn((_nodeId, perm) => perm === 'ManageNode'),
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    expect(screen.getByText('Node Settings')).toBeInTheDocument();
  });

  it('displays Create Channel option when user has permission', () => {
    const ctx = createMockContext({
      hasPermission: vi.fn((_nodeId, perm) => perm === 'CreateChannel'),
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    expect(screen.getByText('Create Channel')).toBeInTheDocument();
  });

  it('displays Create Category option when user has manage permission', () => {
    const ctx = createMockContext({
      hasPermission: vi.fn((_nodeId, perm) => perm === 'ManageNode'),
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    expect(screen.getByText('Create Category')).toBeInTheDocument();
  });

  it('displays Notification Settings option', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    expect(screen.getByText('Notification Settings')).toBeInTheDocument();
  });

  it('displays Leave Node option', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    expect(screen.getByText('Leave Node')).toBeInTheDocument();
  });

  it('calls handleGenerateInvite when Invite People is clicked', () => {
    const handleGenerateInvite = vi.fn();
    const ctx = createMockContext({
      hasPermission: vi.fn(() => true),
      handleGenerateInvite,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    fireEvent.click(screen.getByText('Invite People'));
    expect(handleGenerateInvite).toHaveBeenCalled();
  });

  it('calls setShowNodeSettings when Node Settings is clicked', () => {
    const setShowNodeSettings = vi.fn();
    const ctx = createMockContext({
      hasPermission: vi.fn(() => true),
      setShowNodeSettings,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    fireEvent.click(screen.getByText('Node Settings'));
    expect(setShowNodeSettings).toHaveBeenCalledWith(true);
  });

  it('calls setShowCreateChannelForm when Create Channel is clicked', () => {
    const setShowCreateChannelForm = vi.fn();
    const setNewChannelCategoryId = vi.fn();
    const ctx = createMockContext({
      hasPermission: vi.fn(() => true),
      setShowCreateChannelForm,
      setNewChannelCategoryId,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    fireEvent.click(screen.getByText('Create Channel'));
    expect(setNewChannelCategoryId).toHaveBeenCalledWith('');
    expect(setShowCreateChannelForm).toHaveBeenCalledWith(true);
  });

  it('sets channel type to category when Create Category is clicked', () => {
    const setNewChannelType = vi.fn();
    const ctx = createMockContext({
      hasPermission: vi.fn(() => true),
      setNewChannelType,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    fireEvent.click(screen.getByText('Create Category'));
    expect(setNewChannelType).toHaveBeenCalledWith('category');
  });

  it('calls setShowNotificationSettings when Notification Settings is clicked', () => {
    const setShowNotificationSettings = vi.fn();
    const ctx = createMockContext({ setShowNotificationSettings });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    fireEvent.click(screen.getByText('Notification Settings'));
    expect(setShowNotificationSettings).toHaveBeenCalledWith(true);
  });

  it('shows confirmation dialog when Leave Node is clicked', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    fireEvent.click(screen.getByText('Leave Node'));
    expect(screen.getByText('Are you sure?')).toBeInTheDocument();
    expect(screen.getByText('Leave')).toBeInTheDocument();
    expect(screen.getByText('Cancel')).toBeInTheDocument();
  });

  it('cancels leave confirmation when Cancel is clicked', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    fireEvent.click(screen.getByText('Leave Node'));
    fireEvent.click(screen.getByText('Cancel'));
    expect(screen.queryByText('Are you sure?')).not.toBeInTheDocument();
    expect(screen.getByText('Leave Node')).toBeInTheDocument();
  });

  it('calls leaveNode API when Leave is confirmed', async () => {
    mockLeaveNode.mockResolvedValue({ status: 'ok', node_id: 'node-1' });
    const loadNodes = vi.fn();
    const ctx = createMockContext({
      selectedNodeId: 'node-1',
      appState: { token: 'test-token' } as any,
      loadNodes,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    fireEvent.click(screen.getByText('Leave Node'));
    fireEvent.click(screen.getByText('Leave'));

    await waitFor(() => {
      expect(mockLeaveNode).toHaveBeenCalledWith('node-1', 'test-token');
    });
    expect(loadNodes).toHaveBeenCalled();
  });

  it('closes dropdown when clicking outside', () => {
    const ctx = createMockContext();
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    expect(container.querySelector('.server-header-dropdown')).toBeInTheDocument();

    fireEvent.mouseDown(document.body);
    expect(container.querySelector('.server-header-dropdown')).not.toBeInTheDocument();
  });

  it('closes dropdown on Escape key', () => {
    const ctx = createMockContext();
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    expect(container.querySelector('.server-header-dropdown')).toBeInTheDocument();

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(container.querySelector('.server-header-dropdown')).not.toBeInTheDocument();
  });

  it('toggles arrow icon when dropdown opens', () => {
    const ctx = createMockContext();
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    const arrow = container.querySelector('.server-header-arrow');
    expect(arrow?.textContent).toBe('▼');

    fireEvent.click(screen.getByRole('button', { expanded: false }));
    expect(arrow?.textContent).toBe('✕');
  });

  it('closes dropdown when menu item is clicked', () => {
    const ctx = createMockContext();
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    expect(container.querySelector('.server-header-dropdown')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Notification Settings'));
    expect(container.querySelector('.server-header-dropdown')).not.toBeInTheDocument();
  });

  it('applies open class to header button when dropdown is open', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    const button = screen.getByRole('button', { expanded: false });
    expect(button).not.toHaveClass('open');

    fireEvent.click(button);
    expect(button).toHaveClass('open');
  });

  it('displays dividers between menu sections', () => {
    const ctx = createMockContext({
      hasPermission: vi.fn(() => true),
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    const dividers = container.querySelectorAll('.server-dropdown-divider');
    expect(dividers.length).toBeGreaterThan(0);
  });

  it('handles leave node API error gracefully', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
    mockLeaveNode.mockRejectedValue(new Error('Network error'));
    const ctx = createMockContext({
      selectedNodeId: 'node-1',
      appState: { token: 'test-token' } as any,
    });
    render(
      <AppContext.Provider value={ctx}>
        <ServerHeader />
      </AppContext.Provider>
    );
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    fireEvent.click(screen.getByText('Leave Node'));
    fireEvent.click(screen.getByText('Leave'));

    await waitFor(() => {
      expect(consoleError).toHaveBeenCalledWith('Failed to leave node:', expect.any(Error));
    });

    consoleError.mockRestore();
  });
});
