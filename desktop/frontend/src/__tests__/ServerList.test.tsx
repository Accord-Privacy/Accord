import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ServerList } from '../components/ServerList';
import { AppContext } from '../components/AppContext';
import type { AppContextType } from '../components/AppContext';
import type { Node } from '../types';
import * as notificationsModule from '../notifications';

vi.mock('../api', () => ({
  api: {
    getNodeIconUrl: vi.fn((nodeId: string) => `https://example.com/icon/${nodeId}`),
  },
}));

vi.mock('../notifications', () => ({
  notificationManager: {
    getNodeUnreads: vi.fn(() => ({ totalUnreads: 0, totalMentions: 0 })),
    markAllNodeChannelsAsRead: vi.fn(),
  },
  muteManager: {
    isNodeMuted: vi.fn(() => false),
    muteNode: vi.fn(),
    unmuteNode: vi.fn(),
  },
  MUTE_DURATIONS: [
    { label: '15 minutes', minutes: 15 },
    { label: '1 hour', minutes: 60 },
    { label: '8 hours', minutes: 480 },
  ],
}));

const mockNode = (id: string, name: string, iconHash?: string): Node => ({
  id,
  name,
  icon_hash: iconHash,
  created_at: Date.now(),
  owner_id: 'owner-1',
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
  handleNodeSelect: vi.fn(),
  setShowJoinNodeModal: vi.fn(),
  forceUpdate: 0,
  setForceUpdate: vi.fn(),
  ...overrides,
} as AppContextType);

describe('ServerList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders home server icon', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    expect(screen.getByRole('button', { name: 'Home' })).toBeInTheDocument();
  });

  it('renders separator after home icon', () => {
    const ctx = createMockContext();
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    expect(container.querySelector('.server-list-separator')).toBeInTheDocument();
  });

  it('renders server icons for all nodes', () => {
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1'), mockNode('n2', 'Server 2'), mockNode('n3', 'Server 3')],
      servers: ['Server 1', 'Server 2', 'Server 3'],
    } as any);
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    expect(screen.getByRole('button', { name: 'Server 1' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Server 2' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Server 3' })).toBeInTheDocument();
  });

  it('applies active class to active server', () => {
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1'), mockNode('n2', 'Server 2')],
      servers: ['Server 1', 'Server 2'],
      activeServer: 1,
    } as any);
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const icons = container.querySelectorAll('.server-icon');
    expect(icons[2]).toHaveClass('active'); // index 2 because home is index 0, separator is 1
  });

  it('displays server initials when no icon', () => {
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Alpha Server')],
      servers: ['Alpha Server'],
    } as any);
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const button = screen.getByRole('button', { name: 'Alpha Server' });
    expect(button.textContent).toContain('A');
  });

  it('displays server icon image when icon_hash is present', () => {
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1', 'icon-hash-123')],
      servers: ['Server 1'],
    } as any);
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const img = container.querySelector('img[alt="S"]');
    expect(img).toBeInTheDocument();
    expect(img?.getAttribute('src')).toContain('icon-hash-123');
  });

  it('calls handleNodeSelect when server is clicked', () => {
    const handleNodeSelect = vi.fn();
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
      handleNodeSelect,
    } as any);
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const button = screen.getByRole('button', { name: 'Server 1' });
    fireEvent.click(button);
    expect(handleNodeSelect).toHaveBeenCalledWith('n1', 0);
  });

  it('displays unread dot when server has unreads', () => {
    (notificationsModule.notificationManager.getNodeUnreads as any).mockReturnValue({ totalUnreads: 5, totalMentions: 0 });

    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
      activeServer: -1,
    } as any);
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    expect(container.querySelector('.server-notification.dot')).toBeInTheDocument();
  });

  it('displays mention badge with count', () => {
    (notificationsModule.notificationManager.getNodeUnreads as any).mockReturnValue({ totalUnreads: 5, totalMentions: 3 });

    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
    } as any);
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const badge = container.querySelector('.server-notification.mention');
    expect(badge).toBeInTheDocument();
    expect(badge?.textContent).toBe('3');
  });

  it('displays 9+ for mention counts over 9', () => {
    (notificationsModule.notificationManager.getNodeUnreads as any).mockReturnValue({ totalUnreads: 15, totalMentions: 12 });

    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
    } as any);
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const badge = container.querySelector('.server-notification.mention');
    expect(badge?.textContent).toBe('9+');
  });

  it('does not show unread indicator for active server', () => {
    (notificationsModule.notificationManager.getNodeUnreads as any).mockReturnValue({ totalUnreads: 5, totalMentions: 0 });

    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
      activeServer: 0,
    } as any);
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const serverIcon = container.querySelectorAll('.server-icon')[2]; // Skip home and separator
    expect(serverIcon).not.toHaveClass('has-unread');
  });

  it('renders add server button', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    expect(screen.getByRole('button', { name: 'Join or Create Node' })).toBeInTheDocument();
  });

  it('opens join node modal when add button is clicked', () => {
    const setShowJoinNodeModal = vi.fn();
    const ctx = createMockContext({ setShowJoinNodeModal });
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const addButton = screen.getByRole('button', { name: 'Join or Create Node' });
    fireEvent.click(addButton);
    expect(setShowJoinNodeModal).toHaveBeenCalledWith(true);
  });

  it('opens context menu on right-click', () => {
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
    } as any);
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const serverButton = screen.getByRole('button', { name: 'Server 1' });
    fireEvent.contextMenu(serverButton);
    expect(container.querySelector('.context-menu')).toBeInTheDocument();
  });

  it('shows Mark All as Read in context menu', () => {
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
    } as any);
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const serverButton = screen.getByRole('button', { name: 'Server 1' });
    fireEvent.contextMenu(serverButton);
    expect(screen.getByText('Mark All as Read')).toBeInTheDocument();
  });

  it('calls markAllNodeChannelsAsRead when clicked', () => {
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
    } as any);
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const serverButton = screen.getByRole('button', { name: 'Server 1' });
    fireEvent.contextMenu(serverButton);
    const markReadButton = screen.getByText('Mark All as Read');
    fireEvent.click(markReadButton);
    expect(notificationsModule.notificationManager.markAllNodeChannelsAsRead).toHaveBeenCalledWith('n1');
  });

  it('shows Mute Server menu item when not muted', () => {
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
    } as any);
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const serverButton = screen.getByRole('button', { name: 'Server 1' });
    fireEvent.contextMenu(serverButton);
    expect(screen.getByText('Mute Server')).toBeInTheDocument();
  });

  it('shows Unmute Server when muted', () => {
    (notificationsModule.muteManager.isNodeMuted as any).mockReturnValue(true);

    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
    } as any);
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const serverButton = screen.getByRole('button', { name: 'Server 1' });
    fireEvent.contextMenu(serverButton);
    expect(screen.getByText('Unmute Server')).toBeInTheDocument();
  });

  it('displays mute duration submenu on hover', () => {
    (notificationsModule.muteManager.isNodeMuted as any).mockReturnValue(false);

    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
    } as any);
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const serverButton = screen.getByRole('button', { name: 'Server 1' });
    fireEvent.contextMenu(serverButton);
    const muteItem = screen.getByText('Mute Server');
    fireEvent.mouseEnter(muteItem);
    expect(screen.getByText('15 minutes')).toBeInTheDocument();
    expect(screen.getByText('1 hour')).toBeInTheDocument();
  });

  it('closes context menu on Escape key', () => {
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
    } as any);
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const serverButton = screen.getByRole('button', { name: 'Server 1' });
    fireEvent.contextMenu(serverButton);
    expect(container.querySelector('.context-menu')).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(container.querySelector('.context-menu')).not.toBeInTheDocument();
  });

  it('closes context menu when clicking outside', () => {
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
    } as any);
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const serverButton = screen.getByRole('button', { name: 'Server 1' });
    fireEvent.contextMenu(serverButton);
    expect(container.querySelector('.context-menu')).toBeInTheDocument();
    fireEvent.mouseDown(document.body);
    expect(container.querySelector('.context-menu')).not.toBeInTheDocument();
  });

  it('supports keyboard navigation with Enter key', () => {
    const handleNodeSelect = vi.fn();
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
      handleNodeSelect,
    } as any);
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const serverButton = screen.getByRole('button', { name: 'Server 1' });
    fireEvent.keyDown(serverButton, { key: 'Enter' });
    expect(handleNodeSelect).toHaveBeenCalledWith('n1', 0);
  });

  it('supports keyboard navigation with Space key', () => {
    const handleNodeSelect = vi.fn();
    const ctx = createMockContext({
      nodes: [mockNode('n1', 'Server 1')],
      servers: ['Server 1'],
      handleNodeSelect,
    } as any);
    render(
      <AppContext.Provider value={ctx}>
        <ServerList />
      </AppContext.Provider>
    );
    const serverButton = screen.getByRole('button', { name: 'Server 1' });
    fireEvent.keyDown(serverButton, { key: ' ' });
    expect(handleNodeSelect).toHaveBeenCalledWith('n1', 0);
  });
});
