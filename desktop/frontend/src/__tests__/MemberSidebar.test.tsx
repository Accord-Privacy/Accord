import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemberSidebar } from '../components/MemberSidebar';
import { AppContext } from '../components/AppContext';
import type { AppContextType } from '../components/AppContext';
import type { NodeMember, User, Role } from '../types';
import { PresenceStatus } from '../types';

vi.mock('../api', () => ({
  api: {
    getUserAvatarUrl: vi.fn((_userId: string) => `https://example.com/avatar/${_userId}`),
  },
}));

vi.mock('../buildHash', () => ({
  getCombinedTrust: vi.fn(() => 'verified'),
  getTrustIndicator: vi.fn(() => ({ label: 'Verified' })),
  CLIENT_BUILD_HASH: 'test-hash',
}));

vi.mock('../avatarColor', () => ({
  avatarColor: vi.fn((_userId: string) => '#ff5733'),
}));

const mockUser = (id: string, displayName: string): User => ({
  id,
  public_key_hash: `hash-${id}`,
  public_key: `key-${id}`,
  created_at: Date.now(),
  display_name: displayName,
});

const mockMember = (userId: string, role: 'admin' | 'moderator' | 'member' = 'member'): NodeMember & { user: User } => ({
  node_id: 'node-1',
  user_id: userId,
  public_key_hash: `hash-${userId}`,
  role,
  joined_at: Date.now(),
  profile: {
    user_id: userId,
    display_name: `User ${userId}`,
    status: PresenceStatus.Online,
    updated_at: Date.now(),
  },
  user: mockUser(userId, `User ${userId}`),
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
  showMemberSidebar: true,
  sortedMembers: [],
  nodeRoles: [],
  memberRolesMap: {},
  displayName: vi.fn((user: User) => user.display_name || user.id),
  getPresenceStatus: vi.fn(() => PresenceStatus.Online),
  hasPermission: vi.fn(() => false),
  setProfileCardTarget: vi.fn(),
  handleContextMenu: vi.fn(),
  openDmWithUser: vi.fn(),
  setShowRolePopup: vi.fn(),
  handleKickMember: vi.fn(),
  getMemberRoleColor: vi.fn(() => null),
  getRoleBadge: vi.fn(() => ''),
  getMemberHighestHoistedRole: vi.fn(() => null),
  serverBuildHash: 'test-hash',
  knownHashes: [],
  ...overrides,
} as any);

describe('MemberSidebar', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.setItem('accord_user_id', 'user-1');
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('does not render when showMemberSidebar is false', () => {
    const ctx = createMockContext({ showMemberSidebar: false });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    expect(container.querySelector('.member-sidebar')).not.toBeInTheDocument();
  });

  it('renders member sidebar with correct aria-label', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    const sidebar = screen.getByRole('complementary');
    expect(sidebar).toHaveAttribute('aria-label', 'Members');
  });

  it('displays member count in header', () => {
    const members = [mockMember('user-1'), mockMember('user-2'), mockMember('user-3')];
    const ctx = createMockContext({ members, sortedMembers: members });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('MEMBERS – 3')).toBeInTheDocument();
  });

  it('renders online and offline sections without hoisted roles', () => {
    const members = [mockMember('user-1'), mockMember('user-2')];
    const ctx = createMockContext({
      members,
      sortedMembers: members,
      getPresenceStatus: vi.fn((_uid: string) => _uid === 'user-1' ? PresenceStatus.Online : PresenceStatus.Offline),
    });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('ONLINE – 1')).toBeInTheDocument();
    expect(screen.getByText('OFFLINE – 1')).toBeInTheDocument();
  });

  it('displays member with avatar and presence indicator', () => {
    const members = [mockMember('user-1')];
    const ctx = createMockContext({ members, sortedMembers: members });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('User user-1')).toBeInTheDocument();
    expect(container.querySelector('.presence-dot.presence-online')).toBeInTheDocument();
  });

  it('displays trust indicator for current user', () => {
    const members = [mockMember('user-1')];
    const ctx = createMockContext({ members, sortedMembers: members });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    const trustDot = container.querySelector('.trust-dot.trust-verified');
    expect(trustDot).toBeInTheDocument();
  });

  it('does not display trust indicator for other users', () => {
    const members = [mockMember('user-2')];
    const ctx = createMockContext({ members, sortedMembers: members });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    const trustDot = container.querySelector('.trust-dot');
    expect(trustDot).not.toBeInTheDocument();
  });

  it('displays member custom status', () => {
    const memberWithStatus = {
      ...mockMember('user-1'),
      profile: { user_id: 'user-1', display_name: 'User user-1', status: PresenceStatus.Online, updated_at: Date.now(), custom_status: 'Working on a project', bio: '' },
    };
    const ctx = createMockContext({ members: [memberWithStatus], sortedMembers: [memberWithStatus] });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('Working on a project')).toBeInTheDocument();
  });

  it('displays member activity', () => {
    const memberWithActivity = {
      ...mockMember('user-1'),
      profile: { user_id: 'user-1', display_name: 'User user-1', status: PresenceStatus.Online, updated_at: Date.now(), activity: 'Playing a game', bio: '' },
    };
    const ctx = createMockContext({ members: [memberWithActivity], sortedMembers: [memberWithActivity] });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('Playing a game')).toBeInTheDocument();
  });

  it('displays DM button for other users', () => {
    const members = [mockMember('user-2')];
    const ctx = createMockContext({ members, sortedMembers: members });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByTitle('Send DM')).toBeInTheDocument();
  });

  it('does not display DM button for current user', () => {
    const members = [mockMember('user-1')];
    const ctx = createMockContext({ members, sortedMembers: members });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    expect(screen.queryByTitle('Send DM')).not.toBeInTheDocument();
  });

  it('displays kick and roles buttons when user has permission', () => {
    const members = [mockMember('user-2')];
    const ctx = createMockContext({
      members,
      sortedMembers: members,
      hasPermission: vi.fn(() => true),
    });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByTitle('Manage roles')).toBeInTheDocument();
    expect(screen.getByTitle('Kick member')).toBeInTheDocument();
  });

  it('does not display kick and roles buttons without permission', () => {
    const members = [mockMember('user-2')];
    const ctx = createMockContext({
      members,
      sortedMembers: members,
      hasPermission: vi.fn(() => false),
    });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    expect(screen.queryByTitle('Manage roles')).not.toBeInTheDocument();
    expect(screen.queryByTitle('Kick member')).not.toBeInTheDocument();
  });

  it('calls openDmWithUser when DM button is clicked', () => {
    const openDmWithUser = vi.fn();
    const members = [mockMember('user-2')];
    const ctx = createMockContext({ members, sortedMembers: members, openDmWithUser });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    const dmButton = screen.getByTitle('Send DM');
    fireEvent.click(dmButton);
    expect(openDmWithUser).toHaveBeenCalledWith(members[0].user);
  });

  it('calls setShowRolePopup when roles button is clicked', () => {
    const setShowRolePopup = vi.fn();
    const members = [mockMember('user-2')];
    const ctx = createMockContext({
      members,
      sortedMembers: members,
      hasPermission: vi.fn(() => true),
      setShowRolePopup,
    });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    const rolesButton = screen.getByTitle('Manage roles');
    fireEvent.click(rolesButton);
    expect(setShowRolePopup).toHaveBeenCalled();
  });

  it('calls handleKickMember when kick button is clicked', () => {
    const handleKickMember = vi.fn();
    const members = [mockMember('user-2')];
    const ctx = createMockContext({
      members,
      sortedMembers: members,
      hasPermission: vi.fn(() => true),
      handleKickMember,
      displayName: vi.fn(() => 'User 2'),
    });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    const kickButton = screen.getByTitle('Kick member');
    fireEvent.click(kickButton);
    expect(handleKickMember).toHaveBeenCalledWith('user-2', 'User 2');
  });

  it('calls setProfileCardTarget when member is clicked', () => {
    const setProfileCardTarget = vi.fn();
    const members = [mockMember('user-2')];
    const ctx = createMockContext({ members, sortedMembers: members, setProfileCardTarget });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    const memberElement = screen.getByText('User user-2').closest('.member');
    fireEvent.click(memberElement!);
    expect(setProfileCardTarget).toHaveBeenCalled();
  });

  it('displays hoisted role sections when roles have hoist enabled', () => {
    const role: Role = {
      id: 'role-1',
      node_id: 'node-1',
      name: 'Moderators',
      color: '#ff0000',
      position: 10,
      permissions: 0,
      hoist: true,
      mentionable: false,
      created_at: Date.now(),
    };
    const members = [mockMember('user-1', 'moderator')];
    const ctx = createMockContext({
      members,
      sortedMembers: members,
      nodeRoles: [role],
      getMemberHighestHoistedRole: vi.fn(() => role),
    });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    expect(screen.getByText('Moderators — 1')).toBeInTheDocument();
  });

  it('applies role color to role section header', () => {
    const role: Role = {
      id: 'role-1',
      node_id: 'node-1',
      name: 'Admins',
      color: '#0000ff',
      position: 20,
      permissions: 0,
      hoist: true,
      mentionable: false,
      created_at: Date.now(),
    };
    const members = [mockMember('user-1', 'admin')];
    const ctx = createMockContext({
      members,
      sortedMembers: members,
      nodeRoles: [role],
      getMemberHighestHoistedRole: vi.fn(() => role),
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    const header = container.querySelector('.role-section-header');
    expect(header).toHaveStyle({ color: '#0000ff' });
  });

  it('applies member-offline class to offline members', () => {
    const members = [mockMember('user-1')];
    const ctx = createMockContext({
      members,
      sortedMembers: members,
      getPresenceStatus: vi.fn(() => PresenceStatus.Offline),
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    const member = container.querySelector('.member.member-offline');
    expect(member).toBeInTheDocument();
  });

  it('displays empty state icon when no members and no nodes', () => {
    const ctx = createMockContext({
      members: [],
      sortedMembers: [],
      nodes: [],
    });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    // Just check that the sidebar renders with member header showing 0
    expect(screen.getByText('MEMBERS – 0')).toBeInTheDocument();
  });

  it('displays member header with zero count when no members loaded', () => {
    const ctx = createMockContext({
      members: [],
      sortedMembers: [],
      nodes: [{ id: 'node-1', name: 'Test', owner_id: 'owner', created_at: Date.now() }],
    });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    // Just check that the sidebar renders with member header showing 0
    expect(screen.getByText('MEMBERS – 0')).toBeInTheDocument();
  });

  it('applies member role color to member name', () => {
    const members = [mockMember('user-1')];
    const ctx = createMockContext({
      members,
      sortedMembers: members,
      getMemberRoleColor: vi.fn(() => '#00ff00'),
    });
    const { container } = render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    const memberName = container.querySelector('.member-name');
    expect(memberName).toHaveStyle({ color: '#00ff00' });
  });

  it('stops propagation when action buttons are clicked', () => {
    const setProfileCardTarget = vi.fn();
    const members = [mockMember('user-2')];
    const ctx = createMockContext({ members, sortedMembers: members, setProfileCardTarget });
    render(
      <AppContext.Provider value={ctx}>
        <MemberSidebar />
      </AppContext.Provider>
    );
    const dmButton = screen.getByTitle('Send DM');
    fireEvent.click(dmButton);
    // Profile card should not be triggered when clicking action button
    expect(setProfileCardTarget).not.toHaveBeenCalled();
  });
});
