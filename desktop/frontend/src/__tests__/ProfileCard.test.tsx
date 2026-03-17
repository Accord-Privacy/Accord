import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { ProfileCard } from '../ProfileCard';
import type { UserProfile, Role } from '../types';

vi.mock('../api', () => ({
  api: {
    getUserProfile: vi.fn().mockResolvedValue(null),
    getMemberRoles: vi.fn().mockResolvedValue([]),
    getUserAvatarUrl: vi.fn((id: string) => `https://example.com/avatar/${id}`),
  },
}));

const baseProps = {
  anchorX: 100,
  anchorY: 100,
  token: 'test-token',
  onClose: vi.fn(),
};

const mockProfile = (overrides: Partial<UserProfile> = {}): UserProfile => ({
  user_id: 'user-1',
  display_name: 'Test User',
  status: 'online' as UserProfile['status'],
  updated_at: Date.now(),
  ...overrides,
});

const mockRole = (overrides: Partial<Role> = {}): Role => ({
  id: 'r1',
  node_id: 'n1',
  name: 'Member',
  color: '#ffffff',
  position: 0,
  permissions: 0,
  hoist: false,
  mentionable: false,
  created_at: Date.now(),
  ...overrides,
});

describe('ProfileCard', () => {
  beforeEach(() => { vi.clearAllMocks(); localStorage.clear(); });

  it('renders display name and bio from profile', () => {
    render(
      <ProfileCard {...baseProps} userId="user-1" currentUserId="user-2"
        profile={mockProfile({ display_name: 'Alice', bio: 'Hello world' })} />
    );
    expect(screen.getByText('Alice')).toBeInTheDocument();
    expect(screen.getByText('Hello world')).toBeInTheDocument();
  });

  it('shows Edit Profile button for self', () => {
    render(
      <ProfileCard {...baseProps} userId="user-1" currentUserId="user-1"
        profile={mockProfile({ display_name: 'Me' })} />
    );
    expect(screen.getByText('Edit Profile')).toBeInTheDocument();
    expect(screen.queryByText('Message')).not.toBeInTheDocument();
  });

  it('shows Message and Block buttons for other users', () => {
    render(
      <ProfileCard {...baseProps} userId="user-1" currentUserId="user-2"
        profile={mockProfile({ display_name: 'Other' })} />
    );
    expect(screen.getByText('Message')).toBeInTheDocument();
    expect(screen.getByText('Block')).toBeInTheDocument();
  });

  it('renders roles when provided', () => {
    render(
      <ProfileCard {...baseProps} userId="user-1" currentUserId="user-2"
        profile={mockProfile({ display_name: 'Bob' })}
        roles={[
          mockRole({ id: 'r1', name: 'Admin', color: '#ff0000', position: 1 }),
          mockRole({ id: 'r2', name: 'Member', color: '#00ff00', position: 0 }),
        ]} />
    );
    expect(screen.getByText('Admin')).toBeInTheDocument();
    expect(screen.getByText('Member')).toBeInTheDocument();
  });

  it('renders About Me and Mutual Nodes tabs', () => {
    render(
      <ProfileCard {...baseProps} userId="user-1" currentUserId="user-2"
        profile={mockProfile({ display_name: 'Tab User' })} />
    );
    expect(screen.getByText('About Me')).toBeInTheDocument();
    expect(screen.getByText('Mutual Nodes')).toBeInTheDocument();
  });

  it('switches to Mutual Nodes tab', () => {
    render(
      <ProfileCard {...baseProps} userId="user-1" currentUserId="user-2"
        profile={mockProfile({ display_name: 'Tab User' })} nodeId="node-1" />
    );
    act(() => {
      fireEvent.click(screen.getByText('Mutual Nodes'));
    });
    expect(screen.getByText('Current Node')).toBeInTheDocument();
  });

  it('shows note placeholder and allows editing', () => {
    render(
      <ProfileCard {...baseProps} userId="user-1" currentUserId="user-2"
        profile={mockProfile({ display_name: 'Note User' })} />
    );
    expect(screen.getByText('Click to add a note')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Click to add a note'));
    const textarea = screen.getByPlaceholderText('Click to add a note');
    fireEvent.change(textarea, { target: { value: 'My private note' } });
    expect(localStorage.getItem('accord-note:user-1')).toBe('My private note');
  });
});
