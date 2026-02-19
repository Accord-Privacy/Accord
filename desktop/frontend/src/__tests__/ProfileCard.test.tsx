import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { ProfileCard } from '../ProfileCard';

// Mock the api module
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

describe('ProfileCard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders display name and bio from profile', () => {
    render(
      <ProfileCard
        {...baseProps}
        userId="user-1"
        currentUserId="user-2"
        profile={{ display_name: 'Alice', bio: 'Hello world', custom_status: '' }}
      />
    );

    expect(screen.getByText('Alice')).toBeInTheDocument();
    expect(screen.getByText('Hello world')).toBeInTheDocument();
  });

  it('shows Edit Profile button for self', () => {
    render(
      <ProfileCard
        {...baseProps}
        userId="user-1"
        currentUserId="user-1"
        profile={{ display_name: 'Me', bio: '', custom_status: '' }}
      />
    );

    expect(screen.getByText('Edit Profile')).toBeInTheDocument();
    expect(screen.queryByText('Message')).not.toBeInTheDocument();
    expect(screen.queryByText('Block')).not.toBeInTheDocument();
  });

  it('shows Message and Block buttons for other users', () => {
    render(
      <ProfileCard
        {...baseProps}
        userId="user-1"
        currentUserId="user-2"
        profile={{ display_name: 'Other', bio: '', custom_status: '' }}
      />
    );

    expect(screen.getByText('Message')).toBeInTheDocument();
    expect(screen.getByText('Block')).toBeInTheDocument();
    expect(screen.queryByText('Edit Profile')).not.toBeInTheDocument();
  });

  it('renders roles when provided', () => {
    render(
      <ProfileCard
        {...baseProps}
        userId="user-1"
        currentUserId="user-2"
        profile={{ display_name: 'Bob', bio: '', custom_status: '' }}
        roles={[
          { id: 'r1', name: 'Admin', color: '#ff0000', position: 1, permissions: 0 },
          { id: 'r2', name: 'Member', color: '#00ff00', position: 0, permissions: 0 },
        ]}
      />
    );

    expect(screen.getByText('Admin')).toBeInTheDocument();
    expect(screen.getByText('Member')).toBeInTheDocument();
  });
});
