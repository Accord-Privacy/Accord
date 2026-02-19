import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { SearchOverlay } from '../SearchOverlay';

// Mock api and crypto
vi.mock('../api', () => ({
  api: {
    searchMessages: vi.fn().mockResolvedValue({ results: [] }),
  },
}));
vi.mock('../crypto', () => ({
  decryptMessage: vi.fn(),
  getChannelKey: vi.fn(),
}));

const baseProps = {
  isVisible: true,
  onClose: vi.fn(),
  nodeId: 'node-1',
  channels: [
    { id: 'ch1', name: 'general', node_id: 'node-1', channel_type: 'text' as const, position: 0 },
    { id: 'ch2', name: 'random', node_id: 'node-1', channel_type: 'text' as const, position: 1 },
  ],
  token: 'test-token',
  onNavigateToMessage: vi.fn(),
};

describe('SearchOverlay', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders search input when visible', () => {
    render(<SearchOverlay {...baseProps} />);
    expect(screen.getByPlaceholderText(/search messages/i)).toBeInTheDocument();
  });

  it('does not render when not visible', () => {
    render(<SearchOverlay {...baseProps} isVisible={false} />);
    expect(screen.queryByPlaceholderText(/search messages/i)).not.toBeInTheDocument();
  });

  it('shows filter panel when Filters button is clicked', () => {
    render(<SearchOverlay {...baseProps} />);
    fireEvent.click(screen.getByText(/filters/i));
    expect(screen.getByText('Channel:')).toBeInTheDocument();
    expect(screen.getByText(/from \(user id\)/i)).toBeInTheDocument();
  });

  it('renders channel options in filter dropdown', () => {
    render(<SearchOverlay {...baseProps} />);
    fireEvent.click(screen.getByText(/filters/i));
    const select = screen.getByDisplayValue('All channels');
    expect(select).toBeInTheDocument();
    expect(screen.getByText('#general')).toBeInTheDocument();
    expect(screen.getByText('#random')).toBeInTheDocument();
  });
});
