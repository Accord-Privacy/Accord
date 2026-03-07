import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { SearchOverlay, parseSearchQuery } from '../SearchOverlay';
import type { Channel } from '../types';

vi.mock('../api', () => ({
  api: {
    searchMessages: vi.fn().mockResolvedValue({ results: [] }),
  },
}));
vi.mock('../crypto', () => ({
  decryptMessage: vi.fn(),
  getChannelKey: vi.fn(),
}));

const mockChannel = (overrides: Partial<Channel> = {}): Channel => ({
  id: 'ch1',
  name: 'general',
  node_id: 'node-1',
  channel_type: 'text' as const,
  position: 0,
  members: [],
  created_at: Date.now(),
  ...overrides,
});

const baseProps = {
  isVisible: true,
  onClose: vi.fn(),
  nodeId: 'node-1',
  channels: [
    mockChannel({ id: 'ch1', name: 'general' }),
    mockChannel({ id: 'ch2', name: 'random', position: 1 }),
  ],
  token: 'test-token',
  onNavigateToMessage: vi.fn(),
  currentMessages: [] as any[],
  currentChannelId: 'ch1',
};

describe('SearchOverlay', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('renders search input when visible', () => {
    render(<SearchOverlay {...baseProps} />);
    expect(screen.getByPlaceholderText(/search.*messages/i)).toBeInTheDocument();
  });

  it('does not render when not visible', () => {
    render(<SearchOverlay {...baseProps} isVisible={false} />);
    expect(screen.queryByPlaceholderText(/search messages/i)).not.toBeInTheDocument();
  });

  it('shows filter panel when Filters button is clicked', () => {
    render(<SearchOverlay {...baseProps} />);
    const serverTab = screen.getByText('Server');
    fireEvent.click(serverTab);
    fireEvent.click(screen.getByText(/filters/i));
    expect(screen.getByText('Channel:')).toBeInTheDocument();
    expect(screen.getByText(/from \(user id\)/i)).toBeInTheDocument();
  });

  it('renders channel options in filter dropdown', () => {
    render(<SearchOverlay {...baseProps} />);
    const serverTab = screen.getByText('Server');
    fireEvent.click(serverTab);
    fireEvent.click(screen.getByText(/filters/i));
    const select = screen.getByDisplayValue('All channels');
    expect(select).toBeInTheDocument();
    expect(screen.getByText('#general')).toBeInTheDocument();
    expect(screen.getByText('#random')).toBeInTheDocument();
  });
});

describe('parseSearchQuery', () => {
  it('parses from: filter', () => {
    const result = parseSearchQuery('from:alice hello world');
    expect(result.from).toBe('alice');
    expect(result.text).toBe('hello world');
  });

  it('parses in: filter', () => {
    const result = parseSearchQuery('in:general test');
    expect(result.in).toBe('general');
    expect(result.text).toBe('test');
  });

  it('parses before: and after: filters', () => {
    const result = parseSearchQuery('before:2026-01-01 after:2025-06-01 keyword');
    expect(result.before).toBe('2026-01-01');
    expect(result.after).toBe('2025-06-01');
    expect(result.text).toBe('keyword');
  });

  it('parses has: filters', () => {
    const result = parseSearchQuery('has:file has:image test');
    expect(result.has).toEqual(['file', 'image']);
    expect(result.text).toBe('test');
  });

  it('parses quoted values', () => {
    const result = parseSearchQuery('from:"John Doe" hello');
    expect(result.from).toBe('John Doe');
    expect(result.text).toBe('hello');
  });

  it('returns plain text when no filters', () => {
    const result = parseSearchQuery('just a search');
    expect(result.text).toBe('just a search');
    expect(result.from).toBeUndefined();
    expect(result.has).toBeUndefined();
  });

  it('handles has:link', () => {
    const result = parseSearchQuery('has:link');
    expect(result.has).toEqual(['link']);
    expect(result.text).toBe('');
  });
});
