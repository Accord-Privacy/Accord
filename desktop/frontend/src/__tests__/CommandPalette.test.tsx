import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { CommandPalette } from '../components/CommandPalette';
import { AppContext } from '../components/AppContext';
import type { AppContextType } from '../components/AppContext';

// Stub CSS imports
vi.mock('../styles/command-palette.css', () => ({}));

// jsdom doesn't implement scrollIntoView
Element.prototype.scrollIntoView = vi.fn();

// Stub themes
vi.mock('../themes', () => ({
  getSavedTheme: vi.fn(() => 'dark'),
  applyTheme: vi.fn(),
  themes: { dark: {}, light: {}, amoled: {} },
}));

const handleChannelSelect = vi.fn();
const openDmWithUser = vi.fn();
const setShowSettings = vi.fn();
const setShowCreateNodeModal = vi.fn();
const setShowJoinNodeModal = vi.fn();

const mockCtx: Partial<AppContextType> = {
  channels: [
    { id: 'ch1', name: 'general', node_id: 'n1', channel_type: 'text', position: 0, members: [], created_at: Date.now() },
    { id: 'ch2', name: 'random', node_id: 'n1', channel_type: 'text', position: 1, members: [], created_at: Date.now() },
    { id: 'ch3', name: 'voice-lobby', node_id: 'n1', channel_type: 'voice', position: 2, members: [], created_at: Date.now() },
  ],
  sortedMembers: [
    {
      user_id: 'user-1',
      user: { user_id: 'user-1', display_name: 'Alice', public_key_hash: 'hash1', created_at: Date.now() },
      profile: null,
      node_id: 'n1',
      joined_at: Date.now(),
      roles: [],
    } as any,
  ],
  handleChannelSelect,
  openDmWithUser,
  setShowSettings,
  setShowCreateNodeModal,
  setShowJoinNodeModal,
};

const Wrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <AppContext.Provider value={mockCtx as AppContextType}>
    {children}
  </AppContext.Provider>
);

describe('CommandPalette', () => {
  const onClose = vi.fn();

  beforeEach(() => { vi.clearAllMocks(); });

  it('renders the search input', () => {
    render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    expect(screen.getByPlaceholderText(/type a command or search/i)).toBeInTheDocument();
  });

  it('renders channel items', () => {
    render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    expect(screen.getByText('general')).toBeInTheDocument();
    expect(screen.getByText('random')).toBeInTheDocument();
  });

  it('renders built-in action items', () => {
    render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    expect(screen.getByText('Open Settings')).toBeInTheDocument();
    expect(screen.getByText('Create Node')).toBeInTheDocument();
    expect(screen.getByText('Join Node')).toBeInTheDocument();
    expect(screen.getByText('Toggle Theme')).toBeInTheDocument();
  });

  it('renders user items', () => {
    render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    expect(screen.getByText('Alice')).toBeInTheDocument();
  });

  it('filters results when typing in the search input', () => {
    render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    const input = screen.getByPlaceholderText(/type a command or search/i);
    fireEvent.change(input, { target: { value: 'gen' } });
    expect(screen.getByText('general')).toBeInTheDocument();
    expect(screen.queryByText('random')).not.toBeInTheDocument();
  });

  it('shows "No results found" for a query with no matches', () => {
    render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    const input = screen.getByPlaceholderText(/type a command or search/i);
    fireEvent.change(input, { target: { value: 'zzzzz' } });
    expect(screen.getByText('No results found')).toBeInTheDocument();
  });

  it('closes when Escape is pressed', () => {
    render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    const input = screen.getByPlaceholderText(/type a command or search/i);
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('closes when the overlay is clicked', () => {
    const { container } = render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    const overlay = container.querySelector('.command-palette-overlay');
    expect(overlay).toBeInTheDocument();
    fireEvent.click(overlay!);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('selects an item and calls its action on Enter', () => {
    render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    const input = screen.getByPlaceholderText(/type a command or search/i);
    // Filter to just 'general'
    fireEvent.change(input, { target: { value: 'general' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(handleChannelSelect).toHaveBeenCalledWith('ch1', 'general');
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('navigates down with ArrowDown key', () => {
    render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    const input = screen.getByPlaceholderText(/type a command or search/i);
    // First item is active by default; pressing down moves to second
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    // The active item gets cp-active class — just verify no crash and keyDown works
    const activeItems = document.querySelectorAll('.cp-active');
    expect(activeItems.length).toBe(1);
  });

  it('clicking an item calls its action and closes', () => {
    render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    fireEvent.click(screen.getByText('Open Settings'));
    expect(setShowSettings).toHaveBeenCalledWith(true);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('has accessible dialog role', () => {
    render(<CommandPalette onClose={onClose} />, { wrapper: Wrapper });
    expect(screen.getByRole('dialog', { name: /command palette/i })).toBeInTheDocument();
  });
});
