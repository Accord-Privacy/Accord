import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { SlashCommandPopup } from '../components/SlashCommandPopup';
import type { SlashCommand } from '../hooks/useSlashCommands';

const mockCommands: SlashCommand[] = [
  { name: 'nick', description: 'Change display name', usage: '/nick [name]', hasArg: true },
  { name: 'status', description: 'Set custom status', usage: '/status [text]', hasArg: true },
  { name: 'clear', description: 'Clear chat', usage: '/clear', hasArg: false, immediate: true },
  { name: 'shrug', description: 'Append shrug emoji', usage: '/shrug', hasArg: false, appendText: '¯\\_(ツ)_/¯' },
];

describe('SlashCommandPopup', () => {
  const mockOnSelect = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    Element.prototype.scrollIntoView = vi.fn();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('renders null when not visible', () => {
    const { container } = render(
      <SlashCommandPopup items={mockCommands} selectedIndex={0} visible={false} onSelect={mockOnSelect} />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders null when items array is empty', () => {
    const { container } = render(
      <SlashCommandPopup items={[]} selectedIndex={0} visible={true} onSelect={mockOnSelect} />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders all command items when visible', () => {
    render(<SlashCommandPopup items={mockCommands} selectedIndex={0} visible={true} onSelect={mockOnSelect} />);
    expect(screen.getByText('/nick [name]')).toBeInTheDocument();
    expect(screen.getByText('/status [text]')).toBeInTheDocument();
    expect(screen.getByText('/clear')).toBeInTheDocument();
    expect(screen.getByText('/shrug')).toBeInTheDocument();
  });

  it('displays command descriptions', () => {
    render(<SlashCommandPopup items={mockCommands} selectedIndex={0} visible={true} onSelect={mockOnSelect} />);
    expect(screen.getByText('Change display name')).toBeInTheDocument();
    expect(screen.getByText('Set custom status')).toBeInTheDocument();
    expect(screen.getByText('Clear chat')).toBeInTheDocument();
    expect(screen.getByText('Append shrug emoji')).toBeInTheDocument();
  });

  it('applies selected class to first item when selectedIndex is 0', () => {
    const { container } = render(
      <SlashCommandPopup items={mockCommands} selectedIndex={0} visible={true} onSelect={mockOnSelect} />
    );
    const items = container.querySelectorAll('.slash-command-item');
    expect(items[0]).toHaveClass('selected');
    expect(items[1]).not.toHaveClass('selected');
  });

  it('applies selected class to correct item based on selectedIndex', () => {
    const { container } = render(
      <SlashCommandPopup items={mockCommands} selectedIndex={2} visible={true} onSelect={mockOnSelect} />
    );
    const items = container.querySelectorAll('.slash-command-item');
    expect(items[0]).not.toHaveClass('selected');
    expect(items[2]).toHaveClass('selected');
  });

  it('calls onSelect with correct index on mouseDown', () => {
    render(<SlashCommandPopup items={mockCommands} selectedIndex={0} visible={true} onSelect={mockOnSelect} />);
    const statusItem = screen.getByText('/status [text]').closest('.slash-command-item');
    fireEvent.mouseDown(statusItem!);
    expect(mockOnSelect).toHaveBeenCalledWith(1);
  });

  it('prevents default on mouseDown to avoid losing focus', () => {
    render(<SlashCommandPopup items={mockCommands} selectedIndex={0} visible={true} onSelect={mockOnSelect} />);
    const item = screen.getByText('/nick [name]').closest('.slash-command-item');
    const event = new MouseEvent('mousedown', { bubbles: true, cancelable: true });
    const preventDefaultSpy = vi.spyOn(event, 'preventDefault');
    fireEvent(item!, event);
    expect(preventDefaultSpy).toHaveBeenCalled();
  });

  it('renders slash icon for each command', () => {
    const { container } = render(
      <SlashCommandPopup items={mockCommands} selectedIndex={0} visible={true} onSelect={mockOnSelect} />
    );
    const icons = container.querySelectorAll('.slash-command-icon');
    expect(icons).toHaveLength(4);
    icons.forEach(icon => {
      expect(icon.textContent).toBe('/');
    });
  });

  it('applies correct ARIA attributes', () => {
    const { container } = render(
      <SlashCommandPopup items={mockCommands} selectedIndex={1} visible={true} onSelect={mockOnSelect} />
    );
    const listbox = container.querySelector('[role="listbox"]');
    expect(listbox).toBeInTheDocument();
    expect(listbox).toHaveAttribute('aria-label', 'Slash commands');

    const items = container.querySelectorAll('[role="option"]');
    expect(items).toHaveLength(4);
    expect(items[0]).toHaveAttribute('aria-selected', 'false');
    expect(items[1]).toHaveAttribute('aria-selected', 'true');
  });

  it('scrolls selected item into view when selectedIndex changes', () => {
    const scrollIntoViewMock = vi.fn();
    Element.prototype.scrollIntoView = scrollIntoViewMock;

    const { rerender } = render(
      <SlashCommandPopup items={mockCommands} selectedIndex={0} visible={true} onSelect={mockOnSelect} />
    );
    expect(scrollIntoViewMock).toHaveBeenCalledWith({ block: 'nearest' });

    scrollIntoViewMock.mockClear();
    rerender(<SlashCommandPopup items={mockCommands} selectedIndex={2} visible={true} onSelect={mockOnSelect} />);
    expect(scrollIntoViewMock).toHaveBeenCalledWith({ block: 'nearest' });
  });

  it('applies correct CSS classes for styling', () => {
    const { container } = render(
      <SlashCommandPopup items={mockCommands} selectedIndex={0} visible={true} onSelect={mockOnSelect} />
    );
    expect(container.querySelector('.mention-autocomplete')).toBeInTheDocument();
    expect(container.querySelector('.slash-command-autocomplete')).toBeInTheDocument();
    expect(container.querySelector('.mention-autocomplete-item')).toBeInTheDocument();
    expect(container.querySelector('.slash-command-item')).toBeInTheDocument();
  });

  it('renders command usage in correct element', () => {
    const { container } = render(
      <SlashCommandPopup items={mockCommands} selectedIndex={0} visible={true} onSelect={mockOnSelect} />
    );
    const usageElements = container.querySelectorAll('.mention-autocomplete-name');
    expect(usageElements[0].textContent).toBe('/nick [name]');
  });

  it('renders command description in correct element', () => {
    const { container } = render(
      <SlashCommandPopup items={mockCommands} selectedIndex={0} visible={true} onSelect={mockOnSelect} />
    );
    const descElements = container.querySelectorAll('.mention-autocomplete-role');
    expect(descElements[0].textContent).toBe('Change display name');
  });

  it('handles single command item', () => {
    const singleCommand = [mockCommands[0]];
    render(<SlashCommandPopup items={singleCommand} selectedIndex={0} visible={true} onSelect={mockOnSelect} />);
    expect(screen.getByText('/nick [name]')).toBeInTheDocument();
    const { container } = render(
      <SlashCommandPopup items={singleCommand} selectedIndex={0} visible={true} onSelect={mockOnSelect} />
    );
    expect(container.querySelectorAll('.slash-command-item')).toHaveLength(1);
  });
});
