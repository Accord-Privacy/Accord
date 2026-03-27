import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MentionAutocomplete } from '../components/MentionAutocomplete';
import type { AutocompleteItem } from '../hooks/useMentionAutocomplete';

describe('MentionAutocomplete', () => {
  const mockUserItem: AutocompleteItem = {
    type: 'user',
    id: 'user-1',
    label: 'John Doe',
    subtitle: 'Admin',
    avatarUrl: 'https://example.com/avatar.png',
    avatarColor: '#ff5733',
    insertText: '@JohnDoe',
  };

  const mockChannelItem: AutocompleteItem = {
    type: 'channel',
    id: 'channel-1',
    label: 'general',
    insertText: '#general',
    avatarColor: '#00ff00',
  };

  let onSelectMock: (index: number) => void;

  beforeEach(() => {
    onSelectMock = vi.fn() as unknown as (index: number) => void;
    vi.clearAllMocks();
    // Mock scrollIntoView
    Element.prototype.scrollIntoView = vi.fn();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('does not render when visible is false', () => {
    const { container } = render(
      <MentionAutocomplete
        items={[mockUserItem]}
        selectedIndex={0}
        triggerChar="@"
        visible={false}
        onSelect={onSelectMock}
      />
    );
    expect(container.querySelector('.mention-autocomplete')).not.toBeInTheDocument();
  });

  it('does not render when items array is empty', () => {
    const { container } = render(
      <MentionAutocomplete
        items={[]}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    expect(container.querySelector('.mention-autocomplete')).not.toBeInTheDocument();
  });

  it('renders listbox with correct aria-label for user mentions', () => {
    render(
      <MentionAutocomplete
        items={[mockUserItem]}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const listbox = screen.getByRole('listbox');
    expect(listbox).toBeInTheDocument();
    expect(listbox).toHaveAttribute('aria-label', 'User mentions');
  });

  it('renders listbox with correct aria-label for channel links', () => {
    render(
      <MentionAutocomplete
        items={[mockChannelItem]}
        selectedIndex={0}
        triggerChar="#"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const listbox = screen.getByRole('listbox');
    expect(listbox).toHaveAttribute('aria-label', 'Channel links');
  });

  it('renders all items in the list', () => {
    const items: AutocompleteItem[] = [
      mockUserItem,
      { ...mockUserItem, id: 'user-2', label: 'Jane Smith', insertText: '@JaneSmith' },
      mockChannelItem,
    ];
    render(
      <MentionAutocomplete
        items={items}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const options = screen.getAllByRole('option');
    expect(options).toHaveLength(3);
  });

  it('applies selected class to the selected item', () => {
    const items = [mockUserItem, mockChannelItem];
    const { container } = render(
      <MentionAutocomplete
        items={items}
        selectedIndex={1}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const selectedItem = container.querySelectorAll('.mention-autocomplete-item')[1];
    expect(selectedItem).toHaveClass('selected');
  });

  it('sets aria-selected on the selected item', () => {
    const items = [mockUserItem, mockChannelItem];
    render(
      <MentionAutocomplete
        items={items}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const options = screen.getAllByRole('option');
    expect(options[0]).toHaveAttribute('aria-selected', 'true');
    expect(options[1]).toHaveAttribute('aria-selected', 'false');
  });

  it('displays user avatar with correct background color', () => {
    const { container } = render(
      <MentionAutocomplete
        items={[mockUserItem]}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const avatar = container.querySelector('.mention-autocomplete-avatar');
    expect(avatar).toHaveStyle({ background: '#ff5733' });
  });

  it('displays channel hash symbol for channel items', () => {
    const { container } = render(
      <MentionAutocomplete
        items={[mockChannelItem]}
        selectedIndex={0}
        triggerChar="#"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const hashSymbol = container.querySelector('.mention-autocomplete-hash');
    expect(hashSymbol).toBeInTheDocument();
    expect(hashSymbol?.textContent).toBe('#');
  });

  it('displays avatar image when avatarUrl is provided', () => {
    const { container } = render(
      <MentionAutocomplete
        items={[mockUserItem]}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const img = container.querySelector('.mention-autocomplete-avatar img');
    expect(img).toBeInTheDocument();
    expect(img?.getAttribute('src')).toBe('https://example.com/avatar.png');
    expect(img?.getAttribute('alt')).toBe('J');
  });

  it('displays initials when no avatarUrl is provided', () => {
    const itemWithoutAvatar = { ...mockUserItem, avatarUrl: undefined };
    const { container } = render(
      <MentionAutocomplete
        items={[itemWithoutAvatar]}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const avatar = container.querySelector('.mention-autocomplete-avatar');
    expect(avatar?.textContent).toBe('J');
  });

  it('displays user label and subtitle', () => {
    render(
      <MentionAutocomplete
        items={[mockUserItem]}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    expect(screen.getByText('John Doe')).toBeInTheDocument();
    expect(screen.getByText('Admin')).toBeInTheDocument();
  });

  it('does not display subtitle when not provided', () => {
    const itemWithoutSubtitle = { ...mockChannelItem };
    const { container } = render(
      <MentionAutocomplete
        items={[itemWithoutSubtitle]}
        selectedIndex={0}
        triggerChar="#"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    expect(container.querySelector('.mention-autocomplete-role')).not.toBeInTheDocument();
  });

  it('calls onSelect with correct index when item is clicked', () => {
    const items = [mockUserItem, mockChannelItem];
    const { container } = render(
      <MentionAutocomplete
        items={items}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const items2 = container.querySelectorAll('.mention-autocomplete-item');
    fireEvent.mouseDown(items2[1]);
    expect(onSelectMock).toHaveBeenCalledWith(1);
  });

  it('prevents default on mouseDown to maintain focus', () => {
    const { container } = render(
      <MentionAutocomplete
        items={[mockUserItem]}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const item = container.querySelector('.mention-autocomplete-item') as HTMLElement;
    const event = new MouseEvent('mousedown', { bubbles: true, cancelable: true });
    const preventDefaultSpy = vi.spyOn(event, 'preventDefault');
    item.dispatchEvent(event);
    expect(preventDefaultSpy).toHaveBeenCalled();
  });

  it('handles avatar image load error by showing initials', () => {
    const { container } = render(
      <MentionAutocomplete
        items={[mockUserItem]}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const img = container.querySelector('.mention-autocomplete-avatar img') as HTMLImageElement;
    fireEvent.error(img);
    expect(img.style.display).toBe('none');
  });

  it('handles empty label gracefully with fallback character', () => {
    const itemWithEmptyLabel = { ...mockUserItem, label: '', avatarUrl: undefined };
    const { container } = render(
      <MentionAutocomplete
        items={[itemWithEmptyLabel]}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const avatar = container.querySelector('.mention-autocomplete-avatar');
    expect(avatar?.textContent?.trim()).toBe('?');
  });

  it('renders with null triggerChar', () => {
    const { container } = render(
      <MentionAutocomplete
        items={[mockUserItem]}
        selectedIndex={0}
        triggerChar={null}
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const listbox = container.querySelector('.mention-autocomplete');
    expect(listbox).toBeInTheDocument();
  });

  it('uses fallback background color when avatarColor is not provided', () => {
    const itemWithoutColor = { ...mockUserItem, avatarColor: undefined };
    const { container } = render(
      <MentionAutocomplete
        items={[itemWithoutColor]}
        selectedIndex={0}
        triggerChar="@"
        visible={true}
        onSelect={onSelectMock}
      />
    );
    const avatar = container.querySelector('.mention-autocomplete-avatar');
    expect(avatar).toHaveStyle({ background: 'var(--bg-tertiary)' });
  });
});
