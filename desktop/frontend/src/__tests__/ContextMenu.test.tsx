import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ContextMenu, type ContextMenuItem } from '../components/ui/ContextMenu';

describe('ContextMenu', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const basicItems: ContextMenuItem[] = [
    { label: 'Edit', onClick: vi.fn() },
    { label: 'Delete', onClick: vi.fn(), danger: true },
  ];

  it('renders children without menu initially', () => {
    render(
      <ContextMenu items={basicItems}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    expect(screen.getByText('Right-click me')).toBeInTheDocument();
    expect(screen.queryByText('Edit')).not.toBeInTheDocument();
  });

  it('opens menu on right-click', () => {
    render(
      <ContextMenu items={basicItems}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    expect(screen.getByText('Edit')).toBeInTheDocument();
    expect(screen.getByText('Delete')).toBeInTheDocument();
  });

  it('prevents default context menu behavior', () => {
    render(
      <ContextMenu items={basicItems}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    const event = new MouseEvent('contextmenu', { bubbles: true, cancelable: true });
    const preventDefaultSpy = vi.spyOn(event, 'preventDefault');
    screen.getByText('Right-click me').dispatchEvent(event);
    expect(preventDefaultSpy).toHaveBeenCalled();
  });

  it('closes menu when clicking outside', () => {
    render(
      <ContextMenu items={basicItems}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    expect(screen.getByText('Edit')).toBeInTheDocument();

    fireEvent.mouseDown(document.body);
    expect(screen.queryByText('Edit')).not.toBeInTheDocument();
  });

  it('closes menu on Escape key', () => {
    render(
      <ContextMenu items={basicItems}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    expect(screen.getByText('Edit')).toBeInTheDocument();

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByText('Edit')).not.toBeInTheDocument();
  });

  it('calls onClick handler when menu item is clicked', () => {
    const onClick = vi.fn();
    const items: ContextMenuItem[] = [{ label: 'Action', onClick }];
    render(
      <ContextMenu items={items}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    fireEvent.click(screen.getByText('Action'));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('closes menu after clicking menu item', () => {
    const items: ContextMenuItem[] = [{ label: 'Action', onClick: vi.fn() }];
    render(
      <ContextMenu items={items}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    fireEvent.click(screen.getByText('Action'));
    expect(screen.queryByText('Action')).not.toBeInTheDocument();
  });

  it('applies danger class to danger items', () => {
    const items: ContextMenuItem[] = [{ label: 'Delete', danger: true }];
    render(
      <ContextMenu items={items}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    const menuItem = screen.getByText('Delete').parentElement;
    expect(menuItem).toHaveClass('context-menu-danger');
  });

  it('does not trigger onClick for disabled items', () => {
    const onClick = vi.fn();
    const items: ContextMenuItem[] = [{ label: 'Disabled', disabled: true, onClick }];
    render(
      <ContextMenu items={items}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    fireEvent.click(screen.getByText('Disabled'));
    expect(onClick).not.toHaveBeenCalled();
  });

  it('applies disabled class to disabled items', () => {
    const items: ContextMenuItem[] = [{ label: 'Disabled', disabled: true }];
    render(
      <ContextMenu items={items}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    const menuItem = screen.getByText('Disabled').parentElement;
    expect(menuItem).toHaveClass('context-menu-disabled');
  });

  it('renders separator items', () => {
    const items: ContextMenuItem[] = [
      { label: 'Action 1', onClick: vi.fn() },
      { label: '', separator: true },
      { label: 'Action 2', onClick: vi.fn() },
    ];
    const { container } = render(
      <ContextMenu items={items}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    expect(container.querySelector('.context-menu-separator')).toBeInTheDocument();
  });

  it('renders icon when provided', () => {
    const items: ContextMenuItem[] = [{ label: 'Star', icon: '⭐', onClick: vi.fn() }];
    render(
      <ContextMenu items={items}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    expect(screen.getByText('⭐')).toBeInTheDocument();
  });

  it('renders backdrop when menu is open', () => {
    const { container } = render(
      <ContextMenu items={basicItems}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    expect(container.querySelector('.context-menu-backdrop')).toBeInTheDocument();
  });

  it('closes menu when backdrop is clicked', () => {
    const { container } = render(
      <ContextMenu items={basicItems}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    const backdrop = container.querySelector('.context-menu-backdrop');
    if (backdrop) {
      fireEvent.click(backdrop);
    }
    expect(screen.queryByText('Edit')).not.toBeInTheDocument();
  });

  it('closes menu on scroll', () => {
    render(
      <ContextMenu items={basicItems}>
        <div>Right-click me</div>
      </ContextMenu>
    );
    fireEvent.contextMenu(screen.getByText('Right-click me'));
    expect(screen.getByText('Edit')).toBeInTheDocument();

    fireEvent.scroll(document);
    expect(screen.queryByText('Edit')).not.toBeInTheDocument();
  });
});
