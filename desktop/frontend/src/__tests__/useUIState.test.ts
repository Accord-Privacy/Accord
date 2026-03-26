/**
 * useUIState hook unit tests
 *
 * Covers:
 * - Initial state values
 * - State toggle/setter functions
 * - Combined state interactions
 * - Sidebar/panel visibility
 */

import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { useUIState } from '../hooks/useUIState';

// ─── setup ────────────────────────────────────────────────────────────────────

beforeEach(() => {
  localStorage.clear();
});

// ─── Initial state ────────────────────────────────────────────────────────────

describe('useUIState — initial state', () => {
  it('customStatus is empty string', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.customStatus).toBe('');
  });

  it('showStatusPopover is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showStatusPopover).toBe(false);
  });

  it('statusInput is empty string', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.statusInput).toBe('');
  });

  it('showPinnedPanel is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showPinnedPanel).toBe(false);
  });

  it('pinnedMessages is empty array', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.pinnedMessages).toEqual([]);
  });

  it('showPinConfirm is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showPinConfirm).toBeNull();
  });

  it('threadParentMessage is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.threadParentMessage).toBeNull();
  });

  it('threadMessages is empty array', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.threadMessages).toEqual([]);
  });

  it('threadLoading is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.threadLoading).toBe(false);
  });

  it('showEmojiPicker is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showEmojiPicker).toBeNull();
  });

  it('hoveredMessageId is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.hoveredMessageId).toBeNull();
  });

  it('showNotificationSettings is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showNotificationSettings).toBe(false);
  });

  it('showSearchOverlay is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showSearchOverlay).toBe(false);
  });

  it('showJoinNodeModal is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showJoinNodeModal).toBe(false);
  });

  it('showCreateNodeModal is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showCreateNodeModal).toBe(false);
  });

  it('showSettings is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showSettings).toBe(false);
  });

  it('showNodeSettings is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showNodeSettings).toBe(false);
  });

  it('showCreateChannelForm is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showCreateChannelForm).toBe(false);
  });

  it('showInviteModal is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showInviteModal).toBe(false);
  });

  it('showDisplayNamePrompt is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showDisplayNamePrompt).toBe(false);
  });

  it('showShortcutsHelp is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showShortcutsHelp).toBe(false);
  });

  it('mobileSidebarOpen is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.mobileSidebarOpen).toBe(false);
  });

  it('showMemberSidebar is true by default', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showMemberSidebar).toBe(true);
  });

  it('showInputEmojiPicker is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showInputEmojiPicker).toBe(false);
  });

  it('showGifPicker is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showGifPicker).toBe(false);
  });

  it('showScrollToBottom is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showScrollToBottom).toBe(false);
  });

  it('newMessageCount is 0', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.newMessageCount).toBe(0);
  });

  it('contextMenu is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.contextMenu).toBeNull();
  });

  it('profileCardTarget is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.profileCardTarget).toBeNull();
  });

  it('showBlockConfirm is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showBlockConfirm).toBeNull();
  });

  it('connectedSince is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.connectedSince).toBeNull();
  });

  it('showConnectionInfo is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showConnectionInfo).toBe(false);
  });

  it('showTemplateImport is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showTemplateImport).toBe(false);
  });

  it('collapsedCategories is empty Set', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.collapsedCategories.size).toBe(0);
  });

  it('showRolePopup is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showRolePopup).toBeNull();
  });

  it('showDmChannelCreate is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showDmChannelCreate).toBe(false);
  });

  it('editingMessageId is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.editingMessageId).toBeNull();
  });

  it('editingContent is empty string', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.editingContent).toBe('');
  });

  it('showDeleteConfirm is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.showDeleteConfirm).toBeNull();
  });

  it('replyingTo is null', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.replyingTo).toBeNull();
  });

  it('error is empty string', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.error).toBe('');
  });

  it('newChannelType defaults to "text"', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.newChannelType).toBe('text');
  });

  it('inviteExpiry defaults to "24"', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.inviteExpiry).toBe('24');
  });

  it('joiningNode is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.joiningNode).toBe(false);
  });

  it('creatingNode is false', () => {
    const { result } = renderHook(() => useUIState());
    expect(result.current.creatingNode).toBe(false);
  });
});

// ─── Setter functions ─────────────────────────────────────────────────────────

describe('useUIState — setter functions', () => {
  it('setCustomStatus updates customStatus', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setCustomStatus('Working from home'));
    expect(result.current.customStatus).toBe('Working from home');
  });

  it('setShowStatusPopover toggles visibility', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowStatusPopover(true));
    expect(result.current.showStatusPopover).toBe(true);
    act(() => result.current.setShowStatusPopover(false));
    expect(result.current.showStatusPopover).toBe(false);
  });

  it('setStatusInput updates statusInput', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setStatusInput('Away for lunch'));
    expect(result.current.statusInput).toBe('Away for lunch');
  });

  it('setShowSettings opens settings panel', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowSettings(true));
    expect(result.current.showSettings).toBe(true);
  });

  it('setShowSearchOverlay opens search overlay', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowSearchOverlay(true));
    expect(result.current.showSearchOverlay).toBe(true);
  });

  it('setError sets error message', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setError('Something went wrong'));
    expect(result.current.error).toBe('Something went wrong');
  });

  it('setError can clear error', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setError('error'));
    act(() => result.current.setError(''));
    expect(result.current.error).toBe('');
  });

  it('setNewMessageCount increments count', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setNewMessageCount(5));
    expect(result.current.newMessageCount).toBe(5);
  });

  it('setNewMessageCount resets to 0', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setNewMessageCount(10));
    act(() => result.current.setNewMessageCount(0));
    expect(result.current.newMessageCount).toBe(0);
  });

  it('setConnectedSince records timestamp', () => {
    const { result } = renderHook(() => useUIState());
    const ts = Date.now();
    act(() => result.current.setConnectedSince(ts));
    expect(result.current.connectedSince).toBe(ts);
  });

  it('setConnectedSince can be cleared to null', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setConnectedSince(Date.now()));
    act(() => result.current.setConnectedSince(null));
    expect(result.current.connectedSince).toBeNull();
  });

  it('setContextMenu stores context menu data', () => {
    const { result } = renderHook(() => useUIState());
    const menuData = { x: 100, y: 200, userId: 'u1', publicKeyHash: 'hash', displayName: 'Alice' };
    act(() => result.current.setContextMenu(menuData));
    expect(result.current.contextMenu).toEqual(menuData);
  });

  it('setContextMenu can be cleared to null', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setContextMenu({ x: 0, y: 0, userId: 'u1', publicKeyHash: 'h', displayName: 'A' }));
    act(() => result.current.setContextMenu(null));
    expect(result.current.contextMenu).toBeNull();
  });

  it('setEditingMessageId sets which message is being edited', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setEditingMessageId('msg-123'));
    expect(result.current.editingMessageId).toBe('msg-123');
  });

  it('setEditingContent stores draft edit text', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setEditingContent('Updated message text'));
    expect(result.current.editingContent).toBe('Updated message text');
  });

  it('setShowDeleteConfirm stores message ID to delete', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowDeleteConfirm('msg-456'));
    expect(result.current.showDeleteConfirm).toBe('msg-456');
  });

  it('setShowPinConfirm stores message ID to pin', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowPinConfirm('msg-789'));
    expect(result.current.showPinConfirm).toBe('msg-789');
  });

  it('setShowEmojiPicker stores message ID for reaction picker', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowEmojiPicker('msg-111'));
    expect(result.current.showEmojiPicker).toBe('msg-111');
  });

  it('setHoveredMessageId tracks hovered message', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setHoveredMessageId('msg-222'));
    expect(result.current.hoveredMessageId).toBe('msg-222');
  });

  it('setCollapsedCategories updates collapsed set', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setCollapsedCategories(new Set(['cat-1', 'cat-2'])));
    expect(result.current.collapsedCategories.has('cat-1')).toBe(true);
    expect(result.current.collapsedCategories.has('cat-2')).toBe(true);
  });
});

// ─── Sidebar/panel visibility ─────────────────────────────────────────────────

describe('useUIState — sidebar/panel visibility', () => {
  it('showMemberSidebar can be toggled off', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowMemberSidebar(false));
    expect(result.current.showMemberSidebar).toBe(false);
  });

  it('showMemberSidebar can be toggled back on', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowMemberSidebar(false));
    act(() => result.current.setShowMemberSidebar(true));
    expect(result.current.showMemberSidebar).toBe(true);
  });

  it('setMobileSidebarOpen opens mobile sidebar', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setMobileSidebarOpen(true));
    expect(result.current.mobileSidebarOpen).toBe(true);
  });

  it('setMobileSidebarOpen closes mobile sidebar', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setMobileSidebarOpen(true));
    act(() => result.current.setMobileSidebarOpen(false));
    expect(result.current.mobileSidebarOpen).toBe(false);
  });

  it('setShowPinnedPanel opens pinned messages panel', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowPinnedPanel(true));
    expect(result.current.showPinnedPanel).toBe(true);
  });

  it('setShowPinnedPanel closes pinned messages panel', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowPinnedPanel(true));
    act(() => result.current.setShowPinnedPanel(false));
    expect(result.current.showPinnedPanel).toBe(false);
  });

  it('setShowConnectionInfo opens connection info panel', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowConnectionInfo(true));
    expect(result.current.showConnectionInfo).toBe(true);
  });

  it('setShowScrollToBottom shows scroll indicator', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowScrollToBottom(true));
    expect(result.current.showScrollToBottom).toBe(true);
  });

  it('setShowInputEmojiPicker shows emoji picker for input', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowInputEmojiPicker(true));
    expect(result.current.showInputEmojiPicker).toBe(true);
  });

  it('setShowGifPicker shows GIF picker', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowGifPicker(true));
    expect(result.current.showGifPicker).toBe(true);
  });
});

// ─── Combined/interaction state ───────────────────────────────────────────────

describe('useUIState — combined state interactions', () => {
  it('opening one modal does not affect other modals', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowSettings(true));
    expect(result.current.showSettings).toBe(true);
    expect(result.current.showNodeSettings).toBe(false);
    expect(result.current.showSearchOverlay).toBe(false);
    expect(result.current.showInviteModal).toBe(false);
  });

  it('can open multiple panels simultaneously', () => {
    const { result } = renderHook(() => useUIState());
    act(() => {
      result.current.setShowPinnedPanel(true);
      result.current.setShowMemberSidebar(true);
      result.current.setShowConnectionInfo(true);
    });
    expect(result.current.showPinnedPanel).toBe(true);
    expect(result.current.showMemberSidebar).toBe(true);
    expect(result.current.showConnectionInfo).toBe(true);
  });

  it('editing state: setting messageId and content together', () => {
    const { result } = renderHook(() => useUIState());
    act(() => {
      result.current.setEditingMessageId('msg-edit-1');
      result.current.setEditingContent('New content here');
    });
    expect(result.current.editingMessageId).toBe('msg-edit-1');
    expect(result.current.editingContent).toBe('New content here');
  });

  it('cancelling edit clears both messageId and content', () => {
    const { result } = renderHook(() => useUIState());
    act(() => {
      result.current.setEditingMessageId('msg-edit-1');
      result.current.setEditingContent('Draft');
    });
    act(() => {
      result.current.setEditingMessageId(null);
      result.current.setEditingContent('');
    });
    expect(result.current.editingMessageId).toBeNull();
    expect(result.current.editingContent).toBe('');
  });

  it('node creation flow: setting name, description, and loading state', () => {
    const { result } = renderHook(() => useUIState());
    act(() => {
      result.current.setShowCreateNodeModal(true);
      result.current.setNewNodeName('My Server');
      result.current.setNewNodeDescription('A cool place');
      result.current.setCreatingNode(true);
    });
    expect(result.current.showCreateNodeModal).toBe(true);
    expect(result.current.newNodeName).toBe('My Server');
    expect(result.current.newNodeDescription).toBe('A cool place');
    expect(result.current.creatingNode).toBe(true);
  });

  it('invite flow: generating, setting invite link, and copy state', () => {
    const { result } = renderHook(() => useUIState());
    act(() => {
      result.current.setShowInviteModal(true);
      result.current.setInviteGenerating(true);
    });
    act(() => {
      result.current.setInviteGenerating(false);
      result.current.setGeneratedInvite('accord://abc123/invcode');
      result.current.setInviteCopied(true);
    });
    expect(result.current.showInviteModal).toBe(true);
    expect(result.current.inviteGenerating).toBe(false);
    expect(result.current.generatedInvite).toBe('accord://abc123/invcode');
    expect(result.current.inviteCopied).toBe(true);
  });

  it('join node flow: invite code, loading, and error', () => {
    const { result } = renderHook(() => useUIState());
    act(() => {
      result.current.setShowJoinNodeModal(true);
      result.current.setJoinInviteCode('GAnxnxQV');
      result.current.setJoiningNode(true);
    });
    act(() => {
      result.current.setJoiningNode(false);
      result.current.setJoinError('Invalid invite code');
    });
    expect(result.current.joinInviteCode).toBe('GAnxnxQV');
    expect(result.current.joiningNode).toBe(false);
    expect(result.current.joinError).toBe('Invalid invite code');
  });

  it('channel create flow: name, type, topic, category', () => {
    const { result } = renderHook(() => useUIState());
    act(() => {
      result.current.setShowCreateChannelForm(true);
      result.current.setNewChannelName('announcements');
      result.current.setNewChannelType('text');
      result.current.setNewChannelTopic('Official announcements');
      result.current.setNewChannelCategoryId('cat-1');
    });
    expect(result.current.showCreateChannelForm).toBe(true);
    expect(result.current.newChannelName).toBe('announcements');
    expect(result.current.newChannelType).toBe('text');
    expect(result.current.newChannelTopic).toBe('Official announcements');
    expect(result.current.newChannelCategoryId).toBe('cat-1');
  });

  it('collapsedCategories loads from localStorage on init', () => {
    localStorage.setItem('accord_collapsed_categories', JSON.stringify(['cat-A', 'cat-B']));
    const { result } = renderHook(() => useUIState());
    expect(result.current.collapsedCategories.has('cat-A')).toBe(true);
    expect(result.current.collapsedCategories.has('cat-B')).toBe(true);
  });

  it('collapsedCategories falls back to empty set when localStorage is corrupt', () => {
    localStorage.setItem('accord_collapsed_categories', '{bad json');
    const { result } = renderHook(() => useUIState());
    expect(result.current.collapsedCategories.size).toBe(0);
  });

  it('profileCardTarget stores user info for profile card display', () => {
    const { result } = renderHook(() => useUIState());
    const target = { userId: 'u1', x: 50, y: 100 };
    act(() => result.current.setProfileCardTarget(target));
    expect(result.current.profileCardTarget).toEqual(target);
  });

  it('showBlockConfirm stores user info for confirmation dialog', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowBlockConfirm({ userId: 'u1', displayName: 'Alice' }));
    expect(result.current.showBlockConfirm?.userId).toBe('u1');
    expect(result.current.showBlockConfirm?.displayName).toBe('Alice');
  });

  it('template import flow: input, loading, result, error', () => {
    const { result } = renderHook(() => useUIState());
    act(() => {
      result.current.setShowTemplateImport(true);
      result.current.setTemplateInput('{"channels":[]}');
      result.current.setTemplateImporting(true);
    });
    act(() => {
      result.current.setTemplateImporting(false);
      result.current.setTemplateResult({ imported: 3 });
    });
    expect(result.current.showTemplateImport).toBe(true);
    expect(result.current.templateInput).toBe('{"channels":[]}');
    expect(result.current.templateImporting).toBe(false);
    expect(result.current.templateResult).toEqual({ imported: 3 });
  });

  it('setTemplateError stores error message', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setTemplateError('Invalid template JSON'));
    expect(result.current.templateError).toBe('Invalid template JSON');
  });

  it('showRolePopup stores position and userId', () => {
    const { result } = renderHook(() => useUIState());
    act(() => result.current.setShowRolePopup({ userId: 'u1', x: 10, y: 20 }));
    expect(result.current.showRolePopup?.userId).toBe('u1');
    expect(result.current.showRolePopup?.x).toBe(10);
  });
});
