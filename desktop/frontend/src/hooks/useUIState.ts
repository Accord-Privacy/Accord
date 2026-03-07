import { useState } from "react";
import type { Message, Role } from "../types";

/** Consolidates all UI toggle/modal states that don't have complex logic. */
export function useUIState() {
  // Custom status
  const [customStatus, setCustomStatus] = useState<string>("");
  const [showStatusPopover, setShowStatusPopover] = useState(false);
  const [statusInput, setStatusInput] = useState("");

  // Pinned messages
  const [showPinnedPanel, setShowPinnedPanel] = useState(false);
  const [pinnedMessages, setPinnedMessages] = useState<Message[]>([]);
  const [showPinConfirm, setShowPinConfirm] = useState<string | null>(null);

  // Thread
  const [threadParentMessage, setThreadParentMessage] = useState<Message | null>(null);
  const [threadMessages, setThreadMessages] = useState<Message[]>([]);
  const [threadLoading, setThreadLoading] = useState(false);

  // Reaction emoji picker
  const [showEmojiPicker, setShowEmojiPicker] = useState<string | null>(null);
  const [hoveredMessageId, setHoveredMessageId] = useState<string | null>(null);

  // Notifications
  const [showNotificationSettings, setShowNotificationSettings] = useState(false);

  // Search
  const [showSearchOverlay, setShowSearchOverlay] = useState(false);

  // Node creation modals
  const [showJoinNodeModal, setShowJoinNodeModal] = useState(false);
  const [showCreateNodeModal, setShowCreateNodeModal] = useState(false);
  const [joinInviteCode, setJoinInviteCode] = useState("");
  const [joiningNode, setJoiningNode] = useState(false);
  const [joinError, setJoinError] = useState("");
  const [newNodeName, setNewNodeName] = useState("");
  const [newNodeDescription, setNewNodeDescription] = useState("");
  const [creatingNode, setCreatingNode] = useState(false);

  // Settings
  const [showSettings, setShowSettings] = useState(false);
  const [showNodeSettings, setShowNodeSettings] = useState(false);

  // Channel create/delete
  const [showCreateChannelForm, setShowCreateChannelForm] = useState(false);
  const [newChannelName, setNewChannelName] = useState("");
  const [newChannelType, setNewChannelType] = useState("text");
  const [newChannelTopic, setNewChannelTopic] = useState("");
  const [newChannelCategoryId, setNewChannelCategoryId] = useState("");
  const [deleteChannelConfirm, setDeleteChannelConfirm] = useState<{ id: string; name: string } | null>(null);

  // Invite modal
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [generatedInvite, setGeneratedInvite] = useState<string>("");
  const [inviteExpiry, setInviteExpiry] = useState<string>("24");
  const [inviteMaxUses, setInviteMaxUses] = useState<string>("");
  const [inviteCopied, setInviteCopied] = useState(false);
  const [inviteGenerating, setInviteGenerating] = useState(false);

  // Display name prompt
  const [showDisplayNamePrompt, setShowDisplayNamePrompt] = useState(false);
  const [displayNameInput, setDisplayNameInput] = useState("");
  const [displayNameSaving, setDisplayNameSaving] = useState(false);

  // Keyboard shortcuts help
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false);

  // Mobile sidebar toggle
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  // Member sidebar
  const [showMemberSidebar, setShowMemberSidebar] = useState(true);

  // Message input emoji picker + staged files
  const [showInputEmojiPicker, setShowInputEmojiPicker] = useState(false);

  // Scroll-to-bottom
  const [showScrollToBottom, setShowScrollToBottom] = useState(false);
  const [newMessageCount, setNewMessageCount] = useState(0);

  // Context menu
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; userId: string; publicKeyHash: string; displayName: string; bio?: string; user?: import("../types").User } | null>(null);

  // Profile card
  const [profileCardTarget, setProfileCardTarget] = useState<{ userId: string; x: number; y: number; user?: import("../types").User; profile?: import("../types").UserProfile; roles?: Role[]; joinedAt?: number; roleColor?: string } | null>(null);

  // Block confirm
  const [showBlockConfirm, setShowBlockConfirm] = useState<{ userId: string; displayName: string } | null>(null);

  // Connection info
  const [connectedSince, setConnectedSince] = useState<number | null>(null);
  const [showConnectionInfo, setShowConnectionInfo] = useState(false);

  // Template import
  const [showTemplateImport, setShowTemplateImport] = useState(false);
  const [templateInput, setTemplateInput] = useState('');
  const [templateImporting, setTemplateImporting] = useState(false);
  const [templateResult, setTemplateResult] = useState<any>(null);
  const [templateError, setTemplateError] = useState('');

  // Category collapse
  const [collapsedCategories, setCollapsedCategories] = useState<Set<string>>(new Set());

  // Role popup
  const [showRolePopup, setShowRolePopup] = useState<{ userId: string; x: number; y: number } | null>(null);

  // DM channel create
  const [showDmChannelCreate, setShowDmChannelCreate] = useState(false);

  // Message editing
  const [editingMessageId, setEditingMessageId] = useState<string | null>(null);
  const [editingContent, setEditingContent] = useState("");
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<string | null>(null);

  // Reply
  const [replyingTo, setReplyingTo] = useState<Message | null>(null);

  // Error banner
  const [error, setError] = useState<string>("");

  return {
    customStatus, setCustomStatus,
    showStatusPopover, setShowStatusPopover,
    statusInput, setStatusInput,
    showPinnedPanel, setShowPinnedPanel,
    pinnedMessages, setPinnedMessages,
    showPinConfirm, setShowPinConfirm,
    threadParentMessage, setThreadParentMessage,
    threadMessages, setThreadMessages,
    threadLoading, setThreadLoading,
    showEmojiPicker, setShowEmojiPicker,
    hoveredMessageId, setHoveredMessageId,
    showNotificationSettings, setShowNotificationSettings,
    showSearchOverlay, setShowSearchOverlay,
    showJoinNodeModal, setShowJoinNodeModal,
    showCreateNodeModal, setShowCreateNodeModal,
    joinInviteCode, setJoinInviteCode,
    joiningNode, setJoiningNode,
    joinError, setJoinError,
    newNodeName, setNewNodeName,
    newNodeDescription, setNewNodeDescription,
    creatingNode, setCreatingNode,
    showSettings, setShowSettings,
    showNodeSettings, setShowNodeSettings,
    showCreateChannelForm, setShowCreateChannelForm,
    newChannelName, setNewChannelName,
    newChannelType, setNewChannelType,
    newChannelTopic, setNewChannelTopic,
    newChannelCategoryId, setNewChannelCategoryId,
    deleteChannelConfirm, setDeleteChannelConfirm,
    showInviteModal, setShowInviteModal,
    generatedInvite, setGeneratedInvite,
    inviteExpiry, setInviteExpiry,
    inviteMaxUses, setInviteMaxUses,
    inviteCopied, setInviteCopied,
    inviteGenerating, setInviteGenerating,
    showDisplayNamePrompt, setShowDisplayNamePrompt,
    displayNameInput, setDisplayNameInput,
    displayNameSaving, setDisplayNameSaving,
    showShortcutsHelp, setShowShortcutsHelp,
    mobileSidebarOpen, setMobileSidebarOpen,
    showMemberSidebar, setShowMemberSidebar,
    showInputEmojiPicker, setShowInputEmojiPicker,
    showScrollToBottom, setShowScrollToBottom,
    newMessageCount, setNewMessageCount,
    contextMenu, setContextMenu,
    profileCardTarget, setProfileCardTarget,
    showBlockConfirm, setShowBlockConfirm,
    connectedSince, setConnectedSince,
    showConnectionInfo, setShowConnectionInfo,
    showTemplateImport, setShowTemplateImport,
    templateInput, setTemplateInput,
    templateImporting, setTemplateImporting,
    templateResult, setTemplateResult,
    templateError, setTemplateError,
    collapsedCategories, setCollapsedCategories,
    showRolePopup, setShowRolePopup,
    showDmChannelCreate, setShowDmChannelCreate,
    editingMessageId, setEditingMessageId,
    editingContent, setEditingContent,
    showDeleteConfirm, setShowDeleteConfirm,
    replyingTo, setReplyingTo,
    error, setError,
  };
}
