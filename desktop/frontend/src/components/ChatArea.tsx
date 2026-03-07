import React, { Suspense, useState, useCallback, useEffect, useMemo, useRef } from "react";
import { useAppContext } from "./AppContext";
import { Icon } from "./Icon";
import { avatarColor } from "../avatarColor";
import { api, parseInviteLink } from "../api";
import { verifyBuildHash, getTrustIndicator } from "../buildHash";
import { notificationManager } from "../notifications";
import { renderMessageMarkdown } from "../markdown";
import { FileUploadButton, FileList, FileDropZone, FileAttachment, StagedFilesPreview } from "../FileManager";
import { EmojiPickerButton } from "../EmojiPicker";
import { GifPickerButton } from "../GifPicker";
import { getNodeCustomEmojis, getCustomEmojiUrl, subscribeCustomEmojis } from "../customEmojiStore";
import { LinkPreview, extractAllUrls } from "../LinkPreview";
import { LoadingSpinner } from "../LoadingSpinner";
import { ConnectionBanner } from "./ConnectionBanner";
import { SlashCommandAutocomplete, CommandParamForm, BotResponseRenderer } from "./BotPanel";
import { MentionAutocomplete } from "./MentionAutocomplete";
import { SlashCommandPopup } from "./SlashCommandPopup";
import { useMentionAutocomplete } from "../hooks/useMentionAutocomplete";
import type { AutocompleteItem } from "../hooks/useMentionAutocomplete";
import { useSlashCommands } from "../hooks/useSlashCommands";
import { ImageLightbox } from "./ImageLightbox";
import { ImageGrid, getNonImageFiles, hasImageGrid } from "./ImageGrid";
import { MediaEmbeds } from "./MediaEmbeds";
import { MessageContextMenu } from "./MessageContextMenu";
import { SavedMessagesPanel } from "./SavedMessagesPanel";
import { MessagePreview } from "./MessagePreview";
import { useBookmarks } from "../hooks/useBookmarks";
import type { InstalledBot, BotCommand } from "../types";
const VoiceChat = React.lazy(() => import("../VoiceChat").then(m => ({ default: m.VoiceChat })));

export const ChatArea: React.FC = () => {
  const ctx = useAppContext();
  const [customEmojis, setCustomEmojisState] = useState(getNodeCustomEmojis());
  useEffect(() => subscribeCustomEmojis(() => setCustomEmojisState(getNodeCustomEmojis())), []);
  const [pendingCommand, setPendingCommand] = useState<{ bot: InstalledBot; command: BotCommand } | null>(null);
  const [showSlashMenu, setShowSlashMenu] = useState(false);
  const [slashQuery, setSlashQuery] = useState('');
  const [showFormattingToolbar, setShowFormattingToolbar] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [lightboxSrc, setLightboxSrc] = useState<string | null>(null);
  const [unreadMarkerId, setUnreadMarkerId] = useState<string | null>(null);
  const [showSavedMessages, setShowSavedMessages] = useState(false);
  const { bookmarks, addBookmark, removeBookmark, isBookmarked } = useBookmarks();
  const [showTopicEdit, setShowTopicEdit] = useState(false);
  const [topicDraft, setTopicDraft] = useState('');
  const [topicSaving, setTopicSaving] = useState(false);
  const topicInputRef = useRef<HTMLTextAreaElement>(null);

  // Build autocomplete items for @mentions and #channels
  const mentionUsers = useMemo<AutocompleteItem[]>(() =>
    ctx.members.map(m => ({
      type: 'user' as const,
      id: m.user_id,
      label: ctx.displayName(m.user),
      subtitle: m.role,
      avatarUrl: m.user_id ? api.getUserAvatarUrl(m.user_id) : undefined,
      avatarColor: avatarColor(m.user_id || ''),
      insertText: `@${ctx.displayName(m.user)}`,
    })),
    [ctx.members, ctx]
  );

  const mentionChannels = useMemo<AutocompleteItem[]>(() =>
    ctx.channels
      .filter(c => c.channel_type !== 'category' && c.channel_type !== 'voice')
      .map(c => ({
        type: 'channel' as const,
        id: c.id,
        label: c.name,
        insertText: `#${c.name}`,
      })),
    [ctx.channels]
  );

  const {
    mentionState,
    handleMentionInput,
    handleMentionKeyDown,
    selectMentionItem,
    dismissMention,
  } = useMentionAutocomplete(mentionUsers, mentionChannels);

  const slashCallbacks = useMemo(() => ({
    onNick: (name: string) => {
      if (ctx.appState.token) {
        api.updateProfile({ display_name: name }, ctx.appState.token).catch(err =>
          console.error('Failed to update display name:', err)
        );
      }
    },
    onStatus: (text: string) => {
      if (ctx.appState.token) {
        api.updateProfile({ status: text as any }, ctx.appState.token).catch(err =>
          console.error('Failed to set status:', err)
        );
      }
    },
    onClear: () => {
      ctx.setAppState(prev => ({ ...prev, messages: [] }));
    },
  }), [ctx]);

  const {
    slashState,
    handleSlashInput,
    handleSlashKeyDown,
    selectSlashItem,
    dismissSlash,
    processSlashCommand,
  } = useSlashCommands(slashCallbacks);

  const wrapSelection = useCallback((prefix: string, suffix: string) => {
    const textarea = ctx.messageInputRef?.current;
    if (!textarea) return;
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const text = ctx.message;
    const selected = text.substring(start, end);
    const newText = text.substring(0, start) + prefix + selected + suffix + text.substring(end);
    ctx.setMessage(newText);
    // Restore cursor after the wrapped selection
    requestAnimationFrame(() => {
      textarea.focus();
      textarea.selectionStart = start + prefix.length;
      textarea.selectionEnd = end + prefix.length;
    });
  }, [ctx]);

  const handleSlashSelect = useCallback((bot: InstalledBot, command: BotCommand) => {
    setShowSlashMenu(false);
    if (command.params.length > 0) {
      setPendingCommand({ bot, command });
    } else {
      ctx.handleInvokeBot(bot.bot_id, command.name, {});
    }
    ctx.setMessage('');
  }, [ctx]);

  const handleCommandSubmit = useCallback((params: Record<string, any>) => {
    if (pendingCommand) {
      ctx.handleInvokeBot(pendingCommand.bot.bot_id, pendingCommand.command.name, params);
      setPendingCommand(null);
    }
  }, [pendingCommand, ctx]);

  const handleToggleBookmark = useCallback((msg: import('../types').Message) => {
    if (isBookmarked(msg.id)) {
      removeBookmark(msg.id);
    } else {
      const channelId = msg.channel_id || ctx.selectedDmChannel?.id || ctx.selectedChannelId || '';
      const channelName = ctx.selectedDmChannel
        ? ctx.selectedDmChannel.other_user_profile.display_name
        : ctx.activeChannel || '';
      addBookmark({
        id: msg.id,
        content: msg.content,
        channelId,
        channelName,
        author: msg.author,
        timestamp: msg.timestamp,
        savedAt: Date.now(),
      });
    }
  }, [isBookmarked, removeBookmark, addBookmark, ctx]);

  const handleJumpToBookmark = useCallback((channelId: string, messageId: string) => {
    // Switch channel if needed, then scroll
    if (channelId && channelId !== ctx.selectedChannelId && !ctx.selectedDmChannel) {
      const ch = ctx.channels.find(c => c.id === channelId);
      if (ch) {
        ctx.handleChannelSelect(ch.id, ch.name);
      }
    }
    setShowSavedMessages(false);
    // Give channel switch time to load messages
    setTimeout(() => ctx.scrollToMessage(messageId), 300);
  }, [ctx]);

  const formatRelativeTime = (ts: number) => {
    const diff = Date.now() - ts;
    if (diff < 60000) return 'just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const formatDateSep = (d: Date) => {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const msgDay = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const diff = today.getTime() - msgDay.getTime();
    if (diff === 0) return 'Today';
    if (diff === 86400000) return 'Yesterday';
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
  };

  const currentCh = ctx.selectedDmChannel?.id || ctx.selectedChannelId;
  const filteredMessages = useMemo(() => ctx.appState.messages.filter(msg => {
    if (currentCh && msg.channel_id && msg.channel_id !== currentCh) return false;
    if (msg.sender_id && ctx.blockedUsers.has(msg.sender_id)) return false;
    return true;
  }), [ctx.appState.messages, currentCh, ctx.blockedUsers]);

  // Collect all clickable image srcs from the messages DOM for gallery navigation
  const [allChannelImages, setAllChannelImages] = useState<string[]>([]);
  const collectImages = useCallback(() => {
    const container = ctx.messagesContainerRef?.current;
    if (!container) return [];
    const imgs = container.querySelectorAll('.message-content img, .file-attachment-image-preview img, .message-image-grid img');
    return Array.from(imgs).map(img => (img as HTMLImageElement).src).filter(Boolean);
  }, [ctx.messagesContainerRef]);

  // Invite preview state
  const [invitePreview, setInvitePreview] = useState<{
    node_name: string;
    node_id: string;
    member_count: number;
    server_build_hash: string;
  } | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState("");

  const handlePreviewInvite = useCallback(async () => {
    const input = ctx.inviteLinkInput?.trim();
    if (!input) return;
    const parsed = parseInviteLink(input);
    if (!parsed) {
      setPreviewError("Invalid invite link format");
      return;
    }
    setPreviewLoading(true);
    setPreviewError("");
    try {
      const preview = await api.previewInvite(parsed.relayUrl, parsed.inviteCode);
      setInvitePreview(preview);
    } catch (e: any) {
      setPreviewError(e.message || "Failed to fetch invite preview");
    } finally {
      setPreviewLoading(false);
    }
  }, [ctx.inviteLinkInput]);

  // Empty state: no nodes joined yet
  if (ctx.nodes.length === 0 && !ctx.selectedDmChannel) {
    return (
      <>
        <div className="chat-area chat-area-centered">
          <div className="welcome-card">
            {invitePreview ? (
              <>
                <h2>{invitePreview.node_name}</h2>
                <div className="welcome-card-id">
                  {invitePreview.node_id.substring(0, 16)}
                </div>
                <div className="welcome-card-members">
                  {invitePreview.member_count} member{invitePreview.member_count !== 1 ? 's' : ''}
                </div>
                <div className="welcome-card-trust">
                  {(() => {
                    const trust = verifyBuildHash(invitePreview.server_build_hash, ctx.knownHashes);
                    const indicator = getTrustIndicator(trust);
                    return (
                      <span style={{ color: indicator.color }}>
                        {indicator.emoji} {indicator.label}
                      </span>
                    );
                  })()}
                </div>
                <div className="welcome-card-actions">
                  <button
                    className="btn btn-outline btn-auto-width"
                    onClick={() => { setInvitePreview(null); setPreviewError(""); }}
                  >
                    Cancel
                  </button>
                  <button
                    className="btn btn-primary btn-auto-width"
                    onClick={async () => {
                      setInvitePreview(null);
                      // Use handleJoinNode which handles same-relay join properly
                      if (ctx.joinInviteCode !== undefined) {
                        // joinInviteCode is already set from inviteLinkInput
                      }
                      // Directly join via the parsed invite
                      const input = ctx.inviteLinkInput?.trim();
                      if (!input) return;
                      const parsed = parseInviteLink(input);
                      const code = parsed ? parsed.inviteCode : input;
                      try {
                        let token = ctx.appState.token;
                        if (!token) {
                          setPreviewError("Not authenticated");
                          return;
                        }
                        api.setToken(token);
                        await api.joinNodeByInvite(code, token);
                        ctx.setInviteLinkInput('');
                        // Reload nodes
                        if (ctx.loadNodes) ctx.loadNodes();
                      } catch (e: any) {
                        setPreviewError(e.message || "Failed to join node");
                      }
                    }}
                  >
                    Join
                  </button>
                </div>
              </>
            ) : (
              <>
                <h2 className="welcome-title">Welcome to Accord!</h2>
                <p className="welcome-subtitle">
                  Join a Node to start chatting. Paste an invite link below.
                </p>
                {previewError && (
                  <p className="welcome-error">{previewError}</p>
                )}
                <div className="welcome-form">
                  <input
                    type="text"
                    placeholder="Paste invite link here..."
                    value={ctx.inviteLinkInput ?? ''}
                    onChange={(e) => ctx.setInviteLinkInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handlePreviewInvite(); }}
                    className="form-input"
                  />
                  <button
                    className="btn btn-primary"
                    onClick={handlePreviewInvite}
                    disabled={!ctx.inviteLinkInput?.trim() || previewLoading}
                  >
                    {previewLoading ? '...' : 'Preview →'}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <div className="chat-area">
        <FileDropZone
          channelId={ctx.selectedDmChannel?.id || ctx.selectedChannelId || ''}
          token={ctx.appState.token || ''}
          keyPair={ctx.keyPair}
          encryptionEnabled={ctx.encryptionEnabled}
          onFilesStaged={ctx.handleFilesStaged}
        >
          {/* Chat Header */}
          <div className="chat-header">
            <button
              className="mobile-hamburger"
              onClick={() => ctx.setMobileSidebarOpen(o => !o)}
              aria-label="Toggle sidebar"
            >☰</button>
            <div className="chat-header-left">
              {ctx.selectedDmChannel ? (
                <>
                  <div className="chat-header-dm">
                    <div className="dm-avatar dm-avatar-sm" style={{ background: avatarColor(ctx.selectedDmChannel.other_user?.id || '') }}>
                      {ctx.selectedDmChannel.other_user?.id ? (
                        <img
                          src={`${api.getUserAvatarUrl(ctx.selectedDmChannel.other_user.id)}`}
                          alt={(ctx.selectedDmChannel.other_user_profile?.display_name || "?")[0]}
                          onError={(e) => { const img = e.target as HTMLImageElement; img.style.display = 'none'; if (img.parentElement) img.parentElement.textContent = (ctx.selectedDmChannel!.other_user_profile?.display_name || "?")[0].toUpperCase(); }}
                        />
                      ) : (ctx.selectedDmChannel.other_user_profile?.display_name || "?")[0].toUpperCase()}
                      <span className={`presence-dot presence-${ctx.getPresenceStatus(ctx.selectedDmChannel.other_user?.id || '')}`} />
                    </div>
                    <span className="chat-channel-name">{ctx.selectedDmChannel.other_user_profile.display_name}</span>
                  </div>
                  <span className="chat-topic">
                    Direct message with {ctx.selectedDmChannel.other_user_profile.display_name}
                  </span>
                </>
              ) : (
                <>
                  <span className="chat-channel-icon"><Icon name="hash" size={20} /></span>
                  <span className="chat-channel-name">{ctx.activeChannel}</span>
                  {(() => {
                    const ch = ctx.channels.find(c => c.id === ctx.selectedChannelId);
                    const topicText = ch?.channel_type === 'voice' ? `Voice channel — ${ch.name}` : (ch?.topic || '');
                    const canEdit = ctx.selectedNodeId ? ctx.hasPermission(ctx.selectedNodeId, 'ManageNode') : false;
                    if (!topicText && !canEdit) return null;
                    return (
                      <span
                        className={`chat-topic ${canEdit ? 'chat-topic-editable' : ''}`}
                        title={topicText || 'Click to set a topic'}
                        onClick={() => {
                          if (!canEdit) return;
                          setTopicDraft(ch?.topic || '');
                          setShowTopicEdit(true);
                          setTimeout(() => topicInputRef.current?.focus(), 50);
                        }}
                      >
                        {topicText || (canEdit ? 'Set a topic' : '')}
                      </span>
                    );
                  })()}
                  {ctx.slowModeSeconds > 0 && (
                    <span className="slow-mode-indicator" title={`Slow mode: ${ctx.slowModeSeconds}s cooldown`}>
                      <Icon name="clock" size={14} /> {ctx.slowModeSeconds}s
                    </span>
                  )}
                </>
              )}
            </div>
            <div className="chat-header-right">
              <button onClick={ctx.togglePinnedPanel} className={`chat-header-btn ${ctx.showPinnedPanel ? 'active' : ''}`} title="Pinned Messages" aria-label="Pinned Messages" aria-pressed={ctx.showPinnedPanel}>
                <Icon name="pin" size={20} />
                {ctx.pinnedMessages.length > 0 && <span className="pin-count-badge">{ctx.pinnedMessages.length}</span>}
              </button>
              <button onClick={() => setShowSavedMessages(s => !s)} className={`chat-header-btn ${showSavedMessages ? 'active' : ''}`} title="Saved Messages" aria-label="Saved Messages" aria-pressed={showSavedMessages}>
                <Icon name="bookmark" size={20} />
                {bookmarks.length > 0 && <span className="pin-count-badge">{bookmarks.length}</span>}
              </button>
              {ctx.encryptionEnabled && ctx.keyPair && (
                <span className="e2ee-indicator" title="End-to-end encrypted"><Icon name="lock" size={14} /> E2EE</span>
              )}
              {ctx.encryptionEnabled && !ctx.keyPair && ctx.hasExistingKey && (
                <span className="e2ee-indicator e2ee-indicator-warning" title="Key stored but locked">Key Locked</span>
              )}
              {ctx.encryptionEnabled && !ctx.keyPair && !ctx.hasExistingKey && (
                <span className="e2ee-indicator disabled" title="No encryption keys found">No Keys</span>
              )}
              {!ctx.encryptionEnabled && (
                <span className="e2ee-indicator disabled" title="Encryption not supported">No E2EE</span>
              )}
              <button
                className="chat-header-btn"
                onClick={() => ctx.setShowSearchOverlay(true)}
                title="Search (Ctrl+K)"
                aria-label="Search messages"
              >
                <Icon name="search" size={20} />
              </button>
              <button
                onClick={() => ctx.setShowMemberSidebar(prev => !prev)}
                className={`chat-header-btn ${ctx.showMemberSidebar ? 'active' : ''}`}
                title="Member List"
                aria-label="Toggle member list"
                aria-pressed={ctx.showMemberSidebar}
              >
                <Icon name="members" size={20} />
              </button>
            </div>
          </div>

          {/* Connection status banner */}
          <ConnectionBanner
            connectionInfo={ctx.connectionInfo}
            onRetry={() => ctx.ws?.retry()}
          />

          {/* New messages banner */}
          {ctx.newMessageCount > 0 && ctx.showScrollToBottom && (
            <div className="unread-banner" onClick={ctx.scrollToBottom}>
              {ctx.newMessageCount} new message{ctx.newMessageCount !== 1 ? 's' : ''} — Click to jump
            </div>
          )}

          {/* Messages */}
          <div 
            className={`messages ${ctx.voiceChannelId ? 'with-voice' : ''} density-${ctx.messageDensity}`}
            ref={ctx.messagesContainerRef}
            onScroll={ctx.handleScroll}
            role="log"
            aria-label="Messages"
            aria-live="polite"
            onClick={(e) => {
              const target = e.target as HTMLElement;
              if (target.tagName === 'IMG' && (target.closest('.message-content') || target.closest('.file-attachment-image-preview') || target.closest('.message-image-grid'))) {
                e.stopPropagation();
                setAllChannelImages(collectImages());
                setLightboxSrc((target as HTMLImageElement).src);
              }
              // Handle @mention clicks — open profile card
              const mentionUser = target.closest('[data-mention-user]');
              if (mentionUser) {
                const mentionText = mentionUser.getAttribute('data-mention-user') || '';
                const name = mentionText.startsWith('@') ? mentionText.substring(1) : mentionText;
                const member = ctx.members.find(m =>
                  ctx.displayName(m.user) === name ||
                  ctx.fingerprint(m.public_key_hash) === name
                );
                if (member) {
                  ctx.setProfileCardTarget({
                    userId: member.user_id,
                    x: e.clientX,
                    y: e.clientY,
                    user: member.user,
                    profile: member.profile,
                    roles: ctx.memberRolesMap[member.user_id],
                    joinedAt: member.joined_at,
                    roleColor: ctx.getMemberRoleColor(member.user_id),
                  });
                }
              }
              // Handle #channel clicks — switch to that channel
              const mentionChannel = target.closest('[data-mention-channel]');
              if (mentionChannel) {
                const chName = (mentionChannel.getAttribute('data-mention-channel') || '').replace(/^#/, '');
                const ch = ctx.channels.find(c => c.name === chName);
                if (ch) {
                  ctx.handleChannelSelect(ch.id, ch.name);
                }
              }
            }}
          >
            {ctx.isLoadingOlderMessages && (
              <div className="messages-loading"><span className="spinner spinner-sm"></span> Loading older messages...</div>
            )}
            {!ctx.hasMoreMessages && ctx.appState.messages.length > 0 && (
              ctx.selectedDmChannel ? (
                <div className="messages-beginning dm-beginning">
                  <div className="dm-beginning-avatar" style={{ background: avatarColor(ctx.selectedDmChannel.other_user?.id || '') }}>
                    {ctx.selectedDmChannel.other_user?.id ? (
                      <img
                        src={`${api.getUserAvatarUrl(ctx.selectedDmChannel.other_user.id)}`}
                        alt={(ctx.selectedDmChannel.other_user_profile?.display_name || "?")[0]}
                        onError={(e) => { const img = e.target as HTMLImageElement; img.style.display = 'none'; if (img.parentElement) img.parentElement.textContent = (ctx.selectedDmChannel!.other_user_profile?.display_name || "?")[0].toUpperCase(); }}
                      />
                    ) : (ctx.selectedDmChannel.other_user_profile?.display_name || "?")[0].toUpperCase()}
                  </div>
                  <div className="messages-beginning-title">{ctx.selectedDmChannel.other_user_profile.display_name}</div>
                  <div className="messages-beginning-subtitle">This is the beginning of your direct message history with <strong>{ctx.selectedDmChannel.other_user_profile.display_name}</strong>.</div>
                </div>
              ) : (
                <div className="messages-beginning">
                  <div className="messages-beginning-title">Welcome to {ctx.activeChannel || '# general'}!</div>
                  <div className="messages-beginning-subtitle">This is the start of the <strong>{ctx.activeChannel || '# general'}</strong> channel.</div>
                </div>
              )
            )}
            {!ctx.isLoadingOlderMessages && ctx.appState.messages.length === 0 && (ctx.selectedChannelId || ctx.selectedDmChannel) && (
              ctx.selectedDmChannel ? (
                <div className="empty-state dm-empty-state">
                  <div className="dm-beginning-avatar" style={{ background: avatarColor(ctx.selectedDmChannel.other_user?.id || '') }}>
                    {ctx.selectedDmChannel.other_user?.id ? (
                      <img
                        src={`${api.getUserAvatarUrl(ctx.selectedDmChannel.other_user.id)}`}
                        alt={(ctx.selectedDmChannel.other_user_profile?.display_name || "?")[0]}
                        onError={(e) => { const img = e.target as HTMLImageElement; img.style.display = 'none'; if (img.parentElement) img.parentElement.textContent = (ctx.selectedDmChannel!.other_user_profile?.display_name || "?")[0].toUpperCase(); }}
                      />
                    ) : (ctx.selectedDmChannel.other_user_profile?.display_name || "?")[0].toUpperCase()}
                  </div>
                  <div className="empty-state-title">{ctx.selectedDmChannel.other_user_profile.display_name}</div>
                  <div className="empty-state-text">This is the beginning of your direct message history with <strong>{ctx.selectedDmChannel.other_user_profile.display_name}</strong>.</div>
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-icon"><Icon name="chat-filled" size={48} /></div>
                  <div className="empty-state-title">No messages yet</div>
                  <div className="empty-state-text">Be the first to send a message in this channel!</div>
                </div>
              )
            )}
            {!ctx.selectedChannelId && !ctx.selectedDmChannel && ctx.channels.length === 0 && ctx.nodes.length > 0 && (
              <div className="empty-state">
                <div className="empty-state-icon"><Icon name="hash" size={48} /></div>
                <div className="empty-state-title">No channels</div>
                <div className="empty-state-text">Create a channel to start chatting.</div>
              </div>
            )}
            {ctx.nodes.length === 0 && !ctx.selectedDmChannel && (
              <div className="empty-state">
                <div className="empty-state-icon"><Icon name="bolt" size={48} /></div>
                <div className="empty-state-title">Welcome to Accord</div>
                <div className="empty-state-text">Join a node via invite or create your own to get started.</div>
              </div>
            )}

            {filteredMessages.map((msg, i) => {
              const prevMsg = i > 0 ? filteredMessages[i - 1] : null;
              const isGrouped = prevMsg
                && prevMsg.author === msg.author
                && Math.abs(msg.timestamp - prevMsg.timestamp) < 5 * 60 * 1000
                && !msg.reply_to;

              const msgDate = new Date(msg.timestamp);
              const prevDate = prevMsg ? new Date(prevMsg.timestamp) : null;
              const showDateSep = !prevDate || msgDate.toDateString() !== prevDate.toDateString();

              return (
                <React.Fragment key={msg.id || i}>
                  {showDateSep && (
                    <div className="date-separator">
                      <span className="date-separator-text">{formatDateSep(msgDate)}</span>
                    </div>
                  )}
                  {unreadMarkerId === msg.id && (
                    <div className="unread-marker">
                      <span className="unread-marker-text">New</span>
                    </div>
                  )}
                  <MessageContextMenu message={msg} onMarkUnread={setUnreadMarkerId} isBookmarked={isBookmarked(msg.id)} onToggleBookmark={handleToggleBookmark}>
                  <div className={`message ${msg.reply_to ? 'reply-message' : ''} ${isGrouped ? 'message-grouped message-compact' : ''}`} data-message-id={msg.id} role="article" aria-label={`Message from ${msg.author}`}>
                    {/* Reply preview */}
                    {msg.replied_message && (
                      <div className="reply-preview" onClick={() => ctx.scrollToMessage(msg.reply_to!)}>
                        <div className="reply-bar"></div>
                        <div className="reply-content">
                          <span className="reply-author">
                            <img
                              className="reply-avatar"
                              src={api.getUserAvatarUrl(msg.replied_message.sender_id)}
                              alt=""
                              onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }}
                            />
                            {(() => {
                              const member = ctx.members.find(m => m.user_id === msg.replied_message!.sender_id);
                              return member ? ctx.displayName(member.user) : (msg.replied_message!.sender_public_key_hash ? ctx.fingerprint(msg.replied_message!.sender_public_key_hash) : msg.replied_message!.sender_id);
                            })()}
                          </span>
                          <span className="reply-snippet">{msg.replied_message.content || '(encrypted message)'}</span>
                        </div>
                      </div>
                    )}

                    {!isGrouped && <div className="message-avatar" style={{ background: avatarColor(msg.sender_id || msg.author || '') }}>
                      {msg.sender_id ? (
                        <img 
                          src={`${api.getUserAvatarUrl(msg.sender_id)}`}
                          alt={(msg.author || "?")[0]}
                          onError={(e) => { const img = e.target as HTMLImageElement; img.style.display = 'none'; img.removeAttribute('src'); if (img.parentElement) img.parentElement.textContent = (msg.author || "?")[0]; }}
                        />
                      ) : (msg.author || "?")[0]}
                    </div>}
                    {isGrouped && <div className="message-avatar-spacer"><span className="message-hover-time" title={new Date(msg.timestamp).toLocaleString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}>{new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span></div>}

                    <div className="message-body">
                      {!isGrouped && (
                        <div className="message-header">
                          {(msg as any)._botResponse && (
                            <span className="message-bot-badge">BOT</span>
                          )}
                          {(() => { const am = ctx.members.find(m => ctx.displayName(m.user) === msg.author || ctx.fingerprint(m.public_key_hash) === msg.author); const rc = am ? ctx.getMemberRoleColor(am.user_id) : undefined; return rc ? <span className="message-role-dot" style={{ background: rc }} /> : null; })()}
                          <span className="message-author" style={{ color: (() => { const am = ctx.members.find(m => ctx.displayName(m.user) === msg.author || ctx.fingerprint(m.public_key_hash) === msg.author); return am ? ctx.getMemberRoleColor(am.user_id) : undefined; })() || undefined }}
                          onClick={(e) => {
                            const authorMember = ctx.members.find(m => ctx.displayName(m.user) === msg.author || ctx.fingerprint(m.public_key_hash) === msg.author);
                            if (authorMember) {
                              ctx.setProfileCardTarget({ userId: authorMember.user_id, x: e.clientX, y: e.clientY, user: authorMember.user, profile: authorMember.profile, roles: ctx.memberRolesMap[authorMember.user_id], joinedAt: authorMember.joined_at, roleColor: ctx.getMemberRoleColor(authorMember.user_id) });
                            }
                          }}
                          onContextMenu={(e) => {
                            const authorMember = ctx.members.find(m => ctx.displayName(m.user) === msg.author || ctx.fingerprint(m.public_key_hash) === msg.author);
                            if (authorMember) {
                              ctx.handleContextMenu(e, authorMember.user_id, authorMember.public_key_hash, msg.author, authorMember.profile?.bio, authorMember.user);
                            }
                          }}>{msg.author}</span>
                          <span className="message-time" title={new Date(msg.timestamp).toLocaleString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}>{formatRelativeTime(msg.timestamp)}</span>
                          {msg._status && msg.sender_id === ctx.appState.user?.id && (
                            msg._status === 'failed' ? (
                              <span
                                className="delivery-status delivery-failed"
                                title="Failed to send. Click to retry."
                                onClick={() => ctx.handleRetryMessage(msg.id)}
                                role="button"
                                tabIndex={0}
                                onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleRetryMessage(msg.id); }}
                              >⚠</span>
                            ) : msg._status === 'sending' ? (
                              <span className="delivery-status delivery-sending" title="Sending">○</span>
                            ) : msg._status === 'sent' ? (
                              <span className="delivery-status delivery-sent" title="Sent">●</span>
                            ) : null
                          )}
                          {msg.edited_at && (
                            <span className="message-edited" title={`Edited at ${new Date(msg.edited_at).toLocaleString()}`}>(edited)</span>
                          )}
                          {msg.isEncrypted && (
                            <span className="message-encrypted-badge" title={
                              msg.e2eeType === 'double-ratchet'
                                ? 'End-to-end encrypted (Double Ratchet)'
                                : 'Transport encrypted (placeholder — not E2EE)'
                            }><Icon name="lock" size={12} /></span>
                          )}
                          {msg.pinned_at && (
                            <span className="message-pinned-badge" title={`Pinned ${new Date(msg.pinned_at).toLocaleString()}`}><Icon name="pin" size={12} /></span>
                          )}
                          {isBookmarked(msg.id) && (
                            <span className="message-bookmark-badge" title="Saved message"><Icon name="bookmark" size={12} /></span>
                          )}
                          {ctx.appState.user && (
                            <div className="message-actions">
                              <button onClick={() => ctx.handleReply(msg)} className="message-action-btn" title="Reply" aria-label="Reply"><Icon name="reply" size={18} /></button>
                              {msg.author === (ctx.appState.user.display_name || ctx.fingerprint(ctx.appState.user.public_key_hash)) && (
                                <button onClick={() => ctx.handleStartEdit(msg.id, msg.content)} className="message-action-btn" title="Edit" aria-label="Edit message"><Icon name="edit" size={18} /></button>
                              )}
                              {(msg.author === (ctx.appState.user.display_name || ctx.fingerprint(ctx.appState.user.public_key_hash)) || ctx.canDeleteMessage(msg)) && (
                                <button onClick={() => ctx.setShowDeleteConfirm(msg.id)} className="message-action-btn" title="Delete" aria-label="Delete message"><Icon name="delete" size={18} /></button>
                              )}
                              {ctx.canDeleteMessage(msg) && (
                                <button onClick={() => msg.pinned_at ? ctx.handleUnpinMessage(msg.id) : ctx.setShowPinConfirm(msg.id)} className="message-action-btn" title={msg.pinned_at ? "Unpin" : "Pin"} aria-label={msg.pinned_at ? "Unpin message" : "Pin message"}><Icon name="pin" size={18} /></button>
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Editing Interface */}
                      {ctx.editingMessageId === msg.id ? (
                        <div className="message-edit-container">
                          <textarea
                            value={ctx.editingContent}
                            onChange={(e) => ctx.setEditingContent(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ctx.handleSaveEdit(); }
                              else if (e.key === 'Escape') { ctx.handleCancelEdit(); }
                            }}
                            className="message-edit-input"
                            placeholder="Edit your message..."
                            autoFocus
                            rows={1}
                            ref={(el) => {
                              if (el) {
                                el.style.height = 'auto';
                                el.style.height = el.scrollHeight + 'px';
                              }
                            }}
                            onInput={(e) => {
                              const t = e.currentTarget;
                              t.style.height = 'auto';
                              t.style.height = t.scrollHeight + 'px';
                            }}
                          />
                          <span className="message-edit-hint">escape to <a href="#" onClick={(e) => { e.preventDefault(); ctx.handleCancelEdit(); }}>cancel</a> • enter to <a href="#" onClick={(e) => { e.preventDefault(); ctx.handleSaveEdit(); }}>save</a></span>
                        </div>
                      ) : (
                        <div 
                          className="message-content"
                          dangerouslySetInnerHTML={{ 
                            __html: renderMessageMarkdown(msg.content, notificationManager.currentUsername) 
                          }}
                        />
                      )}

                      {/* Media Embeds (GIF, video, YouTube) */}
                      {msg.content && (
                        <MediaEmbeds content={msg.content} onImageClick={setLightboxSrc} />
                      )}

                      {/* Bot Response Embed */}
                      {(msg as any)._botResponse?.content?.type === 'embed' && (
                        <BotResponseRenderer
                          content={(msg as any)._botResponse.content}
                          botId={(msg as any)._botResponse.bot_id}
                          onInvokeCommand={(botId, cmd, params) => ctx.handleInvokeBot(botId, cmd, params)}
                        />
                      )}
                      {(msg as any)._botResponse && (
                        <div className="bot-sent-disclosure"><Icon name="clipboard" size={14} /> Sent to bot</div>
                      )}

                      {/* Link Preview */}
                      {msg.content && extractAllUrls(msg.content).length > 0 && (
                        <LinkPreview content={msg.content} token={ctx.appState.token || ''} />
                      )}

                      {/* Thread reply count */}
                      {msg.reply_count != null && msg.reply_count > 0 && (
                        <div className="thread-indicator" onClick={() => ctx.openThread(msg)} role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') ctx.openThread(msg); }}>
                          <span className="thread-icon"><Icon name="thread" size={14} /></span>
                          <span className="thread-count">{msg.reply_count} {msg.reply_count === 1 ? 'reply' : 'replies'}</span>
                        </div>
                      )}

                      {/* File Attachments */}
                      {msg.files && msg.files.length > 0 && (
                        <>
                          {/* Image grid for 2+ images */}
                          {hasImageGrid(msg.files) && (
                            <ImageGrid
                              files={msg.files}
                              token={ctx.appState.token || ''}
                              channelId={msg.channel_id || ctx.selectedDmChannel?.id || ctx.selectedChannelId || ''}
                              keyPair={ctx.keyPair}
                              encryptionEnabled={ctx.encryptionEnabled}
                              onImageClick={(src) => {
                                setAllChannelImages(collectImages());
                                setLightboxSrc(src);
                              }}
                            />
                          )}
                          <div className="message-attachments">
                            {(hasImageGrid(msg.files) ? getNonImageFiles(msg.files) : msg.files).map((file) => (
                              <FileAttachment
                                key={file.id}
                                file={file}
                                token={ctx.appState.token || ''}
                                channelId={msg.channel_id || ctx.selectedDmChannel?.id || ctx.selectedChannelId || ''}
                                keyPair={ctx.keyPair}
                                encryptionEnabled={ctx.encryptionEnabled}
                              />
                            ))}
                          </div>
                        </>
                      )}

                      {/* Reactions */}
                      <div 
                        className="message-reactions-container"
                        onMouseEnter={() => ctx.setHoveredMessageId(msg.id)}
                        onMouseLeave={() => ctx.setHoveredMessageId(null)}
                      >
                        {msg.reactions && msg.reactions.length > 0 && (
                          <div className="message-reactions">
                            {msg.reactions.map((reaction) => {
                              const userReacted = ctx.appState.user && reaction.users.includes(ctx.appState.user.id);
                              const reactorNames = reaction.users.map((uid) => {
                                const member = ctx.members.find((m) => m.user.id === uid);
                                return member ? ctx.displayName(member.user) : uid.substring(0, 8);
                              });
                              const tooltipText = reactorNames.length <= 5
                                ? reactorNames.join(', ')
                                : `${reactorNames.slice(0, 5).join(', ')} and ${reactorNames.length - 5} more`;
                              return (
                                <button
                                  key={reaction.emoji}
                                  className={`reaction ${userReacted ? 'reaction-user-reacted' : ''}`}
                                  onClick={() => ctx.handleToggleReaction(msg.id, reaction.emoji)}
                                  title={tooltipText}
                                >
                                  <span className="reaction-emoji">{reaction.emoji}</span>
                                  <span className="reaction-count reaction-count-bump">{reaction.count}</span>
                                </button>
                              );
                            })}
                          </div>
                        )}

                        {ctx.hoveredMessageId === msg.id && ctx.appState.user && (
                          <div className="add-reaction-container quick-react-bar">
                            {['👍', '❤️', '😂', '🔥', '👀'].map((emoji) => (
                              <button key={emoji} className="quick-react-btn" onClick={() => ctx.handleToggleReaction(msg.id, emoji)} title={`React with ${emoji}`}>{emoji}</button>
                            ))}
                            <button 
                              className="add-reaction-btn"
                              onClick={() => ctx.setShowEmojiPicker(ctx.showEmojiPicker === msg.id ? null : msg.id)}
                              title="More reactions"
                            >+</button>

                            {ctx.showEmojiPicker === msg.id && (
                              <div className="emoji-picker">
                                {ctx.COMMON_EMOJIS.map((emoji) => (
                                  <button key={emoji} className="emoji-option" onClick={() => ctx.handleAddReaction(msg.id, emoji)} title={`React with ${emoji}`}>{emoji}</button>
                                ))}
                              </div>
                            )}
                          </div>
                        )}
                      </div>

                      {/* Delete Confirmation */}
                      {ctx.showDeleteConfirm === msg.id && (
                        <div className="delete-confirm-overlay">
                          <div className="delete-confirm-dialog">
                            <p>Are you sure you want to delete this message?</p>
                            <div className="delete-confirm-actions">
                              <button onClick={() => ctx.handleDeleteMessage(msg.id)} className="delete-confirm-btn">Delete</button>
                              <button onClick={() => ctx.setShowDeleteConfirm(null)} className="delete-cancel-btn">Cancel</button>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Pin Confirmation */}
                      {ctx.showPinConfirm === msg.id && (
                        <div className="delete-confirm-overlay">
                          <div className="delete-confirm-dialog">
                            <p>Pin this message to <strong>#{ctx.activeChannel}</strong>?</p>
                            <p className="pin-confirm-preview">{msg.content.substring(0, 100)}{msg.content.length > 100 ? '...' : ''}</p>
                            <div className="delete-confirm-actions">
                              <button onClick={() => { ctx.handlePinMessage(msg.id); ctx.setShowPinConfirm(null); }} className="delete-confirm-btn" style={{ backgroundColor: 'var(--accent)' }}>Pin</button>
                              <button onClick={() => ctx.setShowPinConfirm(null)} className="delete-cancel-btn">Cancel</button>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Read receipts & delivery status */}
                    {ctx.selectedChannelId && (() => {
                      const receipts = ctx.readReceipts.get(ctx.selectedChannelId!) || [];
                      const currentUserId = ctx.appState.user?.id;
                      const isOwn = msg.sender_id === currentUserId;

                      // For own messages: show ✓ (delivered) or ✓✓ (read)
                      const readBy = receipts.filter(r => r.message_id === msg.id && r.user_id !== currentUserId);
                      const allReadNames = readBy.map(r => {
                        const member = ctx.members.find(m => m.user_id === r.user_id);
                        return member?.profile?.display_name || member?.user?.display_name || r.user_id.substring(0, 6);
                      });
                      const tooltipText = allReadNames.length > 0
                        ? `Read by ${allReadNames.join(', ')}`
                        : '';

                      if (isOwn && readBy.length === 0) {
                        // Delivered but not read
                        return (
                          <div className="read-receipts">
                            <span className="delivery-check delivered" title="Delivered">✓</span>
                          </div>
                        );
                      }

                      if (readBy.length === 0) return null;

                      return (
                        <div className="read-receipts" title={tooltipText}>
                          {isOwn && (
                            <span className="delivery-check read" title={tooltipText}>✓✓</span>
                          )}
                          <div className="read-receipt-avatar-stack">
                            {readBy.slice(0, 3).map((r, idx) => {
                              const member = ctx.members.find(m => m.user_id === r.user_id);
                              const name = member?.profile?.display_name || member?.user?.display_name || r.user_id.substring(0, 6);
                              return (
                                <span key={r.user_id} className="read-receipt-avatar" style={{ zIndex: 3 - idx, background: avatarColor(r.user_id) }} title={`Read by ${name}`}>
                                  {r.user_id ? (
                                    <img
                                      src={`${api.getUserAvatarUrl(r.user_id)}`}
                                      alt={name[0]}
                                      onError={(e) => { const img = e.target as HTMLImageElement; img.style.display = 'none'; if (img.parentElement) img.parentElement.textContent = name[0]?.toUpperCase() || '?'; }}
                                    />
                                  ) : (name[0]?.toUpperCase() || '?')}
                                </span>
                              );
                            })}
                            {readBy.length > 3 && <span className="read-receipt-overflow">+{readBy.length - 3}</span>}
                          </div>
                        </div>
                      );
                    })()}
                  </div>
                  </MessageContextMenu>
                </React.Fragment>
              );
            })}

          </div>

          {/* Scroll to bottom button — floating outside scroll container */}
          {ctx.showScrollToBottom && (
            <button className="scroll-to-bottom-fab" onClick={ctx.scrollToBottom} aria-label="Scroll to latest messages">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor"><path d="M10 14.5a.75.75 0 0 1-.53-.22l-5-5a.75.75 0 1 1 1.06-1.06L10 12.69l4.47-4.47a.75.75 0 1 1 1.06 1.06l-5 5a.75.75 0 0 1-.53.22z"/></svg>
              {ctx.newMessageCount > 0 && <span className="scroll-to-bottom-badge">{ctx.newMessageCount > 99 ? '99+' : ctx.newMessageCount}</span>}
            </button>
          )}

          {/* Typing indicator */}
          {ctx.selectedChannelId && (() => {
            const typers = ctx.getTypingUsersForChannel(ctx.selectedChannelId!);
            if (typers.length === 0) return null;
            return (
              <div className="typing-indicator typing-indicator-animated">
                <div className="typing-avatars">
                  {typers.slice(0, 3).map(t => (
                    <div key={t.user_id} className="typing-avatar" style={{ background: avatarColor(t.user_id) }} title={t.displayName}>
                      {t.user_id ? (
                        <img
                          src={`${api.getUserAvatarUrl(t.user_id)}`}
                          alt={t.displayName[0]}
                          onError={(e) => { const img = e.target as HTMLImageElement; img.style.display = 'none'; if (img.parentElement) img.parentElement.textContent = t.displayName[0]?.toUpperCase() || '?'; }}
                        />
                      ) : (t.displayName[0]?.toUpperCase() || '?')}
                    </div>
                  ))}
                </div>
                <span className="typing-text">{ctx.formatTypingUsers(ctx.selectedChannelId!)}</span>
                <div className="typing-dots-animated">
                  <span></span><span></span><span></span>
                </div>
              </div>
            );
          })()}

          {/* Upload progress */}
          {ctx.uploadProgress && (
            <div className="upload-progress-bar-container">
              <div className="upload-progress-info">
                <span className="upload-progress-filename">
                  Uploading {ctx.uploadProgress.fileName}
                  {ctx.uploadProgress.totalFiles > 1 && ` (${ctx.uploadProgress.current}/${ctx.uploadProgress.totalFiles})`}
                </span>
                <span className="upload-progress-pct">{ctx.uploadProgress.percentage}%</span>
              </div>
              <div className="file-upload-progress-bar-track">
                <div
                  className="file-upload-progress-bar-fill"
                  style={{ width: `${ctx.uploadProgress.percentage}%` }}
                />
              </div>
            </div>
          )}

          {/* Staged files preview */}
          <StagedFilesPreview
            files={ctx.stagedFiles}
            onRemove={ctx.handleRemoveStagedFile}
            onClear={ctx.handleClearStagedFiles}
          />

          {/* Bot Command Param Form */}
          {pendingCommand && (
            <CommandParamForm
              bot={pendingCommand.bot}
              command={pendingCommand.command}
              onSubmit={handleCommandSubmit}
              onCancel={() => setPendingCommand(null)}
            />
          )}

          {/* Voice Chat Component — inline between messages and input */}
          {ctx.voiceChannelId && (
            <Suspense fallback={<LoadingSpinner />}>
              <VoiceChat
                ws={ctx.ws}
                currentUserId={localStorage.getItem('accord_user_id')}
                channelId={ctx.voiceChannelId}
                channelName={ctx.voiceChannelName}
                onLeave={() => {
                  ctx.setVoiceChannelId(null);
                  ctx.setVoiceChannelName("");
                  ctx.setVoiceConnectedAt(null);
                  ctx.setVoiceMuted(false);
                  ctx.setVoiceDeafened(false);
                }}
              />
            </Suspense>
          )}

          {/* Message Input */}
          <div className={`message-input-container${ctx.slowModeCooldown > 0 ? ' slow-mode-active' : ''}`}>
            <MentionAutocomplete
              items={mentionState.items}
              selectedIndex={mentionState.selectedIndex}
              triggerChar={mentionState.triggerChar}
              visible={mentionState.active}
              onSelect={(i) => selectMentionItem(i, ctx.message, ctx.setMessage, ctx.messageInputRef as React.RefObject<HTMLTextAreaElement | null>)}
            />
            <SlashCommandPopup
              items={slashState.items}
              selectedIndex={slashState.selectedIndex}
              visible={slashState.active}
              onSelect={(i) => selectSlashItem(i, ctx.message, ctx.setMessage, ctx.messageInputRef as React.RefObject<HTMLTextAreaElement | null>)}
            />
            <SlashCommandAutocomplete
              query={slashQuery}
              bots={ctx.installedBots}
              onSelect={handleSlashSelect}
              visible={showSlashMenu && !slashState.active}
            />
            {ctx.replyingTo && (
              <div className="reply-input-preview">
                <div className="reply-input-bar"></div>
                <div className="reply-input-content">
                  <span className="reply-input-text">
                    Replying to <strong>{ctx.replyingTo.author}</strong>: {ctx.replyingTo.content.substring(0, 100)}{ctx.replyingTo.content.length > 100 ? '...' : ''}
                  </span>
                  <button className="reply-cancel-btn" onClick={ctx.handleCancelReply} title="Cancel reply" aria-label="Cancel reply">×</button>
                </div>
              </div>
            )}
            {ctx.serverAvailable && ctx.appState.activeChannel && (
              <FileUploadButton
                channelId={ctx.appState.activeChannel}
                token={ctx.appState.token || ''}
                keyPair={ctx.keyPair}
                encryptionEnabled={ctx.encryptionEnabled}
                onFilesStaged={ctx.handleFilesStaged}
              />
            )}
            {ctx.messageError && (
              <div className="message-error-toast">
                {ctx.messageError}
              </div>
            )}
            {ctx.slowModeCooldown > 0 && !ctx.messageError && (
              <div className="slow-mode-toast">
                <Icon name="clock" size={14} /> Slow mode: wait {ctx.slowModeCooldown}s
              </div>
            )}
            <MessagePreview
              text={ctx.message}
              currentUsername={ctx.appState.user?.display_name}
              visible={showPreview}
              onClose={() => setShowPreview(false)}
            />
            {showFormattingToolbar && (
              <div className="formatting-toolbar">
                <button type="button" className="formatting-btn" title="Bold (Ctrl+B)" onMouseDown={(e) => { e.preventDefault(); wrapSelection('**', '**'); }}><strong>B</strong></button>
                <button type="button" className="formatting-btn" title="Italic (Ctrl+I)" onMouseDown={(e) => { e.preventDefault(); wrapSelection('*', '*'); }}><em>I</em></button>
                <button type="button" className="formatting-btn" title="Code (Ctrl+E)" onMouseDown={(e) => { e.preventDefault(); wrapSelection('`', '`'); }}><code>&lt;/&gt;</code></button>
                <button type="button" className="formatting-btn" title="Code Block" onMouseDown={(e) => { e.preventDefault(); wrapSelection('```\n', '\n```'); }}>{'{ }'}</button>
                <button type="button" className="formatting-btn" title="Spoiler" onMouseDown={(e) => { e.preventDefault(); wrapSelection('||', '||'); }}>░</button>
                <button type="button" className={`formatting-btn${showPreview ? ' formatting-btn-active' : ''}`} title="Preview (Ctrl+Shift+P)" onMouseDown={(e) => { e.preventDefault(); setShowPreview(p => !p); }}>👁</button>
              </div>
            )}
            <textarea
              ref={ctx.messageInputRef}
              className="message-input"
              aria-label={`Message ${ctx.activeChannel}`}
              placeholder={ctx.slowModeCooldown > 0 ? `Slow mode — wait ${ctx.slowModeCooldown}s` : `Message ${ctx.activeChannel}`}
              value={ctx.message}
              rows={1}
              disabled={ctx.slowModeCooldown > 0}
              onChange={(e) => {
                const val = e.target.value;
                ctx.setMessage(val);
                e.target.style.height = 'auto';
                e.target.style.height = Math.min(e.target.scrollHeight, 200) + 'px';
                // Mention autocomplete detection
                handleMentionInput(val, e.target.selectionStart ?? val.length);
                // Slash command autocomplete
                handleSlashInput(val, e.target.selectionStart ?? val.length);
                // Bot slash command detection
                if (val.startsWith('/') && val.length > 1 && !val.includes(' ')) {
                  setSlashQuery(val.substring(1));
                  setShowSlashMenu(true);
                } else {
                  setShowSlashMenu(false);
                }
                if (ctx.selectedChannelId) {
                  ctx.sendTypingIndicator(ctx.selectedChannelId);
                }
              }}
              onKeyDown={(e) => {
                // Slash command autocomplete takes priority when active
                if (slashState.active && handleSlashKeyDown(e, ctx.message, ctx.setMessage, ctx.messageInputRef as React.RefObject<HTMLTextAreaElement | null>)) {
                  return;
                }
                // Mention autocomplete takes priority
                if (mentionState.active && handleMentionKeyDown(e, ctx.message, ctx.setMessage, ctx.messageInputRef as React.RefObject<HTMLTextAreaElement | null>)) {
                  return;
                }
                if (e.key === 'ArrowUp' && !ctx.message.trim()) {
                  // Edit last own message when pressing Up on empty input
                  const myName = ctx.appState.user?.display_name || (ctx.appState.user ? ctx.fingerprint(ctx.appState.user.public_key_hash) : '');
                  const lastOwn = [...ctx.appState.messages].reverse().find(m => m.author === myName);
                  if (lastOwn) {
                    e.preventDefault();
                    ctx.handleStartEdit(lastOwn.id, lastOwn.content);
                  }
                } else if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  dismissMention();
                  dismissSlash();
                  if (processSlashCommand(ctx.message)) {
                    ctx.setMessage('');
                  } else {
                    ctx.handleSendMessage();
                  }
                } else if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'P') {
                  e.preventDefault();
                  setShowPreview(p => !p);
                } else if (e.ctrlKey || e.metaKey) {
                  if (e.key === 'b') { e.preventDefault(); wrapSelection('**', '**'); }
                  else if (e.key === 'i') { e.preventDefault(); wrapSelection('*', '*'); }
                  else if (e.key === 'e') { e.preventDefault(); wrapSelection('`', '`'); }
                }
              }}
              onFocus={() => setShowFormattingToolbar(true)}
              onBlur={() => setTimeout(() => setShowFormattingToolbar(false), 200)}
            />
            <EmojiPickerButton
              isOpen={ctx.showInputEmojiPicker}
              onToggle={() => ctx.setShowInputEmojiPicker(prev => !prev)}
              onSelect={ctx.handleInsertEmoji}
              onClose={() => ctx.setShowInputEmojiPicker(false)}
              customEmojis={customEmojis}
              getEmojiUrl={getCustomEmojiUrl}
            />
            <GifPickerButton
              isOpen={ctx.showGifPicker}
              onToggle={() => { ctx.setShowGifPicker(prev => !prev); ctx.setShowInputEmojiPicker(false); }}
              onSelect={(gifUrl: string) => { void ctx.handleSendMessage(gifUrl); }}
              onClose={() => ctx.setShowGifPicker(false)}
            />
            {ctx.serverAvailable && ctx.appState.activeChannel && (
              <FileList
                channelId={ctx.appState.activeChannel}
                token={ctx.appState.token || ''}
                keyPair={ctx.keyPair}
                encryptionEnabled={ctx.encryptionEnabled}
              />
            )}
            <button
              className={`send-btn${ctx.slowModeCooldown > 0 ? ' send-btn-cooldown' : ''}`}
              disabled={ctx.slowModeCooldown > 0 || !ctx.message.trim()}
              title={ctx.slowModeCooldown > 0 ? `Wait ${ctx.slowModeCooldown}s` : 'Send message'}
              aria-label={ctx.slowModeCooldown > 0 ? `Send disabled, ${ctx.slowModeCooldown} seconds remaining` : 'Send message'}
              onClick={() => { if (ctx.slowModeCooldown <= 0) ctx.handleSendMessage(); }}
            >
              {ctx.slowModeCooldown > 0 ? `${ctx.slowModeCooldown}s` : <Icon name="send" size={18} />}
            </button>
          </div>
        </FileDropZone>
      </div>

      {/* Voice Chat Component moved inline above message input */}

      {lightboxSrc && (
        <ImageLightbox
          src={lightboxSrc}
          onClose={() => setLightboxSrc(null)}
          allImages={allChannelImages}
          onNavigate={setLightboxSrc}
        />
      )}

      {/* Topic Edit Modal */}
      {showTopicEdit && (
        <div className="modal-overlay" onClick={() => setShowTopicEdit(false)} onKeyDown={(e) => { if (e.key === 'Escape') setShowTopicEdit(false); }}>
          <div className="modal-card modal-card-narrow" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="topic-edit-title">
            <h3 id="topic-edit-title">Edit Channel Topic</h3>
            <p>Set a topic to let others know what this channel is about.</p>
            <div className="form-group">
              <label className="form-label">Topic</label>
              <textarea
                ref={topicInputRef}
                className="form-input"
                value={topicDraft}
                onChange={(e) => setTopicDraft(e.target.value)}
                placeholder="Enter a topic..."
                rows={3}
                maxLength={1024}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleTopicSave();
                  }
                }}
              />
            </div>
            <div className="modal-actions">
              <button
                className="btn btn-primary btn-auto-width"
                disabled={topicSaving}
                onClick={handleTopicSave}
              >{topicSaving ? 'Saving...' : 'Save'}</button>
              <button className="btn btn-outline btn-auto-width" onClick={() => setShowTopicEdit(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
      {showSavedMessages && (
        <SavedMessagesPanel
          bookmarks={bookmarks}
          onRemove={removeBookmark}
          onJumpTo={handleJumpToBookmark}
          onClose={() => setShowSavedMessages(false)}
        />
      )}
    </>
  );

  async function handleTopicSave() {
    if (!ctx.selectedChannelId || !ctx.appState.token) return;
    setTopicSaving(true);
    try {
      await api.updateChannel(ctx.selectedChannelId, { topic: topicDraft }, ctx.appState.token);
      // Refresh channels to pick up the new topic
      if (ctx.selectedNodeId) ctx.loadChannels(ctx.selectedNodeId);
      setShowTopicEdit(false);
    } catch (err: any) {
      ctx.setError(err.message || 'Failed to update topic');
    } finally {
      setTopicSaving(false);
    }
  }
};
