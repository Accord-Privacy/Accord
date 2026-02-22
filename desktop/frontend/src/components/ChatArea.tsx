import React, { Suspense, useState, useCallback, useEffect } from "react";
import { useAppContext } from "./AppContext";
import { api, parseInviteLink } from "../api";
import { verifyBuildHash, getTrustIndicator } from "../buildHash";
import { notificationManager } from "../notifications";
import { renderMessageMarkdown } from "../markdown";
import { FileUploadButton, FileList, FileDropZone, FileAttachment, StagedFilesPreview } from "../FileManager";
import { EmojiPickerButton } from "../EmojiPicker";
import { getNodeCustomEmojis, getCustomEmojiUrl, subscribeCustomEmojis } from "../customEmojiStore";
// import { LinkPreview, extractFirstUrl } from "../LinkPreview"; // disabled for now
import { LoadingSpinner } from "../LoadingSpinner";
import { SlashCommandAutocomplete, CommandParamForm, BotResponseRenderer } from "./BotPanel";
import type { InstalledBot, BotCommand } from "../types";
const VoiceChat = React.lazy(() => import("../VoiceChat").then(m => ({ default: m.VoiceChat })));

export const ChatArea: React.FC = () => {
  const ctx = useAppContext();
  const [customEmojis, setCustomEmojisState] = useState(getNodeCustomEmojis());
  useEffect(() => subscribeCustomEmojis(() => setCustomEmojisState(getNodeCustomEmojis())), []);
  const [pendingCommand, setPendingCommand] = useState<{ bot: InstalledBot; command: BotCommand } | null>(null);
  const [showSlashMenu, setShowSlashMenu] = useState(false);
  const [slashQuery, setSlashQuery] = useState('');

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

  const filteredMessages = ctx.appState.messages.filter(msg => {
    const currentCh = ctx.selectedDmChannel?.id || ctx.selectedChannelId;
    if (currentCh && msg.channel_id && msg.channel_id !== currentCh) return false;
    if (msg.sender_id && ctx.blockedUsers.has(msg.sender_id)) return false;
    return true;
  });

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
        <div className="chat-area" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{
            textAlign: 'center',
            maxWidth: 420,
            padding: '40px 32px',
            background: 'var(--bg-secondary)',
            borderRadius: 12,
            border: '1px solid var(--border)',
          }}>
            {invitePreview ? (
              <>
                <h2 style={{ margin: '0 0 16px', fontSize: 22, color: 'var(--text-primary)' }}>{invitePreview.node_name}</h2>
                <div style={{ margin: '0 0 8px', fontFamily: 'monospace', fontSize: 13, color: 'var(--text-secondary)' }}>
                  {invitePreview.node_id.substring(0, 16)}
                </div>
                <div style={{ margin: '0 0 8px', color: 'var(--text-secondary)', fontSize: 14 }}>
                  {invitePreview.member_count} member{invitePreview.member_count !== 1 ? 's' : ''}
                </div>
                <div style={{ margin: '0 0 20px', fontSize: 13 }}>
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
                <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }}>
                  <button
                    className="btn"
                    onClick={() => { setInvitePreview(null); setPreviewError(""); }}
                    style={{ minWidth: 80 }}
                  >
                    Cancel
                  </button>
                  <button
                    className="btn btn-primary"
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
                    style={{ minWidth: 80 }}
                  >
                    Join
                  </button>
                </div>
              </>
            ) : (
              <>
                <h2 style={{ margin: '0 0 8px', fontSize: 22, color: 'var(--text-primary)' }}>Welcome to Accord!</h2>
                <p style={{ margin: '0 0 24px', color: 'var(--text-secondary)', fontSize: 14, lineHeight: 1.6 }}>
                  Join a Node to start chatting. Paste an invite link below.
                </p>
                {previewError && (
                  <p style={{ margin: '0 0 12px', color: 'var(--red)', fontSize: 13 }}>{previewError}</p>
                )}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  <input
                    type="text"
                    placeholder="Paste invite link here..."
                    value={ctx.inviteLinkInput ?? ''}
                    onChange={(e) => ctx.setInviteLinkInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handlePreviewInvite(); }}
                    className="form-input"
                    style={{ width: '100%', padding: '10px 12px', fontSize: 14 }}
                  />
                  <button
                    className="btn btn-primary"
                    onClick={handlePreviewInvite}
                    disabled={!ctx.inviteLinkInput?.trim() || previewLoading}
                    style={{ width: '100%', padding: '10px' }}
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
            <div className="chat-header-left">
              {ctx.selectedDmChannel ? (
                <>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <div className="dm-avatar" style={{ width: '24px', height: '24px', fontSize: '12px', marginRight: '8px' }}>
                      {(ctx.selectedDmChannel.other_user_profile?.display_name || "?")[0].toUpperCase()}
                    </div>
                    <span className="chat-channel-name">{ctx.selectedDmChannel.other_user_profile.display_name}</span>
                  </div>
                  <span className="chat-topic">
                    Direct message with {ctx.selectedDmChannel.other_user_profile.display_name}
                  </span>
                </>
              ) : (
                <>
                  <span className="chat-channel-name">{ctx.activeChannel}</span>
                  <span className="chat-topic">
                    {(() => {
                      const ch = ctx.channels.find(c => c.id === ctx.selectedChannelId);
                      if (ch?.channel_type === 'voice') return `🔊 Voice channel — ${ch.name}`;
                      if (ch?.topic) return ch.topic;
                      return '';
                    })()}
                  </span>
                </>
              )}
            </div>
            <div className="chat-header-right">
              <button onClick={ctx.togglePinnedPanel} className={`chat-header-btn ${ctx.showPinnedPanel ? 'active' : ''}`} title="Toggle pinned messages">📌</button>
              {ctx.encryptionEnabled && ctx.keyPair && (
                <span className="e2ee-badge enabled" title="End-to-end encryption enabled">🔐 E2EE</span>
              )}
              {ctx.encryptionEnabled && !ctx.keyPair && ctx.hasExistingKey && (
                <span className="e2ee-badge pending" title="Key stored but locked — enter password to decrypt">🔑 Key Locked</span>
              )}
              {ctx.encryptionEnabled && !ctx.keyPair && !ctx.hasExistingKey && (
                <span className="e2ee-badge warning" title="No encryption keys found">🔓 No Keys</span>
              )}
              {!ctx.encryptionEnabled && (
                <span className="e2ee-badge disabled" title="Encryption not supported">🚫 No E2EE</span>
              )}
              <button
                className="search-button"
                onClick={() => ctx.setShowSearchOverlay(true)}
                title="Search messages (Ctrl+K)"
              >
                🔍
              </button>
              <button
                onClick={() => ctx.setShowMemberSidebar(prev => !prev)}
                className={`chat-header-btn ${ctx.showMemberSidebar ? 'active' : ''}`}
                title="Toggle member list"
              >
                👥
              </button>
            </div>
          </div>

          {/* Messages */}
          <div 
            className={`messages ${ctx.voiceChannelId ? 'with-voice' : ''} density-${ctx.messageDensity}`}
            ref={ctx.messagesContainerRef}
            onScroll={ctx.handleScroll}
          >
            {ctx.isLoadingOlderMessages && (
              <div className="messages-loading"><span className="spinner spinner-sm"></span> Loading older messages...</div>
            )}
            {!ctx.hasMoreMessages && ctx.appState.messages.length > 0 && (
              <div className="messages-beginning">You've reached the beginning of this channel</div>
            )}
            {!ctx.isLoadingOlderMessages && ctx.appState.messages.length === 0 && ctx.selectedChannelId && (
              <div className="empty-state">
                <div className="empty-state-icon">💬</div>
                <div className="empty-state-title">No messages yet</div>
                <div className="empty-state-text">Be the first to send a message in this channel!</div>
              </div>
            )}
            {!ctx.selectedChannelId && !ctx.selectedDmChannel && ctx.channels.length === 0 && ctx.nodes.length > 0 && (
              <div className="empty-state">
                <div className="empty-state-icon">#</div>
                <div className="empty-state-title">No channels</div>
                <div className="empty-state-text">Create a channel to start chatting.</div>
              </div>
            )}
            {ctx.nodes.length === 0 && !ctx.selectedDmChannel && (
              <div className="empty-state">
                <div className="empty-state-icon">⚡</div>
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
                  <div className={`message ${msg.reply_to ? 'reply-message' : ''} ${isGrouped ? 'message-grouped' : ''}`} data-message-id={msg.id}>
                    {/* Reply preview */}
                    {msg.replied_message && (
                      <div className="reply-preview" onClick={() => ctx.scrollToMessage(msg.reply_to!)}>
                        <div className="reply-bar"></div>
                        <div className="reply-content">
                          <span className="reply-author">Replying to {ctx.fingerprint(msg.replied_message.sender_public_key_hash)}</span>
                          <span className="reply-snippet">{msg.replied_message.content || msg.replied_message.encrypted_payload.substring(0, 50) + '...'}</span>
                        </div>
                      </div>
                    )}

                    {!isGrouped && <div className="message-avatar">
                      {msg.sender_id ? (
                        <img 
                          src={`${api.getUserAvatarUrl(msg.sender_id)}`}
                          alt={(msg.author || "?")[0]}
                          style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '50%' }}
                          onError={(e) => { const img = e.target as HTMLImageElement; img.style.display = 'none'; img.removeAttribute('src'); if (img.parentElement) img.parentElement.textContent = (msg.author || "?")[0]; }}
                        />
                      ) : (msg.author || "?")[0]}
                    </div>}
                    {isGrouped && <div className="message-avatar-spacer"><span className="message-hover-time">{new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span></div>}

                    <div className="message-body">
                      {!isGrouped && (
                        <div className="message-header">
                          {(msg as any)._botResponse && (
                            <span className="message-bot-badge">🤖 BOT</span>
                          )}
                          <span className="message-author" style={{ cursor: 'pointer', color: (() => { const am = ctx.members.find(m => ctx.displayName(m.user) === msg.author || ctx.fingerprint(m.public_key_hash) === msg.author); return am ? ctx.getMemberRoleColor(am.user_id) : undefined; })() || undefined }}
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
                          <span className="message-time">{formatRelativeTime(msg.timestamp)}</span>
                          {msg.edited_at && (
                            <span className="message-edited" title={`Edited at ${new Date(msg.edited_at).toLocaleString()}`}>(edited)</span>
                          )}
                          {msg.isEncrypted && (
                            <span className="message-encrypted-badge" title={
                              msg.e2eeType === 'double-ratchet'
                                ? 'End-to-end encrypted (Double Ratchet)'
                                : 'Transport encrypted (placeholder — not E2EE)'
                            }>{msg.e2eeType === 'double-ratchet' ? '🔒' : '🔐'}</span>
                          )}
                          {msg.pinned_at && (
                            <span className="message-pinned-badge" title={`Pinned ${new Date(msg.pinned_at).toLocaleString()}`}>📌</span>
                          )}
                          {ctx.appState.user && (
                            <div className="message-actions">
                              <button onClick={() => ctx.handleReply(msg)} className="message-action-btn" title="Reply to message">💬</button>
                              {msg.author === (ctx.appState.user.display_name || ctx.fingerprint(ctx.appState.user.public_key_hash)) && (
                                <button onClick={() => ctx.handleStartEdit(msg.id, msg.content)} className="message-action-btn" title="Edit message">✏️</button>
                              )}
                              {(msg.author === (ctx.appState.user.display_name || ctx.fingerprint(ctx.appState.user.public_key_hash)) || ctx.canDeleteMessage(msg)) && (
                                <button onClick={() => ctx.setShowDeleteConfirm(msg.id)} className="message-action-btn" title="Delete message">🗑️</button>
                              )}
                              {ctx.canDeleteMessage(msg) && (
                                <button onClick={() => msg.pinned_at ? ctx.handleUnpinMessage(msg.id) : ctx.handlePinMessage(msg.id)} className="message-action-btn" title={msg.pinned_at ? "Unpin message" : "Pin message"}>📌</button>
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Editing Interface */}
                      {ctx.editingMessageId === msg.id ? (
                        <div className="message-edit-container">
                          <input
                            type="text"
                            value={ctx.editingContent}
                            onChange={(e) => ctx.setEditingContent(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ctx.handleSaveEdit(); }
                              else if (e.key === 'Escape') { ctx.handleCancelEdit(); }
                            }}
                            className="message-edit-input"
                            placeholder="Edit your message..."
                            autoFocus
                          />
                          <div className="message-edit-actions">
                            <button onClick={ctx.handleSaveEdit} className="edit-save-btn">Save</button>
                            <button onClick={ctx.handleCancelEdit} className="edit-cancel-btn">Cancel</button>
                          </div>
                        </div>
                      ) : (
                        <div 
                          className="message-content"
                          dangerouslySetInnerHTML={{ 
                            __html: renderMessageMarkdown(msg.content, notificationManager.currentUsername) 
                          }}
                        />
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
                        <div className="bot-sent-disclosure">📋 Sent to bot</div>
                      )}

                      {/* Link Preview — disabled for now */}

                      {/* Thread reply count */}
                      {msg.reply_count && msg.reply_count > 0 && (
                        <div className="thread-indicator">
                          <span className="thread-icon">💬</span>
                          <span className="thread-count">{msg.reply_count} {msg.reply_count === 1 ? 'reply' : 'replies'}</span>
                        </div>
                      )}

                      {/* File Attachments */}
                      {msg.files && msg.files.length > 0 && (
                        <div className="message-attachments">
                          {msg.files.map((file) => (
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
                              return (
                                <button
                                  key={reaction.emoji}
                                  className={`reaction ${userReacted ? 'reaction-user-reacted' : ''}`}
                                  onClick={() => ctx.handleToggleReaction(msg.id, reaction.emoji)}
                                  title={`${reaction.users.length} reactions`}
                                >
                                  <span className="reaction-emoji">{reaction.emoji}</span>
                                  <span className="reaction-count">{reaction.count}</span>
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
                    </div>

                    {/* Read receipts */}
                    {ctx.selectedChannelId && (() => {
                      const receipts = ctx.readReceipts.get(ctx.selectedChannelId!) || [];
                      const currentUserId = ctx.appState.user?.id;
                      const readBy = receipts.filter(r => r.message_id === msg.id && r.user_id !== currentUserId);
                      if (readBy.length === 0) return null;
                      return (
                        <div className="read-receipts" style={{ display: 'flex', gap: '2px', justifyContent: 'flex-end', padding: '2px 8px' }}>
                          {readBy.slice(0, 5).map(r => {
                            const member = ctx.members.find(m => m.user_id === r.user_id);
                            const name = member?.profile?.display_name || member?.user?.display_name || r.user_id.substring(0, 6);
                            return (
                              <span key={r.user_id} className="read-receipt-avatar" title={`Read by ${name}`}
                                style={{ width: '16px', height: '16px', borderRadius: '50%', backgroundColor: 'var(--accent)', color: 'var(--text-on-accent)', fontSize: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center', lineHeight: 1 }}>
                                {name[0]?.toUpperCase()}
                              </span>
                            );
                          })}
                          {readBy.length > 5 && <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>+{readBy.length - 5}</span>}
                        </div>
                      );
                    })()}
                  </div>
                </React.Fragment>
              );
            })}

            {/* Scroll to bottom button */}
            {ctx.showScrollToBottom && (
              <button className="scroll-to-bottom-btn" onClick={ctx.scrollToBottom}>
                ↓ {ctx.newMessageCount > 0 && <span className="scroll-to-bottom-count">{ctx.newMessageCount}</span>}
              </button>
            )}
          </div>

          {/* Typing indicator */}
          {ctx.selectedChannelId && ctx.formatTypingUsers(ctx.selectedChannelId) && (
            <div className="typing-indicator">
              <div className="typing-dots-animated">
                <span></span><span></span><span></span>
              </div>
              <span className="typing-text">{ctx.formatTypingUsers(ctx.selectedChannelId)}</span>
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
                }}
              />
            </Suspense>
          )}

          {/* Message Input */}
          <div className="message-input-container" style={{ position: 'relative' }}>
            <SlashCommandAutocomplete
              query={slashQuery}
              bots={ctx.installedBots}
              onSelect={handleSlashSelect}
              visible={showSlashMenu}
            />
            {ctx.replyingTo && (
              <div className="reply-input-preview">
                <div className="reply-input-bar"></div>
                <div className="reply-input-content">
                  <span className="reply-input-text">
                    Replying to <strong>{ctx.replyingTo.author}</strong>: {ctx.replyingTo.content.substring(0, 100)}{ctx.replyingTo.content.length > 100 ? '...' : ''}
                  </span>
                  <button className="reply-cancel-btn" onClick={ctx.handleCancelReply} title="Cancel reply">×</button>
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
              <div style={{
                position: 'absolute', top: '-36px', left: '50%', transform: 'translateX(-50%)',
                background: 'var(--red)', color: 'var(--text-on-accent)', padding: '6px 14px', borderRadius: '4px',
                fontSize: '13px', fontWeight: 500, zIndex: 11, maxWidth: '90%', textAlign: 'center',
                whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
              }}>
                {ctx.messageError}
              </div>
            )}
            {ctx.slowModeCooldown > 0 && !ctx.messageError && (
              <div style={{
                position: 'absolute', top: '-28px', left: '50%', transform: 'translateX(-50%)',
                background: 'var(--yellow)', color: 'var(--text-on-accent)', padding: '4px 12px', borderRadius: '4px',
                fontSize: '12px', fontWeight: 600, zIndex: 10, whiteSpace: 'nowrap',
              }}>
                ⏱️ Slow mode: wait {ctx.slowModeCooldown}s
              </div>
            )}
            <textarea
              ref={ctx.messageInputRef}
              className="message-input"
              placeholder={ctx.slowModeCooldown > 0 ? `Slow mode — wait ${ctx.slowModeCooldown}s` : `Message ${ctx.activeChannel}`}
              value={ctx.message}
              rows={1}
              disabled={ctx.slowModeCooldown > 0}
              onChange={(e) => {
                const val = e.target.value;
                ctx.setMessage(val);
                e.target.style.height = 'auto';
                e.target.style.height = Math.min(e.target.scrollHeight, 200) + 'px';
                // Slash command detection
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
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  ctx.handleSendMessage();
                }
              }}
            />
            <EmojiPickerButton
              isOpen={ctx.showInputEmojiPicker}
              onToggle={() => ctx.setShowInputEmojiPicker(prev => !prev)}
              onSelect={ctx.handleInsertEmoji}
              onClose={() => ctx.setShowInputEmojiPicker(false)}
              customEmojis={customEmojis}
              getEmojiUrl={getCustomEmojiUrl}
            />
            {ctx.serverAvailable && ctx.appState.activeChannel && (
              <FileList
                channelId={ctx.appState.activeChannel}
                token={ctx.appState.token || ''}
                keyPair={ctx.keyPair}
                encryptionEnabled={ctx.encryptionEnabled}
              />
            )}
          </div>
        </FileDropZone>
      </div>

      {/* Voice Chat Component moved inline above message input */}
    </>
  );
};
