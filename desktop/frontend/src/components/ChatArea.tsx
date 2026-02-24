import React, { Suspense, useState, useCallback, useEffect } from "react";
import { useAppContext } from "./AppContext";
import { api, parseInviteLink } from "../api";
import { verifyBuildHash, getTrustIndicator } from "../buildHash";
import { notificationManager } from "../notifications";
import { renderMessageMarkdown } from "../markdown";
import { FileUploadButton, FileList, FileDropZone, FileAttachment, StagedFilesPreview } from "../FileManager";
import { EmojiPickerButton } from "../EmojiPicker";
import { getNodeCustomEmojis, getCustomEmojiUrl, subscribeCustomEmojis } from "../customEmojiStore";
import { LoadingSpinner } from "../LoadingSpinner";
import { SlashCommandAutocomplete, CommandParamForm, BotResponseRenderer } from "./BotPanel";
import type { InstalledBot, BotCommand } from "../types";
import msgStyles from '../styles/Message.module.css';
import messagesStyles from './channel/Messages.module.css';
import chatStyles from './channel/ChannelChatLayout.module.css';
import headerStyles from './channel/ChannelHeader.module.css';
import textareaStyles from './channel/textarea/TextareaInput.module.css';
import replyStyles from './channel/ReplyBar.module.css';
import typingStyles from './channel/TypingUsers.module.css';
import clsx from 'clsx';
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
    node_name: string; node_id: string; member_count: number; server_build_hash: string;
  } | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState("");

  const handlePreviewInvite = useCallback(async () => {
    const input = ctx.inviteLinkInput?.trim();
    if (!input) return;
    const parsed = parseInviteLink(input);
    if (!parsed) { setPreviewError("Invalid invite link format"); return; }
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
      <div className={chatStyles.container} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{
          textAlign: 'center', maxWidth: 460, padding: '48px 40px',
          background: 'var(--background-tertiary)', borderRadius: 8,
          boxShadow: '0 8px 16px rgba(0,0,0,0.24)',
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
                  return <span style={{ color: indicator.color }}>{indicator.emoji} {indicator.label}</span>;
                })()}
              </div>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }}>
                <button className="btn" onClick={() => { setInvitePreview(null); setPreviewError(""); }} style={{ minWidth: 80 }}>Cancel</button>
                <button className="btn btn-primary" onClick={async () => {
                  setInvitePreview(null);
                  const input = ctx.inviteLinkInput?.trim();
                  if (!input) return;
                  const parsed = parseInviteLink(input);
                  const code = parsed ? parsed.inviteCode : input;
                  try {
                    let token = ctx.appState.token;
                    if (!token) { setPreviewError("Not authenticated"); return; }
                    api.setToken(token);
                    await api.joinNodeByInvite(code, token);
                    ctx.setInviteLinkInput('');
                    if (ctx.loadNodes) ctx.loadNodes();
                  } catch (e: any) { setPreviewError(e.message || "Failed to join node"); }
                }} style={{ minWidth: 80 }}>Join</button>
              </div>
            </>
          ) : (
            <>
              <h2 style={{ margin: '0 0 8px', fontSize: 22, color: 'var(--text-primary)' }}>Welcome to Accord!</h2>
              <p style={{ margin: '0 0 24px', color: 'var(--text-secondary)', fontSize: 14, lineHeight: 1.6 }}>
                Join a Node to start chatting. Paste an invite link below.
              </p>
              {previewError && <p style={{ margin: '0 0 12px', color: 'var(--status-danger)', fontSize: 13 }}>{previewError}</p>}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <input type="text" placeholder="Paste invite link here..." value={ctx.inviteLinkInput ?? ''} onChange={(e) => ctx.setInviteLinkInput(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') handlePreviewInvite(); }} className="form-input" style={{ width: '100%', padding: '10px 12px', fontSize: 14 }} />
                <button className="btn btn-primary" onClick={handlePreviewInvite} disabled={!ctx.inviteLinkInput?.trim() || previewLoading} style={{ width: '100%', padding: '10px' }}>
                  {previewLoading ? '...' : 'Preview →'}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    );
  }

  return (
    <>
      <div className={chatStyles.container}>
        <FileDropZone
          channelId={ctx.selectedDmChannel?.id || ctx.selectedChannelId || ''}
          token={ctx.appState.token || ''}
          keyPair={ctx.keyPair}
          encryptionEnabled={ctx.encryptionEnabled}
          onFilesStaged={ctx.handleFilesStaged}
        >
          {/* Chat Header */}
          <div className={headerStyles.headerWrapper}>
            <div className={headerStyles.headerContainer}>
              <div className={headerStyles.headerLeftSection}>
                {ctx.selectedDmChannel ? (
                  <div className={headerStyles.leftContentContainer}>
                    <span className={headerStyles.channelIcon}>
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" opacity="0.2"/><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z"/></svg>
                    </span>
                    <span className={headerStyles.channelName}>{ctx.selectedDmChannel.other_user_profile.display_name}</span>
                  </div>
                ) : (
                  <div className={headerStyles.leftContentContainer}>
                    <span className={headerStyles.channelIcon}>
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M5.88657 21C5.57547 21 5.3399 20.7189 5.39427 20.4126L6.00001 17H2.59511C2.28449 17 2.04905 16.7198 2.10259 16.4138L2.27759 15.4138C2.31946 15.1746 2.52722 15 2.77011 15H6.35001L7.41001 9H4.00511C3.69449 9 3.45905 8.71977 3.51259 8.41381L3.68759 7.41381C3.72946 7.17456 3.93722 7 4.18011 7H7.76001L8.39677 3.41262C8.43914 3.17391 8.64664 3 8.88907 3H9.87344C10.1845 3 10.4201 3.28107 10.3657 3.58738L9.76001 7H15.76L16.3968 3.41262C16.4391 3.17391 16.6466 3 16.8891 3H17.8734C18.1845 3 18.4201 3.28107 18.3657 3.58738L17.76 7H21.1649C21.4755 7 21.711 7.28023 21.6574 7.58619L21.4824 8.58619C21.4406 8.82544 21.2328 9 20.9899 9H17.41L16.35 15H19.7549C20.0655 15 20.301 15.2802 20.2474 15.5862L20.0724 16.5862C20.0306 16.8254 19.8228 17 19.5799 17H16L15.3632 20.5874C15.3209 20.8261 15.1134 21 14.8709 21H13.8866C13.5755 21 13.3399 20.7189 13.3943 20.4126L14 17H8.00001L7.36325 20.5874C7.32088 20.8261 7.11337 21 6.87094 21H5.88657ZM9.41045 9L8.35045 15H14.3504L15.4104 9H9.41045Z"/>
                      </svg>
                    </span>
                    <span className={headerStyles.channelName}>{ctx.activeChannel}</span>
                  </div>
                )}
              </div>
              <div className={headerStyles.headerRightSection}>
                <button onClick={ctx.togglePinnedPanel} className={clsx(headerStyles.iconButtonDefault, ctx.showPinnedPanel && headerStyles.iconButtonSelected)} title="Pinned messages">
                  <svg className={headerStyles.buttonIcon} viewBox="0 0 24 24" fill="currentColor"><path d="M16 12V4h1V2H7v2h1v8l-2 2v2h5.2v6h1.6v-6H18v-2l-2-2z"/></svg>
                </button>
                <button className={headerStyles.iconButtonDefault} onClick={() => ctx.setShowSearchOverlay(true)} title="Search (Ctrl+K)">
                  <svg className={headerStyles.buttonIcon} viewBox="0 0 24 24" fill="currentColor"><path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
                </button>
                <button onClick={() => ctx.setShowMemberSidebar(prev => !prev)} className={clsx(headerStyles.iconButtonDefault, ctx.showMemberSidebar && headerStyles.iconButtonSelected)} title="Members">
                  <svg className={headerStyles.buttonIcon} viewBox="0 0 24 24" fill="currentColor"><path d="M12 12.75c1.63 0 3.07.39 4.24.9 1.08.48 1.76 1.56 1.76 2.73V18H6v-1.62c0-1.17.68-2.25 1.76-2.73 1.17-.51 2.61-.9 4.24-.9zM4 13c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm1.13 1.1c-.37-.06-.74-.1-1.13-.1-.99 0-1.93.21-2.78.58A2.01 2.01 0 0 0 0 16.43V18h4.5v-1.62c0-.83.23-1.61.63-2.28zM20 13c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm4 3.43c0-.81-.48-1.53-1.22-1.85A6.95 6.95 0 0 0 20 14c-.39 0-.76.04-1.13.1.4.67.63 1.45.63 2.28V18H24v-1.57zM12 6c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3z"/></svg>
                </button>
              </div>
            </div>
          </div>

          {/* Messages area */}
          <div className={messagesStyles.messagesWrapper}>
            <div
              className={messagesStyles.scrollerContainer}
              ref={ctx.messagesContainerRef}
              onScroll={ctx.handleScroll}
              style={{ overflowY: 'auto' }}
            >
              <div className={messagesStyles.scrollerInner}>
                {ctx.isLoadingOlderMessages && (
                  <div className={messagesStyles.loadMoreContainer}><span className="spinner spinner-sm"></span> Loading older messages...</div>
                )}
                {!ctx.hasMoreMessages && ctx.appState.messages.length > 0 && (
                  <div style={{ textAlign: 'center', padding: '16px', color: 'var(--text-tertiary-muted)', fontSize: '13px' }}>
                    You've reached the beginning of this channel
                  </div>
                )}
                {!ctx.isLoadingOlderMessages && ctx.appState.messages.length === 0 && ctx.selectedChannelId && (
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flex: 1, gap: '8px', color: 'var(--text-tertiary-muted)' }}>
                    <div style={{ fontSize: '48px' }}>💬</div>
                    <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>No messages yet</div>
                    <div style={{ fontSize: '14px' }}>Be the first to send a message in this channel!</div>
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
                        <div style={{
                          display: 'flex', alignItems: 'center', margin: '16px 0 8px', gap: '8px',
                        }}>
                          <div style={{ flex: 1, height: '1px', background: 'var(--background-modifier-accent)' }} />
                          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-tertiary-muted)', whiteSpace: 'nowrap' }}>{formatDateSep(msgDate)}</span>
                          <div style={{ flex: 1, height: '1px', background: 'var(--background-modifier-accent)' }} />
                        </div>
                      )}

                      {/* Group spacer */}
                      {!isGrouped && i > 0 && !showDateSep && <div className={messagesStyles.groupSpacer} />}

                      <div
                        className={clsx(
                          isGrouped ? msgStyles.messageGrouped : msgStyles.message,
                          msg.reply_to && msgStyles.messageReplying,
                        )}
                        data-message-id={msg.id}
                      >
                        {/* Reply preview */}
                        {msg.replied_message && (
                          <div className={msgStyles.repliedMessage} onClick={() => ctx.scrollToMessage(msg.reply_to!)} style={{ cursor: 'pointer' }}>
                            <span className={msgStyles.repliedUsername}>{ctx.fingerprint(msg.replied_message.sender_public_key_hash)}</span>
                            <span className={msgStyles.repliedTextPreview}>
                              <span className={msgStyles.repliedTextContent}>{msg.replied_message.content || msg.replied_message.encrypted_payload.substring(0, 50) + '...'}</span>
                            </span>
                          </div>
                        )}

                        {/* Avatar or timestamp hover */}
                        {!isGrouped ? (
                          <div className={msgStyles.messageAvatar}>
                            {msg.sender_id ? (
                              <img
                                src={`${api.getUserAvatarUrl(msg.sender_id)}`}
                                alt={(msg.author || "?")[0]}
                                style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '50%' }}
                                onError={(e) => {
                                  const img = e.target as HTMLImageElement;
                                  img.style.display = 'none';
                                  if (img.parentElement) {
                                    img.parentElement.textContent = (msg.author || "?")[0];
                                    img.parentElement.setAttribute('style', 'width:40px;height:40px;border-radius:50%;background:var(--brand-primary);color:white;display:flex;align-items:center;justify-content:center;font-weight:600;cursor:pointer;');
                                  }
                                }}
                              />
                            ) : (
                              <div style={{
                                width: '40px', height: '40px', borderRadius: '50%',
                                background: 'var(--brand-primary)', color: 'white',
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                fontWeight: 600, cursor: 'pointer',
                              }}>
                                {(msg.author || "?")[0]}
                              </div>
                            )}
                          </div>
                        ) : (
                          <div className={msgStyles.messageTimestampHover}>
                            <span>{new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                          </div>
                        )}

                        {/* Message content */}
                        <div className={msgStyles.messageContent}>
                          {!isGrouped && (
                            <div className={msgStyles.messageAuthorInfo}>
                              <div className={msgStyles.messageAuthorRow}>
                                {(msg as any)._botResponse && (
                                  <span style={{
                                    fontSize: '10px', fontWeight: 600,
                                    background: 'var(--brand-primary)', color: 'white',
                                    borderRadius: '3px', padding: '1px 4px', marginRight: '4px',
                                    verticalAlign: 'middle',
                                  }}>BOT</span>
                                )}
                                <span
                                  className={msgStyles.messageUsername}
                                  style={{
                                    color: (() => {
                                      const am = ctx.members.find(m => ctx.displayName(m.user) === msg.author || ctx.fingerprint(m.public_key_hash) === msg.author);
                                      return am ? ctx.getMemberRoleColor(am.user_id) : undefined;
                                    })() || undefined
                                  }}
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
                                  }}
                                >{msg.author}</span>
                                <span className={msgStyles.messageTimestamp}>{formatRelativeTime(msg.timestamp)}</span>
                                {msg.edited_at && (
                                  <span className={msgStyles.editedTimestamp} title={`Edited at ${new Date(msg.edited_at).toLocaleString()}`}>(edited)</span>
                                )}
                                {msg.isEncrypted && (
                                  <span style={{ marginLeft: '4px', fontSize: '12px' }} title={
                                    msg.e2eeType === 'double-ratchet' ? 'End-to-end encrypted (Double Ratchet)' : 'Transport encrypted'
                                  }>{msg.e2eeType === 'double-ratchet' ? '🔒' : '🔐'}</span>
                                )}
                                {msg.pinned_at && (
                                  <span style={{ marginLeft: '4px', fontSize: '12px' }} title={`Pinned ${new Date(msg.pinned_at).toLocaleString()}`}>📌</span>
                                )}
                              </div>

                              {/* Message action buttons */}
                              {ctx.appState.user && (
                                <div className={msgStyles.buttons} style={{
                                  position: 'absolute', top: '-16px', right: '0',
                                  display: 'flex', gap: '2px', padding: '2px 4px',
                                  background: 'var(--background-secondary)', borderRadius: '4px',
                                  border: '1px solid var(--background-modifier-accent)',
                                }}>
                                  <button onClick={() => ctx.handleReply(msg)} style={actionBtnStyle} title="Reply">💬</button>
                                  {msg.author === (ctx.appState.user.display_name || ctx.fingerprint(ctx.appState.user.public_key_hash)) && (
                                    <button onClick={() => ctx.handleStartEdit(msg.id, msg.content)} style={actionBtnStyle} title="Edit">✏️</button>
                                  )}
                                  {(msg.author === (ctx.appState.user.display_name || ctx.fingerprint(ctx.appState.user.public_key_hash)) || ctx.canDeleteMessage(msg)) && (
                                    <button onClick={() => ctx.setShowDeleteConfirm(msg.id)} style={actionBtnStyle} title="Delete">🗑️</button>
                                  )}
                                  {ctx.canDeleteMessage(msg) && (
                                    <button onClick={() => msg.pinned_at ? ctx.handleUnpinMessage(msg.id) : ctx.handlePinMessage(msg.id)} style={actionBtnStyle} title={msg.pinned_at ? "Unpin" : "Pin"}>📌</button>
                                  )}
                                </div>
                              )}
                            </div>
                          )}

                          {/* Editing interface */}
                          {ctx.editingMessageId === msg.id ? (
                            <div style={{ marginTop: '4px' }}>
                              <input
                                type="text"
                                value={ctx.editingContent}
                                onChange={(e) => ctx.setEditingContent(e.target.value)}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ctx.handleSaveEdit(); }
                                  else if (e.key === 'Escape') { ctx.handleCancelEdit(); }
                                }}
                                style={{
                                  width: '100%', background: 'var(--background-tertiary)',
                                  border: 'none', borderRadius: '4px', padding: '8px',
                                  color: 'var(--text-primary)', fontSize: '14px',
                                }}
                                autoFocus
                              />
                              <div style={{ display: 'flex', gap: '4px', marginTop: '4px' }}>
                                <button onClick={ctx.handleSaveEdit} style={{ background: 'var(--brand-primary)', border: 'none', borderRadius: '3px', padding: '2px 8px', color: 'white', fontSize: '12px', cursor: 'pointer' }}>Save</button>
                                <button onClick={ctx.handleCancelEdit} style={{ background: 'transparent', border: 'none', padding: '2px 8px', color: 'var(--text-tertiary-muted)', fontSize: '12px', cursor: 'pointer' }}>Cancel</button>
                              </div>
                            </div>
                          ) : (
                            <div
                              className={msgStyles.messageText}
                              dangerouslySetInnerHTML={{ __html: renderMessageMarkdown(msg.content, notificationManager.currentUsername) }}
                            />
                          )}

                          {/* Bot response embed */}
                          {(msg as any)._botResponse?.content?.type === 'embed' && (
                            <BotResponseRenderer
                              content={(msg as any)._botResponse.content}
                              botId={(msg as any)._botResponse.bot_id}
                              onInvokeCommand={(botId, cmd, params) => ctx.handleInvokeBot(botId, cmd, params)}
                            />
                          )}
                        </div>

                        {/* Container: attachments, reactions, etc */}
                        <div className={msgStyles.container}>
                          {/* Thread indicator */}
                          {msg.reply_count != null && msg.reply_count > 0 && (
                            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '13px', color: 'var(--brand-primary)', cursor: 'pointer' }}>
                              <span>💬</span>
                              <span>{msg.reply_count} {msg.reply_count === 1 ? 'reply' : 'replies'}</span>
                            </div>
                          )}

                          {/* File attachments */}
                          {msg.files && msg.files.length > 0 && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
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
                            onMouseEnter={() => ctx.setHoveredMessageId(msg.id)}
                            onMouseLeave={() => ctx.setHoveredMessageId(null)}
                          >
                            {msg.reactions && msg.reactions.length > 0 && (
                              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
                                {msg.reactions.map((reaction) => {
                                  const userReacted = ctx.appState.user && reaction.users.includes(ctx.appState.user.id);
                                  return (
                                    <button
                                      key={reaction.emoji}
                                      onClick={() => ctx.handleToggleReaction(msg.id, reaction.emoji)}
                                      style={{
                                        display: 'flex', alignItems: 'center', gap: '4px',
                                        background: userReacted ? 'var(--brand-primary-light, rgba(88,101,242,0.15))' : 'var(--background-tertiary)',
                                        border: userReacted ? '1px solid var(--brand-primary)' : '1px solid transparent',
                                        borderRadius: '4px', padding: '2px 6px', cursor: 'pointer',
                                        fontSize: '14px', color: 'var(--text-primary)',
                                      }}
                                      title={`${reaction.users.length} reactions`}
                                    >
                                      <span>{reaction.emoji}</span>
                                      <span style={{ fontSize: '12px', fontWeight: 500 }}>{reaction.count}</span>
                                    </button>
                                  );
                                })}
                              </div>
                            )}

                            {ctx.hoveredMessageId === msg.id && ctx.appState.user && (
                              <div style={{ display: 'flex', gap: '2px', marginTop: '4px' }}>
                                {['👍', '❤️', '😂', '🔥', '👀'].map((emoji) => (
                                  <button key={emoji} onClick={() => ctx.handleToggleReaction(msg.id, emoji)} style={quickReactStyle} title={`React with ${emoji}`}>{emoji}</button>
                                ))}
                                <button
                                  onClick={() => ctx.setShowEmojiPicker(ctx.showEmojiPicker === msg.id ? null : msg.id)}
                                  style={quickReactStyle} title="More reactions"
                                >+</button>
                                {ctx.showEmojiPicker === msg.id && (
                                  <div style={{
                                    position: 'absolute', bottom: '100%', right: 0,
                                    background: 'var(--background-tertiary)', borderRadius: '8px',
                                    padding: '8px', display: 'flex', flexWrap: 'wrap', gap: '4px',
                                    zIndex: 10, boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
                                  }}>
                                    {ctx.COMMON_EMOJIS.map((emoji) => (
                                      <button key={emoji} onClick={() => ctx.handleAddReaction(msg.id, emoji)} style={quickReactStyle}>{emoji}</button>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )}
                          </div>

                          {/* Delete confirmation */}
                          {ctx.showDeleteConfirm === msg.id && (
                            <div style={{
                              background: 'var(--background-tertiary)', borderRadius: '4px',
                              padding: '12px', marginTop: '4px',
                            }}>
                              <p style={{ margin: '0 0 8px', color: 'var(--text-primary)', fontSize: '14px' }}>Delete this message?</p>
                              <div style={{ display: 'flex', gap: '8px' }}>
                                <button onClick={() => ctx.handleDeleteMessage(msg.id)} style={{ background: 'var(--status-danger)', border: 'none', borderRadius: '3px', padding: '4px 12px', color: 'white', fontSize: '13px', cursor: 'pointer' }}>Delete</button>
                                <button onClick={() => ctx.setShowDeleteConfirm(null)} style={{ background: 'transparent', border: '1px solid var(--background-modifier-accent)', borderRadius: '3px', padding: '4px 12px', color: 'var(--text-secondary)', fontSize: '13px', cursor: 'pointer' }}>Cancel</button>
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
                            <div style={{ display: 'flex', gap: '2px', justifyContent: 'flex-end', padding: '2px 8px', gridColumn: '4' }}>
                              {readBy.slice(0, 5).map(r => {
                                const member = ctx.members.find(m => m.user_id === r.user_id);
                                const name = member?.profile?.display_name || member?.user?.display_name || r.user_id.substring(0, 6);
                                return (
                                  <span key={r.user_id} title={`Read by ${name}`} style={{
                                    width: '16px', height: '16px', borderRadius: '50%',
                                    backgroundColor: 'var(--brand-primary)', color: 'white',
                                    fontSize: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                  }}>{name[0]?.toUpperCase()}</span>
                                );
                              })}
                              {readBy.length > 5 && <span style={{ fontSize: '10px', color: 'var(--text-tertiary-muted)' }}>+{readBy.length - 5}</span>}
                            </div>
                          );
                        })()}
                      </div>
                    </React.Fragment>
                  );
                })}
              </div>

              {/* Scroll to bottom */}
              {ctx.showScrollToBottom && (
                <button onClick={ctx.scrollToBottom} style={{
                  position: 'sticky', bottom: '8px', alignSelf: 'center',
                  background: 'var(--brand-primary)', color: 'white',
                  border: 'none', borderRadius: '20px', padding: '6px 16px',
                  cursor: 'pointer', fontSize: '13px', fontWeight: 600,
                  boxShadow: '0 2px 8px rgba(0,0,0,0.3)',
                }}>
                  ↓ {ctx.newMessageCount > 0 && <span>{ctx.newMessageCount}</span>}
                </button>
              )}
            </div>
          </div>

          {/* Typing indicator */}
          {ctx.selectedChannelId && ctx.formatTypingUsers(ctx.selectedChannelId) && (
            <div className={typingStyles.typing} style={{ padding: '4px 16px', fontSize: '12px', color: 'var(--text-tertiary-muted)', justifyContent: 'flex-start', gap: '4px' }}>
              <span style={{ display: 'inline-flex', gap: '2px' }}>
                <span style={{ animation: 'blink 1.4s infinite 0s' }}>•</span>
                <span style={{ animation: 'blink 1.4s infinite 0.2s' }}>•</span>
                <span style={{ animation: 'blink 1.4s infinite 0.4s' }}>•</span>
              </span>
              <span>{ctx.formatTypingUsers(ctx.selectedChannelId)}</span>
            </div>
          )}

          {/* Staged files */}
          <StagedFilesPreview files={ctx.stagedFiles} onRemove={ctx.handleRemoveStagedFile} onClear={ctx.handleClearStagedFiles} />

          {/* Bot command form */}
          {pendingCommand && (
            <CommandParamForm bot={pendingCommand.bot} command={pendingCommand.command} onSubmit={handleCommandSubmit} onCancel={() => setPendingCommand(null)} />
          )}

          {/* Voice chat */}
          {ctx.voiceChannelId && (
            <Suspense fallback={<LoadingSpinner />}>
              <VoiceChat
                ws={ctx.ws}
                currentUserId={localStorage.getItem('accord_user_id')}
                channelId={ctx.voiceChannelId}
                channelName={ctx.voiceChannelName}
                onLeave={() => {
                  ctx.setVoiceChannelId(null); ctx.setVoiceChannelName(""); ctx.setVoiceConnectedAt(null);
                  ctx.setVoiceMuted(false); ctx.setVoiceDeafened(false);
                }}
              />
            </Suspense>
          )}

          {/* Message input */}
          <div className={chatStyles.textareaArea}>
            <div style={{ position: 'relative', padding: '0 16px 16px' }}>
              <SlashCommandAutocomplete query={slashQuery} bots={ctx.installedBots} onSelect={handleSlashSelect} visible={showSlashMenu} />
              {ctx.replyingTo && (
                <div className={replyStyles.topBorder} style={{
                  display: 'flex', alignItems: 'center', gap: '8px',
                  padding: '8px 12px', marginBottom: '0',
                  background: 'var(--background-tertiary)', borderRadius: '8px 8px 0 0',
                  fontSize: '13px',
                }}>
                  <span className={replyStyles.text} style={{ flex: 1 }}>
                    Replying to <strong className={replyStyles.authorName}>{ctx.replyingTo.author}</strong>: {ctx.replyingTo.content.substring(0, 100)}
                  </span>
                  <button onClick={ctx.handleCancelReply} className={replyStyles.closeButton}>
                    <svg className={replyStyles.closeIcon} viewBox="0 0 24 24" fill="currentColor"><path d="M18.4 4L12 10.4L5.6 4L4 5.6L10.4 12L4 18.4L5.6 20L12 13.6L18.4 20L20 18.4L13.6 12L20 5.6L18.4 4Z" /></svg>
                  </button>
                </div>
              )}
              {ctx.messageError && (
                <div style={{
                  position: 'absolute', top: '-36px', left: '50%', transform: 'translateX(-50%)',
                  background: 'var(--status-danger)', color: 'white', padding: '6px 14px', borderRadius: '4px',
                  fontSize: '13px', fontWeight: 500, zIndex: 11,
                }}>{ctx.messageError}</div>
              )}
              <div className={textareaStyles.textareaContainer} style={{ borderRadius: ctx.replyingTo ? '0 0 var(--radius-xl, 12px) var(--radius-xl, 12px)' : undefined }}>
                <div className={textareaStyles.textareaWrapper}>
                  <div className={textareaStyles.textareaContent} style={{ flexDirection: 'row', alignItems: 'flex-end', gap: '4px', padding: '4px 8px' }}>
                    {ctx.serverAvailable && ctx.appState.activeChannel && (
                      <FileUploadButton
                        channelId={ctx.appState.activeChannel}
                        token={ctx.appState.token || ''}
                        keyPair={ctx.keyPair}
                        encryptionEnabled={ctx.encryptionEnabled}
                        onFilesStaged={ctx.handleFilesStaged}
                      />
                    )}
                    <textarea
                      ref={ctx.messageInputRef}
                      className={textareaStyles.textarea}
                      placeholder={ctx.slowModeCooldown > 0 ? `Slow mode — wait ${ctx.slowModeCooldown}s` : `Message ${ctx.activeChannel}`}
                      value={ctx.message}
                      rows={1}
                      disabled={ctx.slowModeCooldown > 0}
                      onChange={(e) => {
                        const val = e.target.value;
                        ctx.setMessage(val);
                        e.target.style.height = 'auto';
                        e.target.style.height = Math.min(e.target.scrollHeight, 200) + 'px';
                        if (val.startsWith('/') && val.length > 1 && !val.includes(' ')) {
                          setSlashQuery(val.substring(1)); setShowSlashMenu(true);
                        } else { setShowSlashMenu(false); }
                        if (ctx.selectedChannelId) ctx.sendTypingIndicator(ctx.selectedChannelId);
                      }}
                      onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ctx.handleSendMessage(); } }}
                      style={{ padding: '8px 0', minHeight: '24px', maxHeight: '200px' }}
                    />
                    <EmojiPickerButton
                      isOpen={ctx.showInputEmojiPicker}
                      onToggle={() => ctx.setShowInputEmojiPicker(prev => !prev)}
                      onSelect={ctx.handleInsertEmoji}
                      onClose={() => ctx.setShowInputEmojiPicker(false)}
                      customEmojis={customEmojis}
                      getEmojiUrl={getCustomEmojiUrl}
                    />
                  </div>
                </div>
              </div>
              {ctx.serverAvailable && ctx.appState.activeChannel && (
                <FileList
                  channelId={ctx.appState.activeChannel}
                  token={ctx.appState.token || ''}
                  keyPair={ctx.keyPair}
                  encryptionEnabled={ctx.encryptionEnabled}
                />
              )}
            </div>
          </div>
        </FileDropZone>
      </div>
    </>
  );
};

const actionBtnStyle: React.CSSProperties = {
  background: 'none', border: 'none', cursor: 'pointer', padding: '2px 4px', fontSize: '14px',
  borderRadius: '3px', lineHeight: 1,
};

const quickReactStyle: React.CSSProperties = {
  background: 'var(--background-tertiary)', border: 'none', borderRadius: '4px',
  padding: '2px 6px', cursor: 'pointer', fontSize: '16px',
};
