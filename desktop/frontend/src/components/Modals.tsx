import React, { Suspense, useEffect, useRef, useCallback } from "react";
import { useAppContext } from "./AppContext";
import { api, parseInviteLink } from "../api";
import { renderMessageMarkdown } from "../markdown";
import { notificationManager } from "../notifications";
const SearchOverlay = React.lazy(() => import("../SearchOverlay").then(m => ({ default: m.SearchOverlay })));
import { LoadingSpinner } from "../LoadingSpinner";
import { ProfileCard } from "../ProfileCard";
import { LinkPreview, extractFirstUrl } from "../LinkPreview";
import { SHORTCUTS } from "../keyboard";
import { Icon } from "./Icon";

/** Hook: trap focus inside a modal and restore focus on close */
function useFocusTrap(isOpen: boolean) {
  const ref = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (isOpen) {
      triggerRef.current = document.activeElement as HTMLElement;
      // Defer focus to after render
      const id = requestAnimationFrame(() => {
        const el = ref.current;
        if (!el) return;
        const focusable = el.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (focusable.length > 0) focusable[0].focus();
      });
      return () => cancelAnimationFrame(id);
    } else if (triggerRef.current) {
      triggerRef.current.focus();
      triggerRef.current = null;
    }
  }, [isOpen]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key !== 'Tab' || !ref.current) return;
    const focusable = ref.current.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey) {
      if (document.activeElement === first) { e.preventDefault(); last.focus(); }
    } else {
      if (document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }, []);

  return { ref, handleKeyDown };
}
// Note: WebSocket imports removed — socket management centralized in App.tsx connectSocket()
const NodeSettings = React.lazy(() => import("../NodeSettings").then(m => ({ default: m.NodeSettings })));
const NotificationSettings = React.lazy(() => import("../NotificationSettings").then(m => ({ default: m.NotificationSettings })));
const Settings = React.lazy(() => import("../Settings").then(m => ({ default: m.Settings })));

export const AppModals: React.FC = () => {
  const ctx = useAppContext();

  const joinNodeTrap = useFocusTrap(!!ctx.showJoinNodeModal && !ctx.showCreateNodeModal);
  const createNodeTrap = useFocusTrap(!!ctx.showCreateNodeModal);
  const inviteTrap = useFocusTrap(!!ctx.showInviteModal);
  const deleteChannelTrap = useFocusTrap(!!ctx.deleteChannelConfirm);
  const templateTrap = useFocusTrap(!!ctx.showTemplateImport);
  const dmCreateTrap = useFocusTrap(!!ctx.showDmChannelCreate);
  const displayNameTrap = useFocusTrap(!!ctx.showDisplayNamePrompt);
  const blockTrap = useFocusTrap(!!ctx.showBlockConfirm);
  const shortcutsTrap = useFocusTrap(!!ctx.showShortcutsHelp);
  const connectionInfoTrap = useFocusTrap(!!ctx.showConnectionInfo);

  return (
    <>
      {/* Role Assignment Popup */}
      {ctx.showRolePopup && (
        <div className="role-popup-overlay" onClick={() => ctx.setShowRolePopup(null)} onKeyDown={(e) => { if (e.key === 'Escape') ctx.setShowRolePopup(null); }}>
          <div
            className="role-popup"
            role="dialog"
            aria-modal="true"
            aria-label="Assign Roles"
            style={{
              top: Math.min(ctx.showRolePopup.y, window.innerHeight - 300),
              left: Math.min(ctx.showRolePopup.x, window.innerWidth - 220),
            }}
            onClick={e => e.stopPropagation()}
          >
            <div className="role-popup-title">ASSIGN ROLES</div>
            {ctx.nodeRoles.length === 0 ? (
              <div className="role-popup-empty">No roles available</div>
            ) : ctx.nodeRoles.sort((a, b) => b.position - a.position).map(role => {
              const userHasRole = (ctx.memberRolesMap[ctx.showRolePopup!.userId] || []).some(r => r.id === role.id);
              return (
                <label key={role.id} className="role-popup-label">
                  <input type="checkbox" checked={userHasRole} onChange={() => ctx.toggleMemberRole(ctx.showRolePopup!.userId, role.id, userHasRole)} />
                  <div className="role-color-dot" style={{ background: role.color || '#99aab5' }} />
                  {role.name}
                </label>
              );
            })}
          </div>
        </div>
      )}

      {/* Error Message */}
      {ctx.error && (
        <div className="error-toast">
          <span className="error-toast-text">{ctx.error}</span>
          <button onClick={() => ctx.setError("")} className="error-toast-close">×</button>
        </div>
      )}

      {/* Join/Create Node Modal */}
      {ctx.showJoinNodeModal && !ctx.showCreateNodeModal && (
        <div className="modal-overlay" onKeyDown={(e) => { if (e.key === 'Escape') { ctx.setShowJoinNodeModal(false); ctx.setJoinInviteCode(""); ctx.setJoinError(""); } joinNodeTrap.handleKeyDown(e); }}>
          <div className="modal-card" ref={joinNodeTrap.ref} role="dialog" aria-modal="true" aria-labelledby="join-node-title">
            <h3 id="join-node-title">Join a Node</h3>
            <p>Enter an invite link to join an existing community.</p>
            <div className="form-group">
              <label className="form-label">Invite Code or Link</label>
              <input type="text" placeholder="accord://host/invite/CODE or just the code" value={ctx.joinInviteCode} onChange={(e) => ctx.setJoinInviteCode(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && ctx.joinInviteCode.trim()) ctx.handleJoinNode(); }} className="form-input" />
            </div>
            {ctx.joinError && <div className="auth-error">{ctx.joinError}</div>}
            <div className="modal-actions">
              <button onClick={ctx.handleJoinNode} disabled={ctx.joiningNode || !ctx.joinInviteCode.trim()} className="btn btn-primary">{ctx.joiningNode ? 'Joining...' : 'Join Node'}</button>
              <button onClick={() => { ctx.setShowJoinNodeModal(false); ctx.setJoinInviteCode(""); ctx.setJoinError(""); }} className="btn btn-outline">Cancel</button>
            </div>
            <div className="modal-divider">
              <p className="modal-divider-text">Or create your own community</p>
              <button onClick={() => ctx.setShowCreateNodeModal(true)} className="btn-ghost"><strong>Create a New Node</strong></button>
            </div>
          </div>
        </div>
      )}

      {/* Create Node Modal */}
      {ctx.showCreateNodeModal && (
        <div className="modal-overlay" onKeyDown={(e) => { if (e.key === 'Escape') { ctx.setShowCreateNodeModal(false); ctx.setNewNodeName(""); ctx.setNewNodeDescription(""); } createNodeTrap.handleKeyDown(e); }}>
          <div className="modal-card" ref={createNodeTrap.ref} role="dialog" aria-modal="true" aria-labelledby="create-node-title">
            <h3 id="create-node-title">Create a Node</h3>
            <p>Start a new community and invite others. A #general channel will be created automatically.</p>
            <div className="form-group">
              <label className="form-label">Node Name</label>
              <input type="text" placeholder="My Community" value={ctx.newNodeName} onChange={(e) => {
                const val = e.target.value;
                ctx.setNewNodeName(val);
                if (val.includes('invite/') || val.includes('accord://') || val.match(/^[A-Za-z0-9]{6,}$/)) {
                  const parsed = parseInviteLink(val);
                  if (parsed) {
                    ctx.setNewNodeName("");
                    ctx.setJoinInviteCode(val);
                    ctx.setShowCreateNodeModal(false);
                  }
                }
              }} onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleCreateNode(); }} className="form-input" />
              {ctx.newNodeName && parseInviteLink(ctx.newNodeName) && (
                <p className="invite-link-hint">
                  This looks like an invite link — <button className="btn-ghost" onClick={() => { ctx.setJoinInviteCode(ctx.newNodeName); ctx.setNewNodeName(""); ctx.setShowCreateNodeModal(false); }}>switch to Join?</button>
                </p>
              )}
            </div>
            <div className="form-group">
              <label className="form-label">Description (optional)</label>
              <input type="text" placeholder="What's this node about?" value={ctx.newNodeDescription} onChange={(e) => ctx.setNewNodeDescription(e.target.value)} className="form-input" />
            </div>
            <div className="modal-actions">
              <button onClick={ctx.handleCreateNode} disabled={ctx.creatingNode || !ctx.newNodeName.trim()} className="btn btn-green">{ctx.creatingNode ? 'Creating...' : 'Create Node'}</button>
              <button onClick={() => { ctx.setShowCreateNodeModal(false); ctx.setNewNodeName(""); ctx.setNewNodeDescription(""); }} className="btn btn-outline">Cancel</button>
            </div>
            <div className="modal-divider">
              <button onClick={() => ctx.setShowCreateNodeModal(false)} className="btn-ghost">Have an invite code? <strong>Join a Node</strong></button>
            </div>
          </div>
        </div>
      )}

      {/* Invite Modal */}
      {ctx.showInviteModal && (
        <div className="modal-overlay" onKeyDown={(e) => { if (e.key === 'Escape') { ctx.setShowInviteModal(false); ctx.setGeneratedInvite(""); } inviteTrap.handleKeyDown(e); }}>
          <div className="modal-card" ref={inviteTrap.ref} role="dialog" aria-modal="true" aria-labelledby="invite-modal-title">
            <h3 id="invite-modal-title">Invite Link Generated</h3>
            <p>Share this link to invite others to your node. The relay address is encoded for privacy.</p>
            <div className="modal-code-block modal-code-block-mono">{ctx.generatedInvite}</div>
            <div className="modal-actions">
              <button onClick={() => { ctx.copyToClipboard(ctx.generatedInvite).then(() => { alert('Invite code copied to clipboard!'); }); }} className="btn btn-primary btn-auto-width">Copy</button>
              <button onClick={() => { ctx.setShowInviteModal(false); ctx.setGeneratedInvite(""); }} className="btn btn-outline btn-auto-width">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Channel Confirmation */}
      {ctx.deleteChannelConfirm && (
        <div className="modal-overlay" onKeyDown={(e) => { if (e.key === 'Escape') ctx.setDeleteChannelConfirm(null); deleteChannelTrap.handleKeyDown(e); }}>
          <div className="modal-card" ref={deleteChannelTrap.ref} role="alertdialog" aria-modal="true" aria-labelledby="delete-channel-title">
            <h3 id="delete-channel-title">Delete Channel</h3>
            <p>Are you sure you want to delete <strong>#{ctx.deleteChannelConfirm.name}</strong>? This action cannot be undone. All messages will be permanently lost.</p>
            <div className="modal-actions">
              <button onClick={() => ctx.handleDeleteChannelConfirmed(ctx.deleteChannelConfirm!.id)} className="btn btn-red">Delete Channel</button>
              <button onClick={() => ctx.setDeleteChannelConfirm(null)} className="btn btn-outline">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Discord Template Import */}
      {ctx.showTemplateImport && ctx.selectedNodeId && (
        <div className="modal-overlay" onKeyDown={(e) => { if (e.key === 'Escape') { ctx.setShowTemplateImport(false); ctx.setTemplateInput(''); ctx.setTemplateError(''); ctx.setTemplateResult(null); } templateTrap.handleKeyDown(e); }}>
          <div className="modal-card modal-card-wide" ref={templateTrap.ref} role="dialog" aria-modal="true" aria-labelledby="template-import-title">
            <h3 id="template-import-title">Import Discord Template</h3>
            {!ctx.templateResult ? (
              <>
                <p className="template-description">Paste a discord.new link, discord.com/template link, or raw template code.</p>
                <div className="form-group">
                  <input type="text" placeholder="discord.new/CODE or template code" value={ctx.templateInput} onChange={(e) => ctx.setTemplateInput(e.target.value)} className="form-input" disabled={ctx.templateImporting} />
                </div>
                {ctx.templateError && <div className="template-error">{ctx.templateError}</div>}
                <div className="modal-actions">
                  <button className="btn btn-green" disabled={ctx.templateImporting || !ctx.templateInput.trim()} onClick={async () => {
                    ctx.setTemplateError('');
                    ctx.setTemplateImporting(true);
                    try {
                      let code = ctx.templateInput.trim();
                      const m1 = code.match(/discord\.new\/([A-Za-z0-9]+)/);
                      const m2 = code.match(/discord\.com\/template\/([A-Za-z0-9]+)/);
                      if (m1) code = m1[1]; else if (m2) code = m2[1];
                      const result = await api.importDiscordTemplate(ctx.selectedNodeId!, code, ctx.appState.token || '');
                      ctx.setTemplateResult(result);
                    } catch (err: any) {
                      ctx.setTemplateError(err.message || 'Import failed');
                    } finally {
                      ctx.setTemplateImporting(false);
                    }
                  }}>
                    {ctx.templateImporting ? '⏳ Importing...' : 'Import'}
                  </button>
                  <button className="btn btn-outline" onClick={() => { ctx.setShowTemplateImport(false); ctx.setTemplateInput(''); ctx.setTemplateError(''); ctx.setTemplateResult(null); }}>Cancel</button>
                </div>
              </>
            ) : (
              <>
                <div className="template-success">✅ Import complete!</div>
                <div className="template-results">
                  {ctx.templateResult.roles_created !== undefined && <div>Roles created: <strong>{ctx.templateResult.roles_created}</strong></div>}
                  {ctx.templateResult.channels_created !== undefined && <div>Channels created: <strong>{ctx.templateResult.channels_created}</strong></div>}
                  {ctx.templateResult.categories_created !== undefined && <div>Categories created: <strong>{ctx.templateResult.categories_created}</strong></div>}
                </div>
                <div className="modal-actions template-results-actions">
                  <button className="btn btn-green" onClick={() => {
                    ctx.setShowTemplateImport(false); ctx.setTemplateInput(''); ctx.setTemplateResult(null); ctx.setTemplateError('');
                    if (ctx.selectedNodeId) { ctx.loadChannels(ctx.selectedNodeId); ctx.loadRoles(ctx.selectedNodeId); }
                  }}>Done</button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Node Settings */}
      {ctx.showNodeSettings && ctx.selectedNodeId && (() => {
        const currentNode = ctx.nodes.find(n => n.id === ctx.selectedNodeId);
        if (!currentNode) return null;
        return (
          <Suspense fallback={<LoadingSpinner />}>
            <NodeSettings
              isOpen={ctx.showNodeSettings}
              onClose={() => ctx.setShowNodeSettings(false)}
              node={currentNode}
              token={ctx.appState.token || ''}
              userRole={ctx.userRoles[ctx.selectedNodeId!] || 'member'}
              onNodeUpdated={(_updatedNode) => {}}
              onLeaveNode={() => { ctx.loadNodes(); }}
              onShowTemplateImport={() => ctx.setShowTemplateImport(true)}
              resolveUserName={(userId: string) => {
                const member = ctx.members.find(m => m.user_id === userId);
                return member ? ctx.displayName(member.user) : '';
              }}
            />
          </Suspense>
        );
      })()}

      {/* Search Overlay */}
      {ctx.showSearchOverlay && (
        <Suspense fallback={<LoadingSpinner />}>
          <SearchOverlay
            isVisible={ctx.showSearchOverlay}
            onClose={() => ctx.setShowSearchOverlay(false)}
            nodeId={ctx.selectedNodeId}
            channels={ctx.channels}
            token={ctx.appState.token || null}
            onNavigateToMessage={ctx.handleNavigateToMessage}
            keyPair={ctx.keyPair}
            encryptionEnabled={ctx.encryptionEnabled}
            currentMessages={ctx.appState.messages}
            currentChannelId={ctx.selectedChannelId || undefined}
          />
        </Suspense>
      )}

      {/* Notification Settings */}
      <Suspense fallback={<LoadingSpinner />}>
        <NotificationSettings
          isOpen={ctx.showNotificationSettings}
          onClose={() => ctx.setShowNotificationSettings(false)}
          preferences={ctx.notificationPreferences}
          onPreferencesChange={ctx.handleNotificationPreferencesChange}
        />
      </Suspense>

      {/* Settings */}
      <Suspense fallback={<LoadingSpinner />}>
        <Settings
          isOpen={ctx.showSettings}
          onClose={() => ctx.setShowSettings(false)}
          onShowShortcuts={() => ctx.setShowShortcutsHelp(true)}
          currentUser={ctx.appState.user}
          knownHashes={ctx.knownHashes}
          serverInfo={{
            version: ctx.serverHelloVersion,
            buildHash: ctx.serverBuildHash,
            connectedSince: ctx.connectedSince,
            relayAddress: api.getBaseUrl(),
            isConnected: ctx.appState.isConnected,
          }}
          onUserUpdate={(updates) => {
            if (ctx.appState.user) {
              ctx.setAppState(prev => ({ ...prev, user: { ...prev.user!, ...updates } }));
            }
          }}
          blockedUsers={ctx.blockedUsers}
          onUnblockUser={ctx.handleUnblockUser}
          onLogout={ctx.handleLogout}
          onRelayChange={async (newUrl) => {
            if (ctx.ws) { ctx.ws.disconnect(); }
            ctx.setServerUrl(newUrl);
            api.setBaseUrl(newUrl);
          }}
        />
      </Suspense>

      {/* Connection Info Modal */}
      {ctx.showConnectionInfo && (
        <div className="settings-overlay" onClick={() => ctx.setShowConnectionInfo(false)} onKeyDown={(e) => { if (e.key === 'Escape') ctx.setShowConnectionInfo(false); connectionInfoTrap.handleKeyDown(e); }}>
          <div className="connection-info-modal" ref={connectionInfoTrap.ref} role="dialog" aria-modal="true" aria-labelledby="connection-info-title" onClick={(e) => e.stopPropagation()}>
            <div className="connection-info-header">
              <h3 id="connection-info-title">Connection Info</h3>
              <button className="settings-close" onClick={() => ctx.setShowConnectionInfo(false)}>×</button>
            </div>
            <div className="connection-info-body">
              <div className="connection-info-row">
                <span className="connection-info-label">Status</span>
                <span className="connection-info-value">{ctx.appState.isConnected ? 'Connected' : 'Disconnected'}</span>
              </div>
              {ctx.serverHelloVersion && (
                <div className="connection-info-row">
                  <span className="connection-info-label">Server Version</span>
                  <span className="connection-info-value">{ctx.serverHelloVersion}</span>
                </div>
              )}
              {ctx.serverBuildHash && (
                <div className="connection-info-row">
                  <span className="connection-info-label">Build Hash</span>
                  <span className="connection-info-value copyable" title="Click to copy" onClick={() => { ctx.copyToClipboard(ctx.serverBuildHash); }}>
                    <code>{ctx.serverBuildHash}</code>
                  </span>
                </div>
              )}
              {ctx.connectedSince && (
                <div className="connection-info-row">
                  <span className="connection-info-label">Connected Since</span>
                  <span className="connection-info-value">{new Date(ctx.connectedSince).toLocaleString()}</span>
                </div>
              )}
              <div className="connection-info-row">
                <span className="connection-info-label">Relay Address</span>
                <span className="connection-info-value"><code>{api.getBaseUrl()}</code></span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Pinned Messages Panel */}
      {ctx.showPinnedPanel && (
        <div className="pinned-panel" role="complementary" aria-label="Pinned Messages" onKeyDown={(e) => { if (e.key === 'Escape') ctx.setShowPinnedPanel(false); }}>
          <div className="pinned-panel-header">
            <h3 className="pinned-panel-title">Pinned Messages</h3>
            <button onClick={() => ctx.setShowPinnedPanel(false)} className="pinned-panel-close" aria-label="Close pinned messages">✕</button>
          </div>
          <div className="pinned-panel-body">
            {ctx.pinnedMessages.length === 0 ? (
              <div className="pinned-panel-empty">
                <div className="pinned-panel-empty-icon"><Icon name="pin" size={40} /></div>
                <div className="pinned-panel-empty-title">No pinned messages</div>
                <p>Pin messages to keep important information easily accessible.</p>
              </div>
            ) : (
              <div>
                {ctx.pinnedMessages.map((msg, i) => (
                  <div key={msg.id || i} className="pinned-message-card">
                    <div className="pinned-message-header">
                      <div className="pinned-message-avatar">
                        {(msg.author || "?")[0]}
                      </div>
                      <span className="pinned-message-author">{msg.author}</span>
                      <span className="pinned-message-time">{new Date(msg.timestamp).toLocaleDateString()} at {msg.time}</span>
                    </div>
                    <div className="message-content pinned-message-content"
                      dangerouslySetInnerHTML={{ __html: renderMessageMarkdown(msg.content, notificationManager.currentUsername) }} />
                    {msg.content && extractFirstUrl(msg.content) && (
                      <div className="pinned-message-preview"><LinkPreview content={msg.content} token={ctx.appState.token || ''} /></div>
                    )}
                    <div className="pinned-message-meta">
                      <span>Pinned {new Date(msg.pinned_at!).toLocaleDateString()}</span>
                      <button
                        className="pinned-message-unpin"
                        title="Unpin message"
                        aria-label="Unpin message"
                        onClick={async (e) => {
                          e.stopPropagation();
                          if (!ctx.appState.token) return;
                          try {
                            await api.unpinMessage(msg.id, ctx.appState.token);
                            // Close and reopen to refresh
                            ctx.setShowPinnedPanel(false);
                          } catch { /* ignore */ }
                        }}
                      >
                        <Icon name="close" size={14} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Thread Panel */}
      {ctx.threadParentMessage && (
        <div className="pinned-panel" role="complementary" aria-label="Thread" onKeyDown={(e) => { if (e.key === 'Escape') ctx.closeThread(); }}>
          <div className="pinned-panel-header">
            <h3 className="pinned-panel-title">Thread</h3>
            <button onClick={ctx.closeThread} className="pinned-panel-close" aria-label="Close thread">✕</button>
          </div>
          <div className="pinned-panel-body">
            {/* Parent message */}
            <div className="pinned-message-card thread-parent-card">
              <div className="pinned-message-header">
                <div className="pinned-message-avatar">
                  {(ctx.threadParentMessage.author || "?")[0]}
                </div>
                <span className="pinned-message-author">{ctx.threadParentMessage.author}</span>
                <span className="pinned-message-time">{new Date(ctx.threadParentMessage.timestamp).toLocaleDateString()} at {ctx.threadParentMessage.time}</span>
              </div>
              <div className="message-content pinned-message-content"
                dangerouslySetInnerHTML={{ __html: renderMessageMarkdown(ctx.threadParentMessage.content, notificationManager.currentUsername) }} />
            </div>

            <div className="thread-replies-divider">
              <span>{ctx.threadParentMessage.reply_count || 0} {ctx.threadParentMessage.reply_count === 1 ? 'reply' : 'replies'}</span>
            </div>

            {/* Thread replies */}
            {ctx.threadLoading ? (
              <div className="pinned-panel-empty">
                <LoadingSpinner />
              </div>
            ) : ctx.threadMessages.length === 0 ? (
              <div className="pinned-panel-empty">
                <div className="pinned-panel-empty-title">No replies yet</div>
              </div>
            ) : (
              <div>
                {ctx.threadMessages.map((msg, i) => (
                  <div key={msg.id || i} className="pinned-message-card">
                    <div className="pinned-message-header">
                      <div className="pinned-message-avatar">
                        {(msg.author || "?")[0]}
                      </div>
                      <span className="pinned-message-author">{msg.author}</span>
                      <span className="pinned-message-time">{new Date(msg.timestamp).toLocaleDateString()} at {msg.time}</span>
                    </div>
                    <div className="message-content pinned-message-content"
                      dangerouslySetInnerHTML={{ __html: renderMessageMarkdown(msg.content, notificationManager.currentUsername) }} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* DM Channel Creation */}
      {ctx.showDmChannelCreate && (
        <div className="modal-overlay" onKeyDown={(e) => { if (e.key === 'Escape') ctx.setShowDmChannelCreate(false); dmCreateTrap.handleKeyDown(e); }}>
          <div className="modal-card modal-card-narrow" ref={dmCreateTrap.ref} role="dialog" aria-modal="true" aria-labelledby="dm-create-title">
            <div className="dm-create-header">
              <h3 id="dm-create-title">Start a Direct Message</h3>
              <button onClick={() => ctx.setShowDmChannelCreate(false)} className="error-toast-close" aria-label="Close">×</button>
            </div>
            <p>Select a user to start a direct message:</p>
            <div className="dm-create-list">
              {ctx.members
                .filter(member => member.user_id !== localStorage.getItem('accord_user_id'))
                .map((member) => (
                  <div key={member.user_id} className="member" onClick={() => { ctx.openDmWithUser(member.user); ctx.setShowDmChannelCreate(false); }}>
                    <div className="dm-avatar dm-avatar-sm">
                      {ctx.displayName(member.user)[0].toUpperCase()}
                    </div>
                    <div>
                      <div className="dm-create-user-name">{ctx.displayName(member.user)}</div>
                      <div className="dm-create-user-role">{ctx.getRoleBadge(member.role)} {member.role}</div>
                    </div>
                  </div>
                ))}
              {ctx.members.filter(member => member.user_id !== localStorage.getItem('accord_user_id')).length === 0 && (
                <div className="members-empty">No other members available</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Display Name Prompt */}
      {ctx.showDisplayNamePrompt && (
        <div className="modal-overlay" onKeyDown={(e) => { if (e.key === 'Escape') ctx.setShowDisplayNamePrompt(false); displayNameTrap.handleKeyDown(e); }}>
          <div className="modal-card" ref={displayNameTrap.ref} role="dialog" aria-modal="true" aria-labelledby="display-name-title">
            <h3 id="display-name-title">Set Your Display Name</h3>
            <p>Choose a name that others will see instead of your fingerprint.</p>
            <div className="form-group">
              <label className="form-label">Display Name</label>
              <input type="text" placeholder="Enter a display name..." value={ctx.displayNameInput} onChange={(e) => ctx.setDisplayNameInput(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleSaveDisplayName(); }} className="form-input" autoFocus maxLength={32} />
            </div>
            <div className="modal-actions">
              <button onClick={ctx.handleSaveDisplayName} disabled={ctx.displayNameSaving || !ctx.displayNameInput.trim()} className="btn btn-green btn-auto-width">{ctx.displayNameSaving ? 'Saving...' : 'Save'}</button>
              <button onClick={() => ctx.setShowDisplayNamePrompt(false)} className="btn btn-outline btn-auto-width">Skip</button>
            </div>
          </div>
        </div>
      )}

      {/* Profile Card */}
      {ctx.profileCardTarget && (
        <ProfileCard
          userId={ctx.profileCardTarget.userId}
          anchorX={ctx.profileCardTarget.x}
          anchorY={ctx.profileCardTarget.y}
          currentUserId={localStorage.getItem('accord_user_id') || ''}
          token={ctx.appState.token || ''}
          nodeId={ctx.selectedNodeId || undefined}
          profile={ctx.profileCardTarget.profile}
          user={ctx.profileCardTarget.user}
          roles={ctx.profileCardTarget.roles}
          joinedAt={ctx.profileCardTarget.joinedAt}
          roleColor={ctx.profileCardTarget.roleColor}
          onClose={() => ctx.setProfileCardTarget(null)}
          onSendDm={(user) => { ctx.openDmWithUser(user); ctx.setProfileCardTarget(null); }}
          onBlock={(uid, name) => { ctx.setShowBlockConfirm({ userId: uid, displayName: name }); ctx.setProfileCardTarget(null); }}
          onEditProfile={() => { ctx.setProfileCardTarget(null); ctx.setShowSettings(true); }}
        />
      )}

      {/* Context Menu */}
      {ctx.contextMenu && (
        <>
          <div className="context-menu-backdrop" onClick={() => ctx.setContextMenu(null)} />
          <div className="context-menu" role="menu" aria-label="User actions" style={{ left: ctx.contextMenu.x, top: ctx.contextMenu.y }} onKeyDown={(e) => { if (e.key === 'Escape') ctx.setContextMenu(null); }}>
            <div className="context-menu-item context-menu-profile-header">
              <div className="context-menu-display-name">{ctx.contextMenu.displayName}</div>
              <div className="context-menu-fingerprint">{ctx.fingerprint(ctx.contextMenu.publicKeyHash)}</div>
              {ctx.contextMenu.bio && <div className="context-menu-bio">{ctx.contextMenu.bio}</div>}
            </div>
            <div className="context-menu-separator"></div>
            <div className="context-menu-item" onClick={() => {
              const member = ctx.members.find(m => m.user_id === ctx.contextMenu!.userId);
              ctx.setProfileCardTarget({
                userId: ctx.contextMenu!.userId, x: ctx.contextMenu!.x, y: ctx.contextMenu!.y,
                user: ctx.contextMenu!.user, profile: member?.profile,
                roles: ctx.memberRolesMap[ctx.contextMenu!.userId],
                joinedAt: member?.joined_at, roleColor: ctx.getMemberRoleColor(ctx.contextMenu!.userId),
              });
              ctx.setContextMenu(null);
            }}><span className="context-menu-icon"><Icon name="members" size={16} /></span>View Profile</div>
            {ctx.contextMenu.user && ctx.contextMenu.userId !== localStorage.getItem('accord_user_id') && (
              <div className="context-menu-item" onClick={() => {
                if (ctx.contextMenu!.user) ctx.openDmWithUser(ctx.contextMenu!.user);
                ctx.setContextMenu(null);
              }}><span className="context-menu-icon"><Icon name="chat" size={16} /></span>Send DM</div>
            )}
            <div className="context-menu-separator"></div>
            <div className="context-menu-item" onClick={() => {
              ctx.copyToClipboard(ctx.contextMenu!.publicKeyHash);
              ctx.setContextMenu(null);
            }}><span className="context-menu-icon"><Icon name="key" size={16} /></span>Copy Public Key Hash</div>
            {ctx.contextMenu.userId !== localStorage.getItem('accord_user_id') && (
              <>
                <div className="context-menu-separator"></div>
                {ctx.blockedUsers.has(ctx.contextMenu.userId) ? (
                  <div className="context-menu-item" onClick={() => { ctx.handleUnblockUser(ctx.contextMenu!.userId); ctx.setContextMenu(null); }}><span className="context-menu-icon"><Icon name="shield" size={16} /></span>Unblock User</div>
                ) : (
                  <div className="context-menu-item context-menu-item-danger" onClick={() => { ctx.setShowBlockConfirm({ userId: ctx.contextMenu!.userId, displayName: ctx.contextMenu!.displayName }); ctx.setContextMenu(null); }}><span className="context-menu-icon"><Icon name="shield" size={16} /></span>Block User</div>
                )}
              </>
            )}
          </div>
        </>
      )}

      {/* Block Confirmation */}
      {ctx.showBlockConfirm && (
        <div className="modal-overlay" onClick={() => ctx.setShowBlockConfirm(null)} onKeyDown={(e) => { if (e.key === 'Escape') ctx.setShowBlockConfirm(null); blockTrap.handleKeyDown(e); }}>
          <div className="modal-card modal-card-narrow" ref={blockTrap.ref} role="alertdialog" aria-modal="true" aria-labelledby="block-user-title" onClick={(e) => e.stopPropagation()}>
            <h3 id="block-user-title">Block User</h3>
            <p className="block-confirm-text">
              Are you sure you want to block <strong>{ctx.showBlockConfirm.displayName}</strong>?
            </p>
            <p className="block-confirm-detail">
              They won't be able to send you direct messages. Their messages in channels will be hidden for you.
            </p>
            <div className="block-confirm-actions">
              <button onClick={() => ctx.setShowBlockConfirm(null)} className="btn btn-outline btn-auto-width">Cancel</button>
              <button onClick={() => ctx.handleBlockUser(ctx.showBlockConfirm!.userId)} className="btn btn-red btn-auto-width">Block</button>
            </div>
          </div>
        </div>
      )}

      {/* Keyboard Shortcuts Help */}
      {ctx.showShortcutsHelp && (
        <div className="modal-overlay" onClick={() => ctx.setShowShortcutsHelp(false)} onKeyDown={(e) => { if (e.key === 'Escape') ctx.setShowShortcutsHelp(false); shortcutsTrap.handleKeyDown(e); }}>
          <div className="modal-card shortcuts-modal" ref={shortcutsTrap.ref} role="dialog" aria-modal="true" aria-labelledby="shortcuts-title" onClick={(e) => e.stopPropagation()}>
            <h3 id="shortcuts-title">Keyboard Shortcuts</h3>
            <div className="shortcuts-list">
              {SHORTCUTS.map((s, i) => (
                <div className="shortcut-row" key={i}><kbd>{s.label}</kbd><span>{s.description}</span></div>
              ))}
            </div>
            <div className="modal-actions shortcuts-modal-actions">
              <button onClick={() => ctx.setShowShortcutsHelp(false)} className="btn btn-outline btn-auto-width">Close</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
