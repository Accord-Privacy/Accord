import React, { Suspense } from "react";
import clsx from "clsx";
import { useAppContext } from "./AppContext";
import { api, parseInviteLink } from "../api";
import { renderMessageMarkdown } from "../markdown";
import { notificationManager } from "../notifications";
import modalStyles from "./modals/Modal.module.css";
import btnStyles from "./uikit/button/Button.module.css";
import ctxStyles from "./uikit/context_menu/ContextMenu.module.css";
import { SearchOverlay } from "../SearchOverlay";
import { LoadingSpinner } from "../LoadingSpinner";
import { ProfileCard } from "../ProfileCard";
import { LinkPreview, extractFirstUrl } from "../LinkPreview";
import { SHORTCUTS } from "../keyboard";
// Note: WebSocket imports removed — socket management centralized in App.tsx connectSocket()
const NodeSettings = React.lazy(() => import("../NodeSettings").then(m => ({ default: m.NodeSettings })));
const NotificationSettings = React.lazy(() => import("../NotificationSettings").then(m => ({ default: m.NotificationSettings })));
const Settings = React.lazy(() => import("../Settings").then(m => ({ default: m.Settings })));

export const AppModals: React.FC = () => {
  const ctx = useAppContext();

  return (
    <>
      {/* Role Assignment Popup */}
      {ctx.showRolePopup && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, zIndex: 1050 }} onClick={() => ctx.setShowRolePopup(null)}>
          <div style={{
            position: 'absolute',
            top: Math.min(ctx.showRolePopup.y, window.innerHeight - 300),
            left: Math.min(ctx.showRolePopup.x, window.innerWidth - 220),
            background: 'var(--bg-dark)', border: '1px solid #40444b', borderRadius: '6px',
            padding: '8px', minWidth: '200px', maxHeight: '280px', overflowY: 'auto',
            boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 600, padding: '4px 8px', marginBottom: '4px' }}>ASSIGN ROLES</div>
            {ctx.nodeRoles.length === 0 ? (
              <div style={{ padding: '8px', color: 'var(--text-faint)', fontSize: '13px' }}>No roles available</div>
            ) : ctx.nodeRoles.sort((a, b) => b.position - a.position).map(role => {
              const userHasRole = (ctx.memberRolesMap[ctx.showRolePopup!.userId] || []).some(r => r.id === role.id);
              return (
                <label key={role.id} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '13px', color: 'var(--text-secondary)' }}
                  onMouseEnter={e => (e.currentTarget.style.background = '#40444b')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                  <input type="checkbox" checked={userHasRole} onChange={() => ctx.toggleMemberRole(ctx.showRolePopup!.userId, role.id, userHasRole)} />
                  <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: role.color || '#99aab5', flexShrink: 0 }} />
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
          <span style={{ flex: 1 }}>{ctx.error}</span>
          <button onClick={() => ctx.setError("")} className="error-toast-close">×</button>
        </div>
      )}

      {/* Join/Create Node Modal */}
      {ctx.showCreateNodeModal && !ctx.showJoinNodeModal && (
        <div className={modalStyles.layer} style={{ pointerEvents: "auto", zIndex: 1000 }}>
          <div className={clsx(modalStyles.root, modalStyles.small)}>
            <h3>Join a Node</h3>
            <p>Enter an invite link to join an existing community.</p>
            <div className="form-group">
              <label style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.02em", color: "var(--text-tertiary-muted)", display: "block", marginBottom: "6px" }}>Invite Code or Link</label>
              <input type="text" placeholder="accord://host/invite/CODE or just the code" value={ctx.joinInviteCode} onChange={(e) => ctx.setJoinInviteCode(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && ctx.joinInviteCode.trim()) ctx.handleJoinNode(); }} style={{ width: "100%", padding: "10px 12px", fontSize: "14px", backgroundColor: "var(--background-tertiary)", border: "1px solid transparent", borderRadius: "6px", color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const }} />
            </div>
            {ctx.joinError && <div style={{ color: "var(--red)", fontSize: "13px", marginBottom: "12px", padding: "8px 12px", background: "rgba(237,66,69,0.1)", borderRadius: "6px" }}>{ctx.joinError}</div>}
            <div className={clsx(modalStyles.layout, modalStyles.footer)}>
              <button onClick={ctx.handleJoinNode} disabled={ctx.joiningNode || !ctx.joinInviteCode.trim()} className={clsx(btnStyles.button, btnStyles.primary)}>{ctx.joiningNode ? 'Joining...' : 'Join Node'}</button>
              <button onClick={() => { ctx.setShowCreateNodeModal(false); ctx.setJoinInviteCode(""); ctx.setJoinError(""); }} className={clsx(btnStyles.button, btnStyles.secondary)}>Cancel</button>
            </div>
            <div style={{ borderTop: '1px solid var(--border)', marginTop: '16px', paddingTop: '16px', textAlign: 'center' }}>
              <p style={{ fontSize: '13px', opacity: 0.7, marginBottom: '8px' }}>Or create your own community</p>
              <button onClick={() => ctx.setShowJoinNodeModal(true)} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact)}><strong>Create a New Node</strong></button>
            </div>
          </div>
        </div>
      )}

      {/* Create Node Modal */}
      {ctx.showJoinNodeModal && (
        <div className={modalStyles.layer} style={{ pointerEvents: "auto", zIndex: 1000 }}>
          <div className={clsx(modalStyles.root, modalStyles.small)}>
            <h3>Create a Node</h3>
            <p>Start a new community and invite others. A #general channel will be created automatically.</p>
            <div className="form-group">
              <label style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.02em", color: "var(--text-tertiary-muted)", display: "block", marginBottom: "6px" }}>Node Name</label>
              <input type="text" placeholder="My Community" value={ctx.newNodeName} onChange={(e) => {
                const val = e.target.value;
                ctx.setNewNodeName(val);
                if (val.includes('invite/') || val.includes('accord://') || val.match(/^[A-Za-z0-9]{6,}$/)) {
                  const parsed = parseInviteLink(val);
                  if (parsed) {
                    ctx.setNewNodeName("");
                    ctx.setJoinInviteCode(val);
                    ctx.setShowJoinNodeModal(false);
                  }
                }
              }} onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleCreateNode(); }} style={{ width: "100%", padding: "10px 12px", fontSize: "14px", backgroundColor: "var(--background-tertiary)", border: "1px solid transparent", borderRadius: "6px", color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const }} />
              {ctx.newNodeName && parseInviteLink(ctx.newNodeName) && (
                <p style={{ color: 'var(--accent)', fontSize: '12px', marginTop: '4px' }}>
                  💡 This looks like an invite link — <button className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact)} style={{ fontSize: '12px', textDecoration: 'underline' }} onClick={() => { ctx.setJoinInviteCode(ctx.newNodeName); ctx.setNewNodeName(""); ctx.setShowJoinNodeModal(false); }}>switch to Join?</button>
                </p>
              )}
            </div>
            <div className="form-group">
              <label style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.02em", color: "var(--text-tertiary-muted)", display: "block", marginBottom: "6px" }}>Description (optional)</label>
              <input type="text" placeholder="What's this node about?" value={ctx.newNodeDescription} onChange={(e) => ctx.setNewNodeDescription(e.target.value)} style={{ width: "100%", padding: "10px 12px", fontSize: "14px", backgroundColor: "var(--background-tertiary)", border: "1px solid transparent", borderRadius: "6px", color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const }} />
            </div>
            <div className={clsx(modalStyles.layout, modalStyles.footer)}>
              <button onClick={ctx.handleCreateNode} disabled={ctx.creatingNode || !ctx.newNodeName.trim()} className={clsx(btnStyles.button, btnStyles.primary)}>{ctx.creatingNode ? 'Creating...' : 'Create Node'}</button>
              <button onClick={() => { ctx.setShowJoinNodeModal(false); ctx.setNewNodeName(""); ctx.setNewNodeDescription(""); }} className={clsx(btnStyles.button, btnStyles.secondary)}>Cancel</button>
            </div>
            <div style={{ borderTop: '1px solid var(--border)', marginTop: '16px', paddingTop: '16px', textAlign: 'center' }}>
              <button onClick={() => ctx.setShowJoinNodeModal(false)} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact)}>Have an invite code? <strong>Join a Node</strong></button>
            </div>
          </div>
        </div>
      )}

      {/* Invite Modal */}
      {ctx.showInviteModal && (
        <div className={modalStyles.layer} style={{ pointerEvents: "auto", zIndex: 1000 }}>
          <div className={clsx(modalStyles.root, modalStyles.small)}>
            <h3>Invite Link Generated</h3>
            <p>Share this link to invite others to your node. The relay address is encoded for privacy.</p>
            <div className="modal-code-block" style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.85em' }}>{ctx.generatedInvite}</div>
            <div className={clsx(modalStyles.layout, modalStyles.footer)}>
              <button onClick={() => { ctx.copyToClipboard(ctx.generatedInvite).then(() => { alert('Invite code copied to clipboard!'); }); }} className={clsx(btnStyles.button, btnStyles.primary)} style={{ width: 'auto' }}>Copy</button>
              <button onClick={() => { ctx.setShowInviteModal(false); ctx.setGeneratedInvite(""); }} className={clsx(btnStyles.button, btnStyles.secondary)} style={{ width: 'auto' }}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Channel Confirmation */}
      {ctx.deleteChannelConfirm && (
        <div className={modalStyles.layer} style={{ pointerEvents: "auto", zIndex: 1000 }}>
          <div className={clsx(modalStyles.root, modalStyles.small)}>
            <h3>Delete Channel</h3>
            <p>Are you sure you want to delete <strong>#{ctx.deleteChannelConfirm.name}</strong>? This action cannot be undone. All messages will be permanently lost.</p>
            <div className={clsx(modalStyles.layout, modalStyles.footer)}>
              <button onClick={() => ctx.handleDeleteChannelConfirmed(ctx.deleteChannelConfirm!.id)} className={clsx(btnStyles.button, btnStyles.dangerPrimary)}>Delete Channel</button>
              <button onClick={() => ctx.setDeleteChannelConfirm(null)} className={clsx(btnStyles.button, btnStyles.secondary)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Discord Template Import */}
      {ctx.showTemplateImport && ctx.selectedNodeId && (
        <div className={modalStyles.layer} style={{ pointerEvents: "auto", zIndex: 1000 }}>
          <div className={clsx(modalStyles.root, modalStyles.small)} style={{ maxWidth: '480px' }}>
            <h3>📥 Import Discord Template</h3>
            {!ctx.templateResult ? (
              <>
                <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>Paste a discord.new link, discord.com/template link, or raw template code.</p>
                <div className="form-group">
                  <input type="text" placeholder="discord.new/CODE or template code" value={ctx.templateInput} onChange={(e) => ctx.setTemplateInput(e.target.value)} style={{ width: "100%", padding: "10px 12px", fontSize: "14px", backgroundColor: "var(--background-tertiary)", border: "1px solid transparent", borderRadius: "6px", color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const }} disabled={ctx.templateImporting} />
                </div>
                {ctx.templateError && <div style={{ color: 'var(--red)', fontSize: '13px', marginBottom: '8px' }}>{ctx.templateError}</div>}
                <div className={clsx(modalStyles.layout, modalStyles.footer)}>
                  <button className={clsx(btnStyles.button, btnStyles.primary)} disabled={ctx.templateImporting || !ctx.templateInput.trim()} onClick={async () => {
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
                  <button className={clsx(btnStyles.button, btnStyles.secondary)} onClick={() => { ctx.setShowTemplateImport(false); ctx.setTemplateInput(''); ctx.setTemplateError(''); ctx.setTemplateResult(null); }}>Cancel</button>
                </div>
              </>
            ) : (
              <>
                <div style={{ color: 'var(--green)', marginBottom: '12px', fontSize: '14px' }}>✅ Import complete!</div>
                <div style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: '1.6' }}>
                  {ctx.templateResult.roles_created !== undefined && <div>Roles created: <strong>{ctx.templateResult.roles_created}</strong></div>}
                  {ctx.templateResult.channels_created !== undefined && <div>Channels created: <strong>{ctx.templateResult.channels_created}</strong></div>}
                  {ctx.templateResult.categories_created !== undefined && <div>Categories created: <strong>{ctx.templateResult.categories_created}</strong></div>}
                </div>
                <div className={clsx(modalStyles.layout, modalStyles.footer)} style={{ marginTop: '16px' }}>
                  <button className={clsx(btnStyles.button, btnStyles.primary)} onClick={() => {
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
              onNodeUpdated={(_updatedNode) => {
                // This triggers a re-render through parent state
              }}
              onLeaveNode={() => {
                ctx.loadNodes();
              }}
              onShowTemplateImport={() => ctx.setShowTemplateImport(true)}
            />
          </Suspense>
        );
      })()}

      {/* Search Overlay */}
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
            // WebSocket will reconnect automatically when server URL changes
            // via the existing connection's reconnect logic
          }}
        />
      </Suspense>

      {/* Connection Info Modal */}
      {ctx.showConnectionInfo && (
        <div className="settings-overlay" onClick={() => ctx.setShowConnectionInfo(false)}>
          <div className="connection-info-modal" onClick={(e) => e.stopPropagation()}>
            <div className="connection-info-header">
              <h3>Connection Info</h3>
              <button className="settings-close" onClick={() => ctx.setShowConnectionInfo(false)}>×</button>
            </div>
            <div className="connection-info-body">
              <div className="connection-info-row">
                <span className="connection-info-label">Status</span>
                <span className="connection-info-value">{ctx.appState.isConnected ? '🟢 Connected' : '🔴 Disconnected'}</span>
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
                    <code>{ctx.serverBuildHash}</code><span className="copy-hint">📋</span>
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
        <div style={{ position: 'fixed', top: 0, right: 0, width: '400px', height: '100vh', background: 'var(--background)', borderLeft: '1px solid var(--border)', zIndex: 1000, display: 'flex', flexDirection: 'column', color: 'var(--text)' }}>
          <div style={{ padding: '16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600 }}>📌 Pinned Messages</h3>
            <button onClick={() => ctx.setShowPinnedPanel(false)} style={{ background: 'none', border: 'none', fontSize: '18px', cursor: 'pointer', color: 'var(--text)', padding: '4px', borderRadius: '4px' }}>✕</button>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: '16px' }}>
            {ctx.pinnedMessages.length === 0 ? (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', marginTop: '50px' }}>
                <div style={{ fontSize: '48px', marginBottom: '16px' }}>📌</div>
                <p>No pinned messages in this channel yet.</p>
                <p style={{ fontSize: '14px' }}>Pin messages to keep important information easily accessible.</p>
              </div>
            ) : (
              <div>
                {ctx.pinnedMessages.map((msg, i) => (
                  <div key={msg.id || i} style={{ marginBottom: '16px', padding: '12px', background: 'var(--background-modifier-accent)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px', fontSize: '14px' }}>
                      <div style={{ width: '24px', height: '24px', borderRadius: '50%', background: 'var(--primary)', color: 'white', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 600, marginRight: '8px' }}>
                        {(msg.author || "?")[0]}
                      </div>
                      <span style={{ fontWeight: 600, marginRight: '8px' }}>{msg.author}</span>
                      <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{new Date(msg.timestamp).toLocaleDateString()} at {msg.time}</span>
                    </div>
                    <div className="message-content" style={{ marginLeft: '32px', lineHeight: '1.4' }}
                      dangerouslySetInnerHTML={{ __html: renderMessageMarkdown(msg.content, notificationManager.currentUsername) }} />
                    {msg.content && extractFirstUrl(msg.content) && (
                      <div style={{ marginLeft: '32px' }}><LinkPreview content={msg.content} token={ctx.appState.token || ''} /></div>
                    )}
                    <div style={{ marginLeft: '32px', marginTop: '8px', fontSize: '12px', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      📌 Pinned {new Date(msg.pinned_at!).toLocaleDateString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* DM Channel Creation */}
      {ctx.showDmChannelCreate && (
        <div className={modalStyles.layer} style={{ pointerEvents: "auto", zIndex: 1000 }}>
          <div className={clsx(modalStyles.root, modalStyles.small)} style={{ maxWidth: '380px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ margin: 0 }}>Start a Direct Message</h3>
              <button onClick={() => ctx.setShowDmChannelCreate(false)} className="error-toast-close" style={{ color: 'var(--text-muted)' }}>×</button>
            </div>
            <p>Select a user to start a direct message:</p>
            <div style={{ maxHeight: '300px', overflow: 'auto' }}>
              {ctx.members
                .filter(member => member.user_id !== localStorage.getItem('accord_user_id'))
                .map((member) => (
                  <div key={member.user_id} className="member" onClick={() => { ctx.openDmWithUser(member.user); ctx.setShowDmChannelCreate(false); }}>
                    <div className="dm-avatar" style={{ width: '24px', height: '24px', fontSize: '12px', marginRight: '12px' }}>
                      {ctx.displayName(member.user)[0].toUpperCase()}
                    </div>
                    <div>
                      <div style={{ color: 'var(--text-primary)', fontSize: '14px', fontWeight: '500' }}>{ctx.displayName(member.user)}</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{ctx.getRoleBadge(member.role)} {member.role}</div>
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
        <div className={modalStyles.layer} style={{ pointerEvents: "auto", zIndex: 1000 }}>
          <div className={clsx(modalStyles.root, modalStyles.small)}>
            <h3>Set Your Display Name</h3>
            <p>Choose a name that others will see instead of your fingerprint.</p>
            <div className="form-group">
              <label style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.02em", color: "var(--text-tertiary-muted)", display: "block", marginBottom: "6px" }}>Display Name</label>
              <input type="text" placeholder="Enter a display name..." value={ctx.displayNameInput} onChange={(e) => ctx.setDisplayNameInput(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleSaveDisplayName(); }} style={{ width: "100%", padding: "10px 12px", fontSize: "14px", backgroundColor: "var(--background-tertiary)", border: "1px solid transparent", borderRadius: "6px", color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const }} autoFocus maxLength={32} />
            </div>
            <div className={clsx(modalStyles.layout, modalStyles.footer)}>
              <button onClick={ctx.handleSaveDisplayName} disabled={ctx.displayNameSaving || !ctx.displayNameInput.trim()} className={clsx(btnStyles.button, btnStyles.primary)} style={{ width: 'auto' }}>{ctx.displayNameSaving ? 'Saving...' : 'Save'}</button>
              <button onClick={() => ctx.setShowDisplayNamePrompt(false)} className={clsx(btnStyles.button, btnStyles.secondary)} style={{ width: 'auto' }}>Skip</button>
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
        <div className={ctxStyles.contextMenu} style={{ left: ctx.contextMenu.x, top: ctx.contextMenu.y }}>
          <div className={ctxStyles.item}>
            <div style={{ fontWeight: 600, fontSize: '14px' }}>{ctx.contextMenu.displayName}</div>
            <div style={{ fontSize: '11px', color: 'var(--text-faint)', fontFamily: 'var(--font-mono)' }}>{ctx.fingerprint(ctx.contextMenu.publicKeyHash)}</div>
            {ctx.contextMenu.bio && <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>{ctx.contextMenu.bio}</div>}
          </div>
          <div className={ctxStyles.separator}></div>
          <div className={ctxStyles.item} onClick={() => {
            const member = ctx.members.find(m => m.user_id === ctx.contextMenu!.userId);
            ctx.setProfileCardTarget({
              userId: ctx.contextMenu!.userId, x: ctx.contextMenu!.x, y: ctx.contextMenu!.y,
              user: ctx.contextMenu!.user, profile: member?.profile,
              roles: ctx.memberRolesMap[ctx.contextMenu!.userId],
              joinedAt: member?.joined_at, roleColor: ctx.getMemberRoleColor(ctx.contextMenu!.userId),
            });
            ctx.setContextMenu(null);
          }}>👤 View Profile</div>
          {ctx.contextMenu.user && ctx.contextMenu.userId !== localStorage.getItem('accord_user_id') && (
            <div className={ctxStyles.item} onClick={() => {
              if (ctx.contextMenu!.user) ctx.openDmWithUser(ctx.contextMenu!.user);
              ctx.setContextMenu(null);
            }}>💬 Send DM</div>
          )}
          <div className={ctxStyles.separator}></div>
          <div className={ctxStyles.item} onClick={() => {
            ctx.copyToClipboard(ctx.contextMenu!.publicKeyHash);
            ctx.setContextMenu(null);
          }}>📋 Copy Public Key Hash</div>
          {ctx.contextMenu.userId !== localStorage.getItem('accord_user_id') && (
            <>
              <div className={ctxStyles.separator}></div>
              {ctx.blockedUsers.has(ctx.contextMenu.userId) ? (
                <div className={ctxStyles.item} onClick={() => { ctx.handleUnblockUser(ctx.contextMenu!.userId); ctx.setContextMenu(null); }}>✅ Unblock User</div>
              ) : (
                <div className={clsx(ctxStyles.item, ctxStyles.danger)} onClick={() => { ctx.setShowBlockConfirm({ userId: ctx.contextMenu!.userId, displayName: ctx.contextMenu!.displayName }); ctx.setContextMenu(null); }}>🚫 Block User</div>
              )}
            </>
          )}
        </div>
      )}

      {/* Block Confirmation */}
      {ctx.showBlockConfirm && (
        <div className={modalStyles.layer} style={{ pointerEvents: "auto", zIndex: 1000 }} onClick={() => ctx.setShowBlockConfirm(null)}>
          <div className={clsx(modalStyles.root, modalStyles.small)} onClick={(e) => e.stopPropagation()} style={{ maxWidth: '400px' }}>
            <h3>🚫 Block User</h3>
            <p style={{ color: 'var(--text-secondary)', margin: '12px 0' }}>
              Are you sure you want to block <strong>{ctx.showBlockConfirm.displayName}</strong>?
            </p>
            <p style={{ color: 'var(--text-muted)', fontSize: '13px', margin: '8px 0' }}>
              They won't be able to send you direct messages. Their messages in channels will be hidden for you.
            </p>
            <div className={clsx(modalStyles.layout, modalStyles.footer)} style={{ marginTop: '16px', display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button onClick={() => ctx.setShowBlockConfirm(null)} className={clsx(btnStyles.button, btnStyles.secondary)} style={{ width: 'auto' }}>Cancel</button>
              <button onClick={() => ctx.handleBlockUser(ctx.showBlockConfirm!.userId)} className="btn" style={{ width: 'auto', background: 'var(--red, #ed4245)', color: 'var(--text-on-accent)' }}>Block</button>
            </div>
          </div>
        </div>
      )}

      {/* Keyboard Shortcuts Help */}
      {ctx.showShortcutsHelp && (
        <div className={modalStyles.layer} style={{ pointerEvents: "auto", zIndex: 1000 }} onClick={() => ctx.setShowShortcutsHelp(false)}>
          <div className="modal-card shortcuts-modal" onClick={(e) => e.stopPropagation()}>
            <h3>⌨️ Keyboard Shortcuts</h3>
            <div className="shortcuts-list">
              {SHORTCUTS.map((s, i) => (
                <div className="shortcut-row" key={i}><kbd>{s.label}</kbd><span>{s.description}</span></div>
              ))}
            </div>
            <div className={clsx(modalStyles.layout, modalStyles.footer)} style={{ marginTop: '16px' }}>
              <button onClick={() => ctx.setShowShortcutsHelp(false)} className={clsx(btnStyles.button, btnStyles.secondary)} style={{ width: 'auto' }}>Close</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
