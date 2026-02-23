import { useState, useCallback, useEffect } from 'react';
import { api } from './api';
import { Node, AuditLogEntry, Role, CustomEmoji } from './types';

interface Invite {
  code: string;
  created_at: number;
  max_uses?: number;
  expires_at?: number;
  uses: number;
}

interface NodeSettingsProps {
  isOpen: boolean;
  onClose: () => void;
  node: Node;
  token: string;
  userRole: 'admin' | 'moderator' | 'member';
  onNodeUpdated?: (node: Node) => void;
  onLeaveNode?: () => void;
  onShowTemplateImport?: () => void;
}

export function NodeSettings({ 
  isOpen, 
  onClose, 
  node, 
  token, 
  userRole, 
  onNodeUpdated,
  onLeaveNode,
  onShowTemplateImport,
}: NodeSettingsProps) {
  const [activeTab, setActiveTab] = useState<'general' | 'invites' | 'roles' | 'members' | 'audit' | 'moderation' | 'emojis'>('general');
  const [invites, setInvites] = useState<Invite[]>([]);
  const [loadingInvites, setLoadingInvites] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Audit log state
  const [auditEntries, setAuditEntries] = useState<AuditLogEntry[]>([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [auditFilter, setAuditFilter] = useState<string>('all');
  const [hasMoreAudit, setHasMoreAudit] = useState(true);
  const [nextAuditCursor, setNextAuditCursor] = useState<string | undefined>();

  // General settings state
  const [nodeName, setNodeName] = useState(node.name);
  const [nodeDescription, setNodeDescription] = useState(node.description || '');
  const [isUpdating, setIsUpdating] = useState(false);

  // Create invite state
  const [showCreateInvite, setShowCreateInvite] = useState(false);
  const [maxUses, setMaxUses] = useState<string>('');
  const [expiresHours, setExpiresHours] = useState<string>('');
  const [creatingInvite, setCreatingInvite] = useState(false);

  // Roles state
  const [roles, setRoles] = useState<Role[]>([]);
  const [loadingRoles, setLoadingRoles] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [showCreateRole, setShowCreateRole] = useState(false);
  const [newRoleName, setNewRoleName] = useState('New Role');
  const [newRoleColor, setNewRoleColor] = useState('#99aab5');
  const [newRoleHoist, setNewRoleHoist] = useState(false);
  const [newRoleMentionable, setNewRoleMentionable] = useState(false);
  const [editRoleName, setEditRoleName] = useState('');
  const [editRoleColor, setEditRoleColor] = useState('#99aab5');
  const [editRoleHoist, setEditRoleHoist] = useState(false);
  const [editRoleMentionable, setEditRoleMentionable] = useState(false);
  const [editRolePermissions, setEditRolePermissions] = useState(0);
  const [savingRole, setSavingRole] = useState(false);

  // Moderation state
  const [autoModWords, setAutoModWords] = useState<Array<{ word: string; action: string; created_at: number }>>([]);
  const [loadingAutoMod, setLoadingAutoMod] = useState(false);
  const [newWord, setNewWord] = useState('');
  const [newWordAction, setNewWordAction] = useState<'block' | 'warn'>('block');
  const [slowModeChannels, setSlowModeChannels] = useState<Record<string, number>>({});
  const [nodeChannels, setNodeChannels] = useState<Array<{ id: string; name: string }>>([]);

  // Custom emoji state
  const [customEmojis, setCustomEmojis] = useState<CustomEmoji[]>([]);
  const [loadingEmojis, setLoadingEmojis] = useState(false);
  const [newEmojiName, setNewEmojiName] = useState('');
  const [newEmojiFile, setNewEmojiFile] = useState<File | null>(null);
  const [uploadingEmoji, setUploadingEmoji] = useState(false);

  const isAdmin = userRole === 'admin';
  const canManageInvites = userRole === 'admin' || userRole === 'moderator';
  const canManageRoles = userRole === 'admin';
  const canViewAuditLog = userRole === 'admin' || userRole === 'moderator';

  const loadInvites = useCallback(async () => {
    if (!canManageInvites) return;
    setLoadingInvites(true);
    setError('');
    try {
      const nodeInvites = await api.getNodeInvites(node.id, token);
      setInvites(nodeInvites);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to load invites');
    } finally {
      setLoadingInvites(false);
    }
  }, [node.id, token, canManageInvites]);

  const loadRoles = useCallback(async () => {
    if (!canManageRoles) return;
    setLoadingRoles(true);
    try {
      const nodeRoles = await api.getRoles(node.id, token);
      setRoles((Array.isArray(nodeRoles) ? nodeRoles : []).sort((a: Role, b: Role) => b.position - a.position));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load roles');
    } finally {
      setLoadingRoles(false);
    }
  }, [node.id, token, canManageRoles]);

  const handleCreateRole = useCallback(async () => {
    setSavingRole(true);
    setError('');
    try {
      await api.createRole(node.id, token, {
        name: newRoleName,
        color: newRoleColor,
        hoist: newRoleHoist,
        mentionable: newRoleMentionable,
      });
      setSuccess('Role created!');
      setShowCreateRole(false);
      setNewRoleName('New Role');
      setNewRoleColor('#99aab5');
      setNewRoleHoist(false);
      setNewRoleMentionable(false);
      await loadRoles();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create role');
    } finally {
      setSavingRole(false);
    }
  }, [node.id, token, newRoleName, newRoleColor, newRoleHoist, newRoleMentionable, loadRoles]);

  const handleSaveRole = useCallback(async () => {
    if (!editingRole) return;
    setSavingRole(true);
    setError('');
    try {
      await api.updateRole(node.id, editingRole.id, token, {
        name: editRoleName,
        color: editRoleColor,
        hoist: editRoleHoist,
        mentionable: editRoleMentionable,
        permissions: editRolePermissions,
      });
      setSuccess('Role updated!');
      setEditingRole(null);
      await loadRoles();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update role');
    } finally {
      setSavingRole(false);
    }
  }, [node.id, token, editingRole, editRoleName, editRoleColor, editRoleHoist, editRoleMentionable, editRolePermissions, loadRoles]);

  const handleDeleteRole = useCallback(async (roleId: string) => {
    if (!confirm('Delete this role? Members will lose it.')) return;
    try {
      await api.deleteRole(node.id, roleId, token);
      setSuccess('Role deleted!');
      if (editingRole?.id === roleId) setEditingRole(null);
      await loadRoles();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete role');
    }
  }, [node.id, token, editingRole, loadRoles]);

  const handleMoveRole = useCallback(async (roleId: string, direction: 'up' | 'down') => {
    const idx = roles.findIndex(r => r.id === roleId);
    if (idx < 0) return;
    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (swapIdx < 0 || swapIdx >= roles.length) return;
    try {
      const thisRole = roles[idx];
      const otherRole = roles[swapIdx];
      await api.updateRole(node.id, thisRole.id, token, { position: otherRole.position });
      await api.updateRole(node.id, otherRole.id, token, { position: thisRole.position });
      await loadRoles();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reorder roles');
    }
  }, [node.id, token, roles, loadRoles]);

  const startEditRole = useCallback((role: Role) => {
    setEditingRole(role);
    setEditRoleName(role.name);
    setEditRoleColor(role.color || '#99aab5');
    setEditRoleHoist(role.hoist);
    setEditRoleMentionable(role.mentionable);
    setEditRolePermissions(role.permissions);
  }, []);

  const PERMISSIONS = [
    { bit: 1, label: 'Manage Channels' },
    { bit: 2, label: 'Manage Members' },
    { bit: 4, label: 'Kick Members' },
    { bit: 8, label: 'Manage Invites' },
    { bit: 16, label: 'Manage Node' },
    { bit: 32, label: 'Manage Roles' },
    { bit: 64, label: 'Manage Messages' },
  ];

  const handleCreateInvite = useCallback(async () => {
    setCreatingInvite(true);
    setError('');
    try {
      const maxUsesNum = maxUses ? parseInt(maxUses, 10) : undefined;
      const expiresHoursNum = expiresHours ? parseInt(expiresHours, 10) : undefined;
      await api.createInviteWithOptions(node.id, token, maxUsesNum, expiresHoursNum);
      setSuccess('Invite created successfully!');
      setMaxUses('');
      setExpiresHours('');
      setShowCreateInvite(false);
      await loadInvites();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to create invite');
    } finally {
      setCreatingInvite(false);
    }
  }, [node.id, token, maxUses, expiresHours, loadInvites]);

  const handleRevokeInvite = useCallback(async (inviteCode: string) => {
    if (!confirm('Are you sure you want to revoke this invite?')) return;
    try {
      await api.revokeInvite(node.id, inviteCode, token);
      setSuccess('Invite revoked successfully!');
      await loadInvites();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to revoke invite');
    }
  }, [node.id, token, loadInvites]);

  const loadAuditLog = useCallback(async (reset: boolean = false) => {
    if (!canViewAuditLog) return;
    setLoadingAudit(true);
    setError('');
    try {
      const cursor = reset ? undefined : nextAuditCursor;
      const response = await api.getNodeAuditLog(node.id, token, 50, cursor);
      const entries = Array.isArray(response?.entries) ? response.entries : [];
      if (reset) {
        setAuditEntries(entries);
      } else {
        setAuditEntries(prev => [...prev, ...entries]);
      }
      setHasMoreAudit(response?.has_more ?? false);
      setNextAuditCursor(response?.next_cursor);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to load audit log');
    } finally {
      setLoadingAudit(false);
    }
  }, [node.id, token, canViewAuditLog, nextAuditCursor]);

  const loadMoreAudit = useCallback(async () => {
    if (!hasMoreAudit || loadingAudit) return;
    await loadAuditLog(false);
  }, [hasMoreAudit, loadingAudit, loadAuditLog]);

  const getFilteredAuditEntries = useCallback(() => {
    if (auditFilter === 'all') return auditEntries;
    return auditEntries.filter(entry => entry.action === auditFilter);
  }, [auditEntries, auditFilter]);

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'channel_create': return '📝';
      case 'channel_delete': return '🗑️';
      case 'member_kick': return '👢';
      case 'member_ban': return '🔨';
      case 'role_change': return '👑';
      case 'invite_create': return '📬';
      case 'invite_revoke': return '🚫';
      case 'message_pin': return '📌';
      case 'message_unpin': return '📌';
      case 'message_delete': return '❌';
      case 'node_settings_update': return '⚙️';
      default: return '📄';
    }
  };

  const getActionDescription = (entry: AuditLogEntry) => {
    const details = entry.details ? JSON.parse(entry.details) : {};
    switch (entry.action) {
      case 'channel_create': return `created channel #${details.channel_name || 'unknown'}`;
      case 'channel_delete': return `deleted channel #${details.channel_name || 'unknown'}`;
      case 'member_kick': return `kicked a user`;
      case 'member_ban': return `banned a user`;
      case 'role_change': return `changed user role to ${details.new_role || 'unknown'}`;
      case 'invite_create': return `created an invite`;
      case 'invite_revoke': return `revoked invite ${details.invite_code || 'unknown'}`;
      case 'message_pin': return `pinned a message`;
      case 'message_unpin': return `unpinned a message`;
      case 'message_delete': return `deleted a message`;
      case 'node_settings_update': return `updated node settings`;
      default: return entry.action.replace(/_/g, ' ');
    }
  };

  const loadAutoModWords = useCallback(async () => {
    if (!isAdmin) return;
    setLoadingAutoMod(true);
    try {
      const result = await api.getAutoModWords(node.id, token);
      setAutoModWords(result.words || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load auto-mod words');
    } finally {
      setLoadingAutoMod(false);
    }
  }, [node.id, token, isAdmin]);

  const handleAddWord = useCallback(async () => {
    if (!newWord.trim()) return;
    try {
      await api.addAutoModWord(node.id, newWord.trim(), newWordAction, token);
      setNewWord('');
      setSuccess('Word added to filter!');
      await loadAutoModWords();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add word');
    }
  }, [node.id, token, newWord, newWordAction, loadAutoModWords]);

  const handleRemoveWord = useCallback(async (word: string) => {
    try {
      await api.removeAutoModWord(node.id, word, token);
      setSuccess('Word removed from filter!');
      await loadAutoModWords();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove word');
    }
  }, [node.id, token, loadAutoModWords]);

  const loadNodeChannelsForMod = useCallback(async () => {
    try {
      const channels = await api.getNodeChannels(node.id, token);
      setNodeChannels(channels.map((c: any) => ({ id: c.id, name: c.name })));
      const modes: Record<string, number> = {};
      for (const ch of channels) {
        try {
          const result = await api.getSlowMode(ch.id, token);
          modes[ch.id] = result.slow_mode_seconds || 0;
        } catch { /* ignore */ }
      }
      setSlowModeChannels(modes);
    } catch { /* ignore */ }
  }, [node.id, token]);

  const handleSetSlowMode = useCallback(async (channelId: string, seconds: number) => {
    try {
      await api.setSlowMode(channelId, seconds, token);
      setSlowModeChannels(prev => ({ ...prev, [channelId]: seconds }));
      setSuccess(`Slow mode ${seconds > 0 ? `set to ${seconds}s` : 'disabled'}!`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to set slow mode');
    }
  }, [token]);

  const handleUpdateNode = useCallback(async () => {
    if (!isAdmin) return;
    setIsUpdating(true);
    setError('');
    try {
      setSuccess('Node settings saved!');
      if (onNodeUpdated) {
        onNodeUpdated({ ...node, name: nodeName, description: nodeDescription });
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to update node');
    } finally {
      setIsUpdating(false);
    }
  }, [isAdmin, nodeName, nodeDescription, node, onNodeUpdated]);

  const handleLeaveNode = useCallback(async () => {
    const confirmMessage = isAdmin 
      ? 'Are you sure you want to leave this Node? As the admin, this will delete the Node permanently!'
      : 'Are you sure you want to leave this Node?';
    if (!confirm(confirmMessage)) return;
    try {
      await api.leaveNode(node.id, token);
      setSuccess('Left Node successfully!');
      setTimeout(() => { onLeaveNode?.(); onClose(); }, 1000);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to leave node');
    }
  }, [isAdmin, node.id, token, onLeaveNode, onClose]);

  const copyInviteCode = (inviteCode: string) => {
    navigator.clipboard?.writeText(inviteCode).then(() => {
      setSuccess('Invite code copied to clipboard!');
    }).catch(() => {
      const textArea = document.createElement('textarea');
      textArea.value = inviteCode;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setSuccess('Invite code copied to clipboard!');
    });
  };

  const formatDate = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleDateString() + ' ' + 
           new Date(timestamp * 1000).toLocaleTimeString();
  };

  const isInviteExpired = (invite: Invite): boolean => {
    return !!(invite.expires_at && invite.expires_at * 1000 < Date.now());
  };

  const isInviteMaxedOut = (invite: Invite): boolean => {
    return !!(invite.max_uses && invite.uses >= invite.max_uses);
  };

  useEffect(() => {
    if (isOpen && activeTab === 'emojis' && isAdmin) {
      setLoadingEmojis(true);
      api.listCustomEmojis(node.id).then(emojis => {
        setCustomEmojis(emojis);
      }).catch(() => {}).finally(() => setLoadingEmojis(false));
    }
    if (isOpen && activeTab === 'moderation' && isAdmin) {
      loadAutoModWords();
      loadNodeChannelsForMod();
    }
  }, [isOpen, activeTab, isAdmin, loadAutoModWords, loadNodeChannelsForMod]);

  useEffect(() => {
    if (isOpen && activeTab === 'roles' && canManageRoles) loadRoles();
  }, [isOpen, activeTab, canManageRoles, loadRoles]);

  useEffect(() => {
    if (isOpen && activeTab === 'invites' && canManageInvites) loadInvites();
  }, [isOpen, activeTab, canManageInvites, loadInvites]);

  useEffect(() => {
    if (isOpen && activeTab === 'audit' && canViewAuditLog) loadAuditLog(true);
  }, [isOpen, activeTab, canViewAuditLog, loadAuditLog]);

  useEffect(() => {
    if (success) { const t = setTimeout(() => setSuccess(''), 3000); return () => clearTimeout(t); }
  }, [success]);

  useEffect(() => {
    if (error) { const t = setTimeout(() => setError(''), 5000); return () => clearTimeout(t); }
  }, [error]);

  if (!isOpen) return null;

  const tabs: Array<{ key: typeof activeTab; label: string; visible: boolean }> = [
    { key: 'general', label: 'General', visible: true },
    { key: 'roles', label: 'Roles', visible: canManageRoles },
    { key: 'invites', label: 'Invites', visible: canManageInvites },
    { key: 'moderation', label: 'Moderation', visible: isAdmin },
    { key: 'emojis', label: 'Emojis', visible: isAdmin },
    { key: 'audit', label: 'Audit Log', visible: canViewAuditLog },
  ];

  return (
    <div className="node-settings-overlay">
      <div className="node-settings-modal">
        {/* Header */}
        <div className="node-settings-header">
          <h2>Node Settings</h2>
          <button className="settings-close" onClick={onClose}>×</button>
        </div>

        {/* Tabs */}
        <div className="node-settings-tabs">
          {tabs.filter(t => t.visible).map(t => (
            <button
              key={t.key}
              className={`node-settings-tab ${activeTab === t.key ? 'active' : ''}`}
              onClick={() => setActiveTab(t.key)}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="node-settings-body">
          {/* =================== GENERAL =================== */}
          {activeTab === 'general' && (
            <div>
              {/* Node Icon Upload */}
              <div className="node-icon-upload">
                <div
                  className={`node-icon-circle ${isAdmin ? 'editable' : ''}`}
                  onClick={() => {
                    if (!isAdmin) return;
                    const input = document.createElement('input');
                    input.type = 'file';
                    input.accept = 'image/png,image/jpeg,image/gif,image/webp';
                    input.onchange = async (e) => {
                      const file = (e.target as HTMLInputElement).files?.[0];
                      if (!file) return;
                      if (file.size > 256 * 1024) { setError('Icon must be under 256KB'); return; }
                      try {
                        setError('');
                        const result = await api.uploadNodeIcon(node.id, file, token);
                        setSuccess('Node icon updated!');
                        if (onNodeUpdated) onNodeUpdated({ ...node, icon_hash: result.icon_hash });
                      } catch (err) {
                        setError(err instanceof Error ? err.message : 'Failed to upload icon');
                      }
                    };
                    input.click();
                  }}
                  title={isAdmin ? 'Click to upload icon' : 'Node icon'}
                >
                  {node.icon_hash ? (
                    <img src={`${api.getNodeIconUrl(node.id)}?v=${node.icon_hash}`} alt={node.name[0]} />
                  ) : node.name[0]}
                  {isAdmin && <div className="node-icon-edit-badge">Edit</div>}
                </div>
                <span className="ns-help">
                  {isAdmin ? 'Click the icon to upload a new one (PNG, JPEG, GIF, WebP — max 256KB)' : 'Node icon'}
                </span>
              </div>

              <div className="ns-field">
                <label className="ns-label">Node Name</label>
                <input
                  type="text"
                  className="ns-input"
                  value={nodeName}
                  onChange={(e) => setNodeName(e.target.value)}
                  disabled={!isAdmin || isUpdating}
                  maxLength={32}
                />
              </div>

              <div className="ns-field">
                <label className="ns-label">Description</label>
                <textarea
                  className="ns-textarea"
                  value={nodeDescription}
                  onChange={(e) => setNodeDescription(e.target.value)}
                  disabled={!isAdmin || isUpdating}
                  maxLength={200}
                  rows={3}
                />
              </div>

              {isAdmin && (
                <div className="ns-field">
                  <button className="ns-btn ns-btn-success" onClick={handleUpdateNode} disabled={isUpdating}>
                    {isUpdating ? 'Saving...' : 'Save Changes'}
                  </button>
                </div>
              )}

              {/* Leave/Delete Node */}
              <div className="ns-divider">
                <h3 className={`ns-danger-title ${isAdmin ? 'admin' : 'member'}`}>
                  {isAdmin ? 'Delete Node' : 'Leave Node'}
                </h3>
                <p className="ns-section-desc">
                  {isAdmin 
                    ? 'Permanently delete this Node. This action cannot be undone.'
                    : 'Leave this Node. You can rejoin later with an invite.'}
                </p>
                <button className={`ns-btn ${isAdmin ? 'ns-btn-danger' : 'ns-btn-warning'}`} onClick={handleLeaveNode}>
                  {isAdmin ? 'Delete Node' : 'Leave Node'}
                </button>
              </div>
            </div>
          )}

          {/* =================== ROLES =================== */}
          {activeTab === 'roles' && canManageRoles && (
            <div>
              {editingRole ? (
                <div>
                  <div className="settings-action-row" style={{ marginBottom: 20 }}>
                    <button className="ns-back-btn" onClick={() => setEditingRole(null)}>←</button>
                    <h4 className="ns-section-title" style={{ margin: 0 }}>Edit Role</h4>
                  </div>

                  <div className="ns-field">
                    <label className="ns-label">Role Name</label>
                    <input type="text" className="ns-input" value={editRoleName} onChange={e => setEditRoleName(e.target.value)} maxLength={32} />
                  </div>

                  <div className="ns-field" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div>
                      <label className="ns-label">Color</label>
                      <input type="color" value={editRoleColor} onChange={e => setEditRoleColor(e.target.value)} style={{ width: 48, height: 32, border: 'none', background: 'none', cursor: 'pointer' }} />
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <label className="ns-perm-item">
                        <input type="checkbox" checked={editRoleHoist} onChange={e => setEditRoleHoist(e.target.checked)} /> Display separately in member list
                      </label>
                      <label className="ns-perm-item">
                        <input type="checkbox" checked={editRoleMentionable} onChange={e => setEditRoleMentionable(e.target.checked)} /> Allow anyone to @mention this role
                      </label>
                    </div>
                  </div>

                  <div className="ns-field">
                    <label className="ns-label">Permissions</label>
                    <div className="ns-perm-list">
                      {PERMISSIONS.map(p => (
                        <label key={p.bit} className="ns-perm-item">
                          <input type="checkbox" checked={(editRolePermissions & p.bit) !== 0}
                            onChange={e => setEditRolePermissions(prev => e.target.checked ? prev | p.bit : prev & ~p.bit)} />
                          {p.label}
                        </label>
                      ))}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="ns-btn ns-btn-success" onClick={handleSaveRole} disabled={savingRole}>
                      {savingRole ? 'Saving...' : 'Save Changes'}
                    </button>
                    <button className="ns-btn ns-btn-danger" onClick={() => handleDeleteRole(editingRole.id)}>
                      Delete Role
                    </button>
                  </div>
                </div>
              ) : (
                <div>
                  <div style={{ marginBottom: 16 }}>
                    {!showCreateRole ? (
                      <button className="ns-btn ns-btn-primary" onClick={() => setShowCreateRole(true)}>
                        ➕ Create Role
                      </button>
                    ) : (
                      <div className="ns-form-card">
                        <h4>New Role</h4>
                        <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
                          <div style={{ flex: 1 }}>
                            <label className="ns-label">Name</label>
                            <input type="text" className="ns-input" value={newRoleName} onChange={e => setNewRoleName(e.target.value)} maxLength={32} />
                          </div>
                          <div>
                            <label className="ns-label">Color</label>
                            <input type="color" value={newRoleColor} onChange={e => setNewRoleColor(e.target.value)} style={{ width: 48, height: 32, border: 'none', background: 'none', cursor: 'pointer' }} />
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: 16, marginBottom: 12 }}>
                          <label className="ns-perm-item">
                            <input type="checkbox" checked={newRoleHoist} onChange={e => setNewRoleHoist(e.target.checked)} /> Hoisted
                          </label>
                          <label className="ns-perm-item">
                            <input type="checkbox" checked={newRoleMentionable} onChange={e => setNewRoleMentionable(e.target.checked)} /> Mentionable
                          </label>
                        </div>
                        <div style={{ display: 'flex', gap: 8 }}>
                          <button className="ns-btn ns-btn-success" onClick={handleCreateRole} disabled={savingRole}>
                            {savingRole ? 'Creating...' : 'Create'}
                          </button>
                          <button className="ns-btn ns-btn-ghost" onClick={() => setShowCreateRole(false)}>Cancel</button>
                        </div>
                      </div>
                    )}
                  </div>

                  {loadingRoles ? (
                    <div className="ns-loading">Loading roles...</div>
                  ) : roles.length === 0 ? (
                    <div className="ns-empty">No roles created yet</div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {roles.map((role, idx) => (
                        <div key={role.id} className="ns-role-item">
                          <div className="ns-role-dot" style={{ background: role.color || '#99aab5' }} />
                          <span className="ns-role-name" style={{ color: role.color || 'var(--text-secondary)' }} onClick={() => startEditRole(role)}>
                            {role.name}
                          </span>
                          {role.hoist && <span className="ns-badge">hoisted</span>}
                          <div style={{ display: 'flex', gap: 2 }}>
                            <button className="ns-arrow-btn" onClick={() => handleMoveRole(role.id, 'up')} disabled={idx === 0}>▲</button>
                            <button className="ns-arrow-btn" onClick={() => handleMoveRole(role.id, 'down')} disabled={idx === roles.length - 1}>▼</button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Import Discord Template */}
              {isAdmin && (
                <div className="ns-divider">
                  <h4 className="ns-section-title" style={{ fontSize: 14 }}>Import Discord Template</h4>
                  <p className="ns-section-desc">Import channels, roles, and categories from a Discord server template.</p>
                  <button className="ns-btn ns-btn-ghost" onClick={() => { onClose(); if (onShowTemplateImport) setTimeout(onShowTemplateImport, 100); }}>
                    📥 Import Template
                  </button>
                </div>
              )}
            </div>
          )}

          {/* =================== INVITES =================== */}
          {activeTab === 'invites' && canManageInvites && (
            <div>
              <div style={{ marginBottom: 24 }}>
                {!showCreateInvite ? (
                  <button className="ns-btn ns-btn-primary" onClick={() => setShowCreateInvite(true)}>
                    ➕ Create Invite
                  </button>
                ) : (
                  <div className="ns-form-card">
                    <h4>Create New Invite</h4>
                    <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
                      <div style={{ flex: 1 }}>
                        <label className="ns-label">Max Uses (optional)</label>
                        <input type="number" className="ns-input" placeholder="∞" value={maxUses} onChange={(e) => setMaxUses(e.target.value)} min="1" max="100" />
                      </div>
                      <div style={{ flex: 1 }}>
                        <label className="ns-label">Expires in (hours)</label>
                        <input type="number" className="ns-input" placeholder="Never" value={expiresHours} onChange={(e) => setExpiresHours(e.target.value)} min="1" max="8760" />
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button className="ns-btn ns-btn-success" onClick={handleCreateInvite} disabled={creatingInvite}>
                        {creatingInvite ? 'Creating...' : 'Create'}
                      </button>
                      <button className="ns-btn ns-btn-ghost" onClick={() => { setShowCreateInvite(false); setMaxUses(''); setExpiresHours(''); }} disabled={creatingInvite}>
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <h4 className="ns-section-title">Active Invites</h4>
              {loadingInvites ? (
                <div className="ns-loading">Loading invites...</div>
              ) : invites.length === 0 ? (
                <div className="ns-empty">No active invites</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {invites.map((invite) => {
                    const expired = isInviteExpired(invite);
                    const maxedOut = isInviteMaxedOut(invite);
                    const isInactive = expired || maxedOut;
                    return (
                      <div key={invite.code} className={`ns-invite-card ${isInactive ? 'inactive' : ''}`}>
                        <div className="ns-invite-header">
                          <code className="ns-invite-code">{invite.code}</code>
                          <div style={{ display: 'flex', gap: 8 }}>
                            <button className="ns-btn ns-btn-primary" onClick={() => copyInviteCode(invite.code)} disabled={isInactive} style={{ padding: '4px 8px', fontSize: 12 }}>
                              Copy
                            </button>
                            <button className="ns-btn ns-btn-danger" onClick={() => handleRevokeInvite(invite.code)} style={{ padding: '4px 8px', fontSize: 12 }}>
                              Revoke
                            </button>
                          </div>
                        </div>
                        <div className="ns-invite-meta">
                          <span>Created: {formatDate(invite.created_at)}</span>
                          <span>Uses: {invite.uses}{invite.max_uses ? `/${invite.max_uses}` : ''}</span>
                          {invite.expires_at && (
                            <span style={{ color: expired ? 'var(--red)' : 'var(--text-muted)' }}>
                              {expired ? 'Expired: ' : 'Expires: '}{formatDate(invite.expires_at)}
                            </span>
                          )}
                          {maxedOut && <span style={{ color: 'var(--red)' }}>Max uses reached</span>}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* =================== MODERATION =================== */}
          {activeTab === 'moderation' && isAdmin && (
            <div>
              <h4 className="ns-section-title">⏱️ Slow Mode</h4>
              <p className="ns-section-desc">Limit how often users can send messages in a channel.</p>
              {nodeChannels.length === 0 ? (
                <div className="ns-loading" style={{ marginBottom: 32 }}>Loading channels...</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 32 }}>
                  {nodeChannels.map(ch => (
                    <div key={ch.id} className="ns-channel-row">
                      <span className="ns-channel-name">#{ch.name}</span>
                      <select
                        className="ns-select" style={{ width: 'auto' }}
                        value={slowModeChannels[ch.id] || 0}
                        onChange={(e) => handleSetSlowMode(ch.id, parseInt(e.target.value))}
                      >
                        <option value="0">Off</option>
                        <option value="5">5 seconds</option>
                        <option value="10">10 seconds</option>
                        <option value="30">30 seconds</option>
                        <option value="60">60 seconds</option>
                      </select>
                    </div>
                  ))}
                </div>
              )}

              <h4 className="ns-section-title">🛡️ Word Filter</h4>
              <p className="ns-section-desc">Block or warn when messages contain specific words.</p>

              <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
                <input
                  type="text" className="ns-input" style={{ flex: 1 }}
                  placeholder="Enter word to filter..."
                  value={newWord}
                  onChange={(e) => setNewWord(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleAddWord(); }}
                  maxLength={100}
                />
                <select className="ns-select" style={{ width: 'auto' }} value={newWordAction} onChange={(e) => setNewWordAction(e.target.value as 'block' | 'warn')}>
                  <option value="block">Block</option>
                  <option value="warn">Warn</option>
                </select>
                <button className="ns-btn ns-btn-success" onClick={handleAddWord} disabled={!newWord.trim()}>Add</button>
              </div>

              {loadingAutoMod ? (
                <div className="ns-loading">Loading...</div>
              ) : autoModWords.length === 0 ? (
                <div className="ns-empty">No filtered words yet</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {autoModWords.map(w => (
                    <div key={w.word} className="ns-word-row">
                      <span className="ns-word">{w.word}</span>
                      <span className={`ns-badge ${w.action === 'block' ? 'ns-badge-block' : 'ns-badge-warn'}`}>
                        {w.action.toUpperCase()}
                      </span>
                      <button className="ns-remove-btn" onClick={() => handleRemoveWord(w.word)} title="Remove word">×</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* =================== EMOJIS =================== */}
          {activeTab === 'emojis' && isAdmin && (
            <div>
              <h4 className="ns-section-title">Custom Emojis</h4>

              <div className="ns-form-card" style={{ marginBottom: 20 }}>
                <h4>Upload Emoji</h4>
                <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', flexWrap: 'wrap' }}>
                  <div>
                    <label className="ns-label">Name</label>
                    <input type="text" className="ns-input" style={{ width: 200 }}
                      value={newEmojiName}
                      onChange={e => setNewEmojiName(e.target.value.replace(/[^a-zA-Z0-9_]/g, ''))}
                      placeholder="emoji_name" maxLength={32}
                    />
                  </div>
                  <div>
                    <label className="ns-label">Image (PNG/GIF/WebP, max 256KB)</label>
                    <input type="file" accept="image/png,image/gif,image/webp"
                      onChange={e => setNewEmojiFile(e.target.files?.[0] || null)}
                      style={{ color: 'var(--text-secondary)', fontSize: 13 }}
                    />
                  </div>
                  <button className="ns-btn ns-btn-primary"
                    disabled={uploadingEmoji || !newEmojiName || newEmojiName.length < 2 || !newEmojiFile}
                    onClick={async () => {
                      if (!newEmojiFile || !newEmojiName) return;
                      setUploadingEmoji(true); setError(''); setSuccess('');
                      try {
                        await api.uploadEmoji(node.id, newEmojiName, newEmojiFile, token);
                        setSuccess(`Emoji :${newEmojiName}: uploaded!`);
                        setNewEmojiName(''); setNewEmojiFile(null);
                        const emojis = await api.listCustomEmojis(node.id);
                        setCustomEmojis(emojis);
                      } catch (err) {
                        setError(err instanceof Error ? err.message : 'Failed to upload emoji');
                      } finally { setUploadingEmoji(false); }
                    }}
                  >
                    {uploadingEmoji ? 'Uploading...' : 'Upload'}
                  </button>
                </div>
              </div>

              {loadingEmojis ? (
                <div className="ns-loading">Loading emojis...</div>
              ) : customEmojis.length === 0 ? (
                <div className="ns-empty">No custom emojis yet. Upload one above!</div>
              ) : (
                <div className="ns-emoji-grid">
                  {customEmojis.map(emoji => (
                    <div key={emoji.id} className="ns-emoji-item">
                      <img src={api.getEmojiUrl(emoji.content_hash)} alt={`:${emoji.name}:`} />
                      <span className="ns-emoji-name">:{emoji.name}:</span>
                      <button className="ns-remove-btn" title="Delete emoji"
                        onClick={async () => {
                          setError('');
                          try {
                            await api.deleteEmoji(node.id, emoji.id);
                            setCustomEmojis(prev => prev.filter(e => e.id !== emoji.id));
                            setSuccess(`Emoji :${emoji.name}: deleted`);
                          } catch (err) {
                            setError(err instanceof Error ? err.message : 'Failed to delete emoji');
                          }
                        }}
                      >✕</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* =================== AUDIT LOG =================== */}
          {activeTab === 'audit' && canViewAuditLog && (
            <div>
              <div className="ns-field">
                <label className="ns-label">Filter by Action</label>
                <select className="ns-select" style={{ width: 'auto', minWidth: 200 }} value={auditFilter} onChange={(e) => setAuditFilter(e.target.value)}>
                  <option value="all">All Actions</option>
                  <option value="channel_create">Channel Create</option>
                  <option value="channel_delete">Channel Delete</option>
                  <option value="member_kick">Member Kick</option>
                  <option value="role_change">Role Change</option>
                  <option value="invite_create">Invite Create</option>
                  <option value="invite_revoke">Invite Revoke</option>
                  <option value="message_pin">Message Pin</option>
                  <option value="message_unpin">Message Unpin</option>
                  <option value="message_delete">Message Delete</option>
                  <option value="node_settings_update">Settings Update</option>
                </select>
              </div>

              <h4 className="ns-section-title">Recent Activity</h4>
              {loadingAudit && auditEntries.length === 0 ? (
                <div className="ns-loading">Loading audit log...</div>
              ) : getFilteredAuditEntries().length === 0 ? (
                <div className="ns-empty">No audit entries found</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 400, overflowY: 'auto' }}>
                  {getFilteredAuditEntries().map((entry) => (
                    <div key={entry.id} className="ns-audit-entry">
                      <span className="ns-audit-icon">{getActionIcon(entry.action)}</span>
                      <div className="ns-audit-content">
                        <div style={{ marginBottom: 4, fontSize: 14 }}>
                          <span className="ns-audit-actor">
                            {entry.actor_public_key_hash?.slice(0, 16) || 'Unknown'}
                          </span>{' '}
                          <span className="ns-audit-action">{getActionDescription(entry)}</span>
                        </div>
                        <div className="ns-audit-meta">
                          <span>{formatDate(entry.created_at)}</span>
                          <span className="ns-audit-type">{entry.target_type}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                  {hasMoreAudit && (
                    <div style={{ textAlign: 'center', marginTop: 12 }}>
                      <button className="ns-btn ns-btn-primary" onClick={loadMoreAudit} disabled={loadingAudit}>
                        {loadingAudit ? 'Loading...' : 'Load More'}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Toast messages */}
        {(error || success) && (
          <div className={`ns-toast ${error ? 'error' : 'success'}`}>
            {error || success}
          </div>
        )}
      </div>
    </div>
  );
}
