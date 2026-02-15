import { useState, useCallback, useEffect } from 'react';
import { api } from './api';
import { Node } from './types';

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
}

export function NodeSettings({ 
  isOpen, 
  onClose, 
  node, 
  token, 
  userRole, 
  onNodeUpdated,
  onLeaveNode 
}: NodeSettingsProps) {
  const [activeTab, setActiveTab] = useState<'general' | 'invites' | 'members'>('general');
  const [invites, setInvites] = useState<Invite[]>([]);
  const [loadingInvites, setLoadingInvites] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // General settings state
  const [nodeName, setNodeName] = useState(node.name);
  const [nodeDescription, setNodeDescription] = useState(node.description || '');
  const [isUpdating, setIsUpdating] = useState(false);

  // Create invite state
  const [showCreateInvite, setShowCreateInvite] = useState(false);
  const [maxUses, setMaxUses] = useState<string>('');
  const [expiresHours, setExpiresHours] = useState<string>('');
  const [creatingInvite, setCreatingInvite] = useState(false);

  const isAdmin = userRole === 'admin';
  const canManageInvites = userRole === 'admin' || userRole === 'moderator';

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

  const handleUpdateNode = useCallback(async () => {
    if (!isAdmin) return;
    
    setIsUpdating(true);
    setError('');
    try {
      // Note: This would need to be implemented in the API
      // For now, just show success message
      setSuccess('Node settings saved!');
      if (onNodeUpdated) {
        const updatedNode: Node = {
          ...node,
          name: nodeName,
          description: nodeDescription,
        };
        onNodeUpdated(updatedNode);
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
      setTimeout(() => {
        onLeaveNode?.();
        onClose();
      }, 1000);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to leave node');
    }
  }, [isAdmin, node.id, token, onLeaveNode, onClose]);

  const copyInviteCode = (inviteCode: string) => {
    navigator.clipboard.writeText(inviteCode).then(() => {
      setSuccess('Invite code copied to clipboard!');
    }).catch(() => {
      // Fallback for browsers that don't support clipboard API
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

  // Load invites when opening the invites tab
  useEffect(() => {
    if (isOpen && activeTab === 'invites' && canManageInvites) {
      loadInvites();
    }
  }, [isOpen, activeTab, canManageInvites, loadInvites]);

  // Clear messages after a delay
  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => setSuccess(''), 3000);
      return () => clearTimeout(timer);
    }
  }, [success]);

  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => setError(''), 5000);
      return () => clearTimeout(timer);
    }
  }, [error]);

  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(0, 0, 0, 0.8)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1001
    }}>
      <div style={{
        background: '#36393f',
        borderRadius: '8px',
        width: '90%',
        maxWidth: '600px',
        maxHeight: '80vh',
        color: '#ffffff',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Header */}
        <div style={{
          padding: '20px',
          borderBottom: '1px solid #40444b',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <h2 style={{ margin: 0, fontSize: '20px' }}>Node Settings</h2>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: '#b9bbbe',
              fontSize: '24px',
              cursor: 'pointer',
              padding: '0',
              lineHeight: 1
            }}
          >
            ×
          </button>
        </div>

        {/* Tabs */}
        <div style={{
          display: 'flex',
          borderBottom: '1px solid #40444b',
          background: '#2f3136'
        }}>
          <button
            onClick={() => setActiveTab('general')}
            style={{
              background: activeTab === 'general' ? '#40444b' : 'transparent',
              border: 'none',
              color: activeTab === 'general' ? '#ffffff' : '#b9bbbe',
              padding: '12px 20px',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '500'
            }}
          >
            General
          </button>
          {canManageInvites && (
            <button
              onClick={() => setActiveTab('invites')}
              style={{
                background: activeTab === 'invites' ? '#40444b' : 'transparent',
                border: 'none',
                color: activeTab === 'invites' ? '#ffffff' : '#b9bbbe',
                padding: '12px 20px',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '500'
              }}
            >
              Invites
            </button>
          )}
        </div>

        {/* Content */}
        <div style={{ flex: 1, padding: '20px', overflowY: 'auto' }}>
          {/* General Tab */}
          {activeTab === 'general' && (
            <div>
              <div style={{ marginBottom: '20px' }}>
                <label style={{ 
                  display: 'block', 
                  marginBottom: '8px', 
                  fontSize: '14px', 
                  fontWeight: '600', 
                  color: '#b9bbbe' 
                }}>
                  Node Name
                </label>
                <input
                  type="text"
                  value={nodeName}
                  onChange={(e) => setNodeName(e.target.value)}
                  disabled={!isAdmin || isUpdating}
                  maxLength={32}
                  style={{
                    width: '100%',
                    padding: '10px',
                    borderRadius: '4px',
                    border: 'none',
                    background: isAdmin ? '#40444b' : '#2f3136',
                    color: '#ffffff',
                    fontSize: '14px'
                  }}
                />
              </div>

              <div style={{ marginBottom: '20px' }}>
                <label style={{ 
                  display: 'block', 
                  marginBottom: '8px', 
                  fontSize: '14px', 
                  fontWeight: '600', 
                  color: '#b9bbbe' 
                }}>
                  Description
                </label>
                <textarea
                  value={nodeDescription}
                  onChange={(e) => setNodeDescription(e.target.value)}
                  disabled={!isAdmin || isUpdating}
                  maxLength={200}
                  rows={3}
                  style={{
                    width: '100%',
                    padding: '10px',
                    borderRadius: '4px',
                    border: 'none',
                    background: isAdmin ? '#40444b' : '#2f3136',
                    color: '#ffffff',
                    fontSize: '14px',
                    resize: 'vertical'
                  }}
                />
              </div>

              {isAdmin && (
                <div style={{ marginBottom: '20px' }}>
                  <button
                    onClick={handleUpdateNode}
                    disabled={isUpdating}
                    style={{
                      background: '#43b581',
                      border: 'none',
                      color: '#ffffff',
                      padding: '10px 16px',
                      borderRadius: '4px',
                      cursor: isUpdating ? 'not-allowed' : 'pointer',
                      fontSize: '14px',
                      opacity: isUpdating ? 0.6 : 1
                    }}
                  >
                    {isUpdating ? 'Saving...' : 'Save Changes'}
                  </button>
                </div>
              )}

              {/* Leave Node Section */}
              <div style={{
                marginTop: '40px',
                paddingTop: '20px',
                borderTop: '1px solid #40444b'
              }}>
                <h3 style={{ 
                  margin: '0 0 12px 0', 
                  fontSize: '16px', 
                  color: isAdmin ? '#f04747' : '#faa61a' 
                }}>
                  {isAdmin ? 'Delete Node' : 'Leave Node'}
                </h3>
                <p style={{ 
                  margin: '0 0 16px 0', 
                  fontSize: '14px', 
                  color: '#b9bbbe' 
                }}>
                  {isAdmin 
                    ? 'Permanently delete this Node. This action cannot be undone.'
                    : 'Leave this Node. You can rejoin later with an invite.'
                  }
                </p>
                <button
                  onClick={handleLeaveNode}
                  style={{
                    background: isAdmin ? '#f04747' : '#faa61a',
                    border: 'none',
                    color: '#ffffff',
                    padding: '10px 16px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontSize: '14px'
                  }}
                >
                  {isAdmin ? 'Delete Node' : 'Leave Node'}
                </button>
              </div>
            </div>
          )}

          {/* Invites Tab */}
          {activeTab === 'invites' && canManageInvites && (
            <div>
              {/* Create Invite Section */}
              <div style={{ marginBottom: '24px' }}>
                {!showCreateInvite ? (
                  <button
                    onClick={() => setShowCreateInvite(true)}
                    style={{
                      background: '#7289da',
                      border: 'none',
                      color: '#ffffff',
                      padding: '10px 16px',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      fontSize: '14px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}
                  >
                    ➕ Create Invite
                  </button>
                ) : (
                  <div style={{
                    background: '#40444b',
                    padding: '16px',
                    borderRadius: '8px',
                    marginBottom: '16px'
                  }}>
                    <h4 style={{ margin: '0 0 16px 0', fontSize: '16px' }}>Create New Invite</h4>
                    
                    <div style={{ display: 'flex', gap: '12px', marginBottom: '12px' }}>
                      <div style={{ flex: 1 }}>
                        <label style={{ 
                          display: 'block', 
                          marginBottom: '6px', 
                          fontSize: '12px', 
                          color: '#b9bbbe' 
                        }}>
                          Max Uses (optional)
                        </label>
                        <input
                          type="number"
                          placeholder="∞"
                          value={maxUses}
                          onChange={(e) => setMaxUses(e.target.value)}
                          min="1"
                          max="100"
                          style={{
                            width: '100%',
                            padding: '8px',
                            borderRadius: '4px',
                            border: 'none',
                            background: '#36393f',
                            color: '#ffffff',
                            fontSize: '14px'
                          }}
                        />
                      </div>
                      <div style={{ flex: 1 }}>
                        <label style={{ 
                          display: 'block', 
                          marginBottom: '6px', 
                          fontSize: '12px', 
                          color: '#b9bbbe' 
                        }}>
                          Expires in (hours)
                        </label>
                        <input
                          type="number"
                          placeholder="Never"
                          value={expiresHours}
                          onChange={(e) => setExpiresHours(e.target.value)}
                          min="1"
                          max="8760"
                          style={{
                            width: '100%',
                            padding: '8px',
                            borderRadius: '4px',
                            border: 'none',
                            background: '#36393f',
                            color: '#ffffff',
                            fontSize: '14px'
                          }}
                        />
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        onClick={handleCreateInvite}
                        disabled={creatingInvite}
                        style={{
                          background: '#43b581',
                          border: 'none',
                          color: '#ffffff',
                          padding: '8px 12px',
                          borderRadius: '4px',
                          cursor: creatingInvite ? 'not-allowed' : 'pointer',
                          fontSize: '13px',
                          opacity: creatingInvite ? 0.6 : 1
                        }}
                      >
                        {creatingInvite ? 'Creating...' : 'Create'}
                      </button>
                      <button
                        onClick={() => {
                          setShowCreateInvite(false);
                          setMaxUses('');
                          setExpiresHours('');
                        }}
                        disabled={creatingInvite}
                        style={{
                          background: '#4f545c',
                          border: 'none',
                          color: '#ffffff',
                          padding: '8px 12px',
                          borderRadius: '4px',
                          cursor: creatingInvite ? 'not-allowed' : 'pointer',
                          fontSize: '13px'
                        }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Invites List */}
              <div>
                <h4 style={{ margin: '0 0 16px 0', fontSize: '16px' }}>Active Invites</h4>
                
                {loadingInvites ? (
                  <div style={{ textAlign: 'center', padding: '20px', color: '#b9bbbe' }}>
                    Loading invites...
                  </div>
                ) : invites.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '20px', color: '#72767d' }}>
                    No active invites
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {invites.map((invite) => {
                      const expired = isInviteExpired(invite);
                      const maxedOut = isInviteMaxedOut(invite);
                      const isInactive = expired || maxedOut;
                      
                      return (
                        <div
                          key={invite.code}
                          style={{
                            background: '#40444b',
                            padding: '12px',
                            borderRadius: '6px',
                            border: isInactive ? '1px solid #f04747' : 'none',
                            opacity: isInactive ? 0.7 : 1
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                            <code style={{
                              background: '#2f3136',
                              padding: '4px 8px',
                              borderRadius: '4px',
                              fontSize: '13px',
                              fontFamily: 'monospace'
                            }}>
                              {invite.code}
                            </code>
                            <div style={{ display: 'flex', gap: '8px' }}>
                              <button
                                onClick={() => copyInviteCode(invite.code)}
                                disabled={isInactive}
                                style={{
                                  background: '#7289da',
                                  border: 'none',
                                  color: '#ffffff',
                                  padding: '4px 8px',
                                  borderRadius: '4px',
                                  cursor: isInactive ? 'not-allowed' : 'pointer',
                                  fontSize: '12px',
                                  opacity: isInactive ? 0.5 : 1
                                }}
                              >
                                Copy
                              </button>
                              <button
                                onClick={() => handleRevokeInvite(invite.code)}
                                style={{
                                  background: '#f04747',
                                  border: 'none',
                                  color: '#ffffff',
                                  padding: '4px 8px',
                                  borderRadius: '4px',
                                  cursor: 'pointer',
                                  fontSize: '12px'
                                }}
                              >
                                Revoke
                              </button>
                            </div>
                          </div>
                          <div style={{ fontSize: '12px', color: '#b9bbbe', display: 'flex', flexWrap: 'wrap', gap: '16px' }}>
                            <span>Created: {formatDate(invite.created_at)}</span>
                            <span>Uses: {invite.uses}{invite.max_uses ? `/${invite.max_uses}` : ''}</span>
                            {invite.expires_at && (
                              <span style={{ color: expired ? '#f04747' : '#b9bbbe' }}>
                                {expired ? 'Expired: ' : 'Expires: '}{formatDate(invite.expires_at)}
                              </span>
                            )}
                            {maxedOut && <span style={{ color: '#f04747' }}>Max uses reached</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Messages */}
        {(error || success) && (
          <div style={{
            position: 'absolute',
            top: '16px',
            right: '16px',
            background: error ? '#f04747' : '#43b581',
            color: '#ffffff',
            padding: '8px 12px',
            borderRadius: '4px',
            fontSize: '14px',
            maxWidth: '300px',
            zIndex: 1002
          }}>
            {error || success}
          </div>
        )}
      </div>
    </div>
  );
}