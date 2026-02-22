import React, { useState, useCallback } from 'react';
import { api } from './api';
import { Node } from './types';

interface JoinNodeDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onNodeJoined: (node: Node) => void;
  token: string;
}

export function JoinNodeDialog({ isOpen, onClose, onNodeJoined, token }: JoinNodeDialogProps) {
  const [inviteCode, setInviteCode] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleJoinNode = useCallback(async () => {
    if (!inviteCode.trim()) {
      setError('Please enter an invite code');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const nodeInfo = await api.joinNodeByInvite(inviteCode.trim(), token);
      const node: Node = {
        id: nodeInfo.id,
        name: nodeInfo.name,
        owner_id: nodeInfo.owner_id,
        description: nodeInfo.description,
        created_at: nodeInfo.created_at,
      };
      onNodeJoined(node);
      setInviteCode('');
      onClose();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to join Node');
    } finally {
      setIsLoading(false);
    }
  }, [inviteCode, token, onNodeJoined, onClose]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isLoading) {
      handleJoinNode();
    } else if (e.key === 'Escape') {
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-card" style={{ maxWidth: '400px' }}>
        <h3>Join a Node</h3>
        <p>
          Enter an invite code to join a Node
        </p>

        <div className="form-group">
          <input
            type="text"
            className="form-input"
            placeholder="Enter invite code..."
            value={inviteCode}
            onChange={(e) => setInviteCode(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isLoading}
            autoFocus
          />
        </div>

        {error && (
          <div className="form-error">{error}</div>
        )}

        <div className="modal-actions">
          <button
            className="btn btn-outline"
            onClick={onClose}
            disabled={isLoading}
          >
            Cancel
          </button>
          <button
            className="btn btn-primary"
            onClick={handleJoinNode}
            disabled={isLoading || !inviteCode.trim()}
          >
            {isLoading ? 'Joining...' : 'Join Node'}
          </button>
        </div>
      </div>
    </div>
  );
}

interface CreateNodeDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onNodeCreated: (node: Node) => void;
  token: string;
}

export function CreateNodeDialog({ isOpen, onClose, onNodeCreated, token }: CreateNodeDialogProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleCreateNode = useCallback(async () => {
    if (!name.trim()) {
      setError('Please enter a Node name');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const nodeInfo = await api.createNode(name.trim(), token, description.trim() || undefined);
      const node: Node = {
        id: nodeInfo.id,
        name: nodeInfo.name,
        owner_id: nodeInfo.owner_id,
        description: nodeInfo.description,
        created_at: nodeInfo.created_at,
      };
      onNodeCreated(node);
      setName('');
      setDescription('');
      onClose();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to create Node');
    } finally {
      setIsLoading(false);
    }
  }, [name, description, token, onNodeCreated, onClose]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && e.ctrlKey && !isLoading) {
      handleCreateNode();
    } else if (e.key === 'Escape') {
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-card" style={{ maxWidth: '500px' }}>
        <h3>Create a Node</h3>
        <p>
          Create your own Node to chat with friends
        </p>

        <div className="form-group">
          <label className="form-label">Node Name *</label>
          <input
            type="text"
            className="form-input"
            placeholder="My Awesome Node"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isLoading}
            maxLength={32}
            autoFocus
          />
        </div>

        <div className="form-group">
          <label className="form-label">Description (optional)</label>
          <textarea
            className="form-input form-textarea"
            placeholder="What's your Node about?"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isLoading}
            maxLength={200}
            rows={3}
          />
        </div>

        {error && (
          <div className="form-error">{error}</div>
        )}

        <div className="modal-actions">
          <button
            className="btn btn-outline"
            onClick={onClose}
            disabled={isLoading}
          >
            Cancel
          </button>
          <button
            className="btn btn-green"
            onClick={handleCreateNode}
            disabled={isLoading || !name.trim()}
          >
            {isLoading ? 'Creating...' : 'Create Node'}
          </button>
        </div>

        <p style={{ margin: '12px 0 0', color: 'var(--text-faint)', fontSize: '12px' }}>
          Press Ctrl+Enter to create
        </p>
      </div>
    </div>
  );
}

interface NodeDiscoveryMenuProps {
  isOpen: boolean;
  onClose: () => void;
  onJoinNode: () => void;
  onCreateNode: () => void;
  anchorRef: React.RefObject<HTMLDivElement | null>;
}

export function NodeDiscoveryMenu({ isOpen, onClose, onJoinNode, onCreateNode, anchorRef }: NodeDiscoveryMenuProps) {
  if (!isOpen) return null;

  const rect = anchorRef.current?.getBoundingClientRect();
  const menuStyle: React.CSSProperties = {
    position: 'fixed',
    zIndex: 1000,
    minWidth: '160px',
  };

  if (rect) {
    menuStyle.bottom = `${window.innerHeight - rect.top + 8}px`;
    menuStyle.left = `${rect.left}px`;
  } else {
    menuStyle.top = '50%';
    menuStyle.left = '50%';
    menuStyle.transform = 'translate(-50%, -50%)';
  }

  return (
    <>
      <div className="context-menu-backdrop" onClick={onClose} />

      <div className="context-menu" style={menuStyle}>
        <div
          className="context-menu-item"
          onClick={() => { onJoinNode(); onClose(); }}
        >
          <span className="context-menu-icon" style={{ color: 'var(--accent)' }}>🔗</span>
          Join a Node
        </div>
        <div
          className="context-menu-item"
          onClick={() => { onCreateNode(); onClose(); }}
        >
          <span className="context-menu-icon" style={{ color: 'var(--green)' }}>➕</span>
          Create Node
        </div>
      </div>
    </>
  );
}
