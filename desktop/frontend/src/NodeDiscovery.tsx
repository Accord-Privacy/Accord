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
      // Convert NodeInfo to Node format for compatibility
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
        padding: '24px',
        borderRadius: '8px',
        maxWidth: '400px',
        width: '90%',
        color: '#ffffff'
      }}>
        <h3 style={{ margin: '0 0 16px 0', color: '#ffffff' }}>Join a Node</h3>
        <p style={{ margin: '0 0 16px 0', color: '#b9bbbe', fontSize: '14px' }}>
          Enter an invite code to join a Node
        </p>
        
        <div style={{ marginBottom: '16px' }}>
          <input
            type="text"
            placeholder="Enter invite code..."
            value={inviteCode}
            onChange={(e) => setInviteCode(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isLoading}
            style={{
              width: '100%',
              padding: '12px',
              borderRadius: '4px',
              border: 'none',
              background: '#40444b',
              color: '#ffffff',
              fontSize: '14px'
            }}
            autoFocus
          />
        </div>

        {error && (
          <div style={{ 
            color: '#f04747', 
            marginBottom: '16px', 
            fontSize: '14px',
            background: 'rgba(240, 71, 71, 0.1)',
            padding: '8px',
            borderRadius: '4px'
          }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button
            onClick={onClose}
            disabled={isLoading}
            style={{
              background: '#4f545c',
              border: 'none',
              color: '#ffffff',
              padding: '10px 16px',
              borderRadius: '4px',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              opacity: isLoading ? 0.6 : 1
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleJoinNode}
            disabled={isLoading || !inviteCode.trim()}
            style={{
              background: '#7289da',
              border: 'none',
              color: '#ffffff',
              padding: '10px 16px',
              borderRadius: '4px',
              cursor: (isLoading || !inviteCode.trim()) ? 'not-allowed' : 'pointer',
              opacity: (isLoading || !inviteCode.trim()) ? 0.6 : 1
            }}
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
      // Convert NodeInfo to Node format for compatibility
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
        padding: '24px',
        borderRadius: '8px',
        maxWidth: '500px',
        width: '90%',
        color: '#ffffff'
      }}>
        <h3 style={{ margin: '0 0 16px 0', color: '#ffffff' }}>Create a Node</h3>
        <p style={{ margin: '0 0 16px 0', color: '#b9bbbe', fontSize: '14px' }}>
          Create your own Node to chat with friends
        </p>
        
        <div style={{ marginBottom: '16px' }}>
          <label style={{ display: 'block', marginBottom: '6px', fontSize: '14px', fontWeight: '600', color: '#b9bbbe' }}>
            Node Name *
          </label>
          <input
            type="text"
            placeholder="My Awesome Node"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isLoading}
            maxLength={32}
            style={{
              width: '100%',
              padding: '12px',
              borderRadius: '4px',
              border: 'none',
              background: '#40444b',
              color: '#ffffff',
              fontSize: '14px'
            }}
            autoFocus
          />
        </div>

        <div style={{ marginBottom: '16px' }}>
          <label style={{ display: 'block', marginBottom: '6px', fontSize: '14px', fontWeight: '600', color: '#b9bbbe' }}>
            Description (optional)
          </label>
          <textarea
            placeholder="What's your Node about?"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isLoading}
            maxLength={200}
            rows={3}
            style={{
              width: '100%',
              padding: '12px',
              borderRadius: '4px',
              border: 'none',
              background: '#40444b',
              color: '#ffffff',
              fontSize: '14px',
              resize: 'vertical',
              minHeight: '80px'
            }}
          />
        </div>

        {error && (
          <div style={{ 
            color: '#f04747', 
            marginBottom: '16px', 
            fontSize: '14px',
            background: 'rgba(240, 71, 71, 0.1)',
            padding: '8px',
            borderRadius: '4px'
          }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button
            onClick={onClose}
            disabled={isLoading}
            style={{
              background: '#4f545c',
              border: 'none',
              color: '#ffffff',
              padding: '10px 16px',
              borderRadius: '4px',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              opacity: isLoading ? 0.6 : 1
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleCreateNode}
            disabled={isLoading || !name.trim()}
            style={{
              background: '#43b581',
              border: 'none',
              color: '#ffffff',
              padding: '10px 16px',
              borderRadius: '4px',
              cursor: (isLoading || !name.trim()) ? 'not-allowed' : 'pointer',
              opacity: (isLoading || !name.trim()) ? 0.6 : 1
            }}
          >
            {isLoading ? 'Creating...' : 'Create Node'}
          </button>
        </div>
        
        <p style={{ margin: '12px 0 0 0', color: '#72767d', fontSize: '12px' }}>
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

  // Calculate menu position
  const rect = anchorRef.current?.getBoundingClientRect();
  const menuStyle: React.CSSProperties = {
    position: 'fixed',
    background: '#36393f',
    border: '1px solid #202225',
    borderRadius: '4px',
    boxShadow: '0 8px 16px rgba(0, 0, 0, 0.24)',
    zIndex: 1000,
    minWidth: '160px',
    color: '#dcddde',
  };

  if (rect) {
    // Position menu above the button
    menuStyle.bottom = `${window.innerHeight - rect.top + 8}px`;
    menuStyle.left = `${rect.left}px`;
  } else {
    // Fallback positioning
    menuStyle.top = '50%';
    menuStyle.left = '50%';
    menuStyle.transform = 'translate(-50%, -50%)';
  }

  return (
    <>
      {/* Backdrop to close menu */}
      <div
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          zIndex: 999
        }}
        onClick={onClose}
      />
      
      <div style={menuStyle}>
        <div
          onClick={() => {
            onJoinNode();
            onClose();
          }}
          style={{
            padding: '12px 16px',
            cursor: 'pointer',
            fontSize: '14px',
            borderBottom: '1px solid #40444b',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
          onMouseEnter={(e) => e.currentTarget.style.background = '#40444b'}
          onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
        >
          <span style={{ color: '#7289da' }}>🔗</span>
          Join a Node
        </div>
        <div
          onClick={() => {
            onCreateNode();
            onClose();
          }}
          style={{
            padding: '12px 16px',
            cursor: 'pointer',
            fontSize: '14px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
          onMouseEnter={(e) => e.currentTarget.style.background = '#40444b'}
          onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
        >
          <span style={{ color: '#43b581' }}>➕</span>
          Create Node
        </div>
      </div>
    </>
  );
}