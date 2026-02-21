import React from "react";
import { useAppContext } from "./AppContext";
import { api } from "../api";
import { notificationManager } from "../notifications";
import { Channel } from "../types";
// buildHash imports moved to MemberSidebar for trust indicator
import { BotPanel } from "./BotPanel";

// Voice Connection Panel (kept for potential reuse; controls now merged into UserPanel)
export const VoiceConnectionPanel: React.FC<{
  channelName: string;
  connectedAt: number | null;
  onDisconnect: () => void;
}> = ({ channelName, connectedAt, onDisconnect }) => {
  const [elapsed, setElapsed] = React.useState("00:00");
  const [isMuted, setIsMuted] = React.useState(false);
  const [isDeafened, setIsDeafened] = React.useState(false);

  React.useEffect(() => {
    if (!connectedAt) return;
    const interval = setInterval(() => {
      const secs = Math.floor((Date.now() - connectedAt) / 1000);
      const m = String(Math.floor(secs / 60)).padStart(2, '0');
      const s = String(secs % 60).padStart(2, '0');
      setElapsed(`${m}:${s}`);
    }, 1000);
    return () => clearInterval(interval);
  }, [connectedAt]);

  return (
    <div className="voice-connection-panel">
      <div className="voice-connection-info">
        <span className="voice-connection-dot">●</span>
        <div className="voice-connection-details">
          <span className="voice-connection-label">Voice Connected</span>
          <span className="voice-connection-channel">{channelName}</span>
        </div>
        <span className="voice-connection-timer">{elapsed}</span>
      </div>
      <div className="voice-connection-controls">
        <button
          className={`voice-ctrl-btn ${isMuted ? 'active' : ''}`}
          onClick={() => setIsMuted(!isMuted)}
          title={isMuted ? 'Unmute' : 'Mute'}
        >
          {isMuted ? '🔇' : '🎤'}
        </button>
        <button
          className={`voice-ctrl-btn ${isDeafened ? 'active' : ''}`}
          onClick={() => { setIsDeafened(!isDeafened); if (!isDeafened) setIsMuted(true); }}
          title={isDeafened ? 'Undeafen' : 'Deafen'}
        >
          {isDeafened ? '🔇' : '🔊'}
        </button>
        <button
          className="voice-ctrl-btn voice-disconnect-btn"
          onClick={onDisconnect}
          title="Disconnect"
        >
          📞
        </button>
      </div>
    </div>
  );
};

// Drag-and-drop types
type DragItemType = 'channel' | 'category';
interface DragItem {
  type: DragItemType;
  id: string;
  categoryId: string | null;
}

export const ChannelSidebar: React.FC = () => {
  const ctx = useAppContext();
  const [dragItem, setDragItem] = React.useState<DragItem | null>(null);
  const [dropTarget, setDropTarget] = React.useState<{ id: string; position: 'before' | 'after' | 'inside'; type: DragItemType } | null>(null);

  const canManageChannels = ctx.selectedNodeId ? ctx.hasPermission(ctx.selectedNodeId, 'ManageNode') : false;

  const handleDragStart = (e: React.DragEvent, item: DragItem) => {
    if (!canManageChannels) { e.preventDefault(); return; }
    setDragItem(item);
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', JSON.stringify(item));
    (e.currentTarget as HTMLElement).style.opacity = '0.4';
  };

  const handleDragEnd = (e: React.DragEvent) => {
    (e.currentTarget as HTMLElement).style.opacity = '1';
    setDragItem(null);
    setDropTarget(null);
  };

  const handleDragOver = (e: React.DragEvent, targetId: string, targetType: DragItemType) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const y = e.clientY - rect.top;
    const position = y < rect.height / 2 ? 'before' : 'after';
    setDropTarget({ id: targetId, position, type: targetType });
  };

  const handleCategoryDragOver = (e: React.DragEvent, categoryId: string) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (dragItem?.type === 'channel') {
      setDropTarget({ id: categoryId, position: 'inside', type: 'category' });
    } else {
      const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
      const y = e.clientY - rect.top;
      setDropTarget({ id: categoryId, position: y < rect.height / 2 ? 'before' : 'after', type: 'category' });
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    if (!dragItem || !dropTarget || !ctx.selectedNodeId) return;

    // Build the new order
    const allChannels = [...ctx.uncategorizedChannels, ...ctx.categories.flatMap(cat => [cat, ...ctx.categorizedChannels(cat.id)])];
    
    if (dragItem.type === 'channel' && dropTarget.type === 'category' && dropTarget.position === 'inside') {
      // Channel dropped onto a category — move it into that category at the end
      const targetCatChildren = ctx.categorizedChannels(dropTarget.id);
      const newPosition = targetCatChildren.length;
      try {
        await api.reorderChannels(ctx.selectedNodeId, [{
          id: dragItem.id,
          position: newPosition,
          category_id: dropTarget.id,
        }]);
        // Refresh channels
        ctx.loadChannels(ctx.selectedNodeId);
      } catch (err) {
        console.error('Failed to reorder channels:', err);
      }
    } else if (dragItem.type === 'channel') {
      // Channel reorder within or across categories
      const targetChannel = allChannels.find(ch => ch.id === dropTarget.id);
      if (!targetChannel) return;
      const targetCategoryId = targetChannel.parent_id || null;
      
      // Get siblings in target category
      const siblings = targetCategoryId
        ? ctx.categorizedChannels(targetCategoryId).filter(ch => ch.id !== dragItem.id)
        : ctx.uncategorizedChannels.filter(ch => ch.id !== dragItem.id);
      
      const targetIdx = siblings.findIndex(ch => ch.id === dropTarget.id);
      const insertIdx = dropTarget.position === 'after' ? targetIdx + 1 : targetIdx;
      
      // Insert dragged channel
      const dragChannel = allChannels.find(ch => ch.id === dragItem.id);
      if (!dragChannel) return;
      siblings.splice(insertIdx, 0, dragChannel);
      
      const reorderEntries = siblings.map((ch, i) => ({
        id: ch.id,
        position: i,
        category_id: targetCategoryId,
      }));
      
      // If channel moved between categories, also include it
      if (dragItem.categoryId !== targetCategoryId) {
        // Re-index old category siblings
        const oldSiblings = dragItem.categoryId
          ? ctx.categorizedChannels(dragItem.categoryId).filter(ch => ch.id !== dragItem.id)
          : ctx.uncategorizedChannels.filter(ch => ch.id !== dragItem.id);
        oldSiblings.forEach((ch, i) => {
          reorderEntries.push({ id: ch.id, position: i, category_id: dragItem.categoryId });
        });
      }
      
      try {
        await api.reorderChannels(ctx.selectedNodeId, reorderEntries);
        ctx.loadChannels(ctx.selectedNodeId);
      } catch (err) {
        console.error('Failed to reorder channels:', err);
      }
    } else if (dragItem.type === 'category') {
      // Category reorder
      const cats = ctx.categories.filter(c => c.id !== dragItem.id);
      const targetIdx = cats.findIndex(c => c.id === dropTarget.id);
      const insertIdx = dropTarget.position === 'after' ? targetIdx + 1 : targetIdx;
      const dragCat = ctx.categories.find(c => c.id === dragItem.id);
      if (!dragCat) return;
      cats.splice(insertIdx, 0, dragCat);
      
      const reorderEntries = cats.map((c, i) => ({
        id: c.id,
        position: i,
        category_id: null as string | null,
      }));
      
      try {
        await api.reorderChannels(ctx.selectedNodeId, reorderEntries);
        ctx.loadChannels(ctx.selectedNodeId);
      } catch (err) {
        console.error('Failed to reorder categories:', err);
      }
    }
    
    setDragItem(null);
    setDropTarget(null);
  };

  const getDropIndicatorStyle = (itemId: string, _itemType: DragItemType): React.CSSProperties | null => {
    if (!dropTarget || dropTarget.id !== itemId) return null;
    if (dropTarget.position === 'inside') {
      return { outline: '2px solid var(--accent, #5865f2)', borderRadius: '4px' };
    }
    const indicatorStyle: React.CSSProperties = {
      position: 'absolute',
      left: 0,
      right: 0,
      height: '2px',
      background: 'var(--accent, #5865f2)',
      zIndex: 10,
    };
    if (dropTarget.position === 'before') {
      return { ...indicatorStyle, top: 0 };
    }
    return { ...indicatorStyle, bottom: 0 };
  };

  const renderChannel = (channel: Channel) => {
    const isVoiceChannel = ctx.getChannelTypeNum(channel) === 2;
    const isActive = channel.id === ctx.selectedChannelId;
    const isConnectedToVoice = isVoiceChannel && ctx.voiceChannelId === channel.id;
    const canDeleteChannel = ctx.selectedNodeId && ctx.hasPermission(ctx.selectedNodeId, 'DeleteChannel');
    const clientUnreads = ctx.selectedNodeId ? 
      notificationManager.getChannelUnreads(ctx.selectedNodeId, channel.id) : 
      { count: 0, mentions: 0 };
    const channelUnreads = clientUnreads.count > 0 ? clientUnreads : 
      { count: (channel as any).unread_count || 0, mentions: clientUnreads.mentions };
    const hasUnread = channelUnreads.count > 0 || channelUnreads.mentions > 0;
    
    const dropIndicator = getDropIndicatorStyle(channel.id, 'channel');
    
    return (
      <div
        key={channel.id}
        className={`channel ${isActive ? "active" : ""} ${isConnectedToVoice ? "voice-connected" : ""} ${hasUnread && !isActive ? "unread" : ""}`}
        title={channel.topic || undefined}
        draggable={canManageChannels}
        onDragStart={(e) => handleDragStart(e, { type: 'channel', id: channel.id, categoryId: channel.parent_id || null })}
        onDragEnd={handleDragEnd}
        onDragOver={(e) => handleDragOver(e, channel.id, 'channel')}
        onDrop={handleDrop}
        style={{ position: 'relative', cursor: canManageChannels ? 'grab' : undefined }}
      >
        {dropIndicator && <div style={dropIndicator} />}
        <div
          onClick={() => {
            if (isVoiceChannel) {
              if (!isConnectedToVoice) {
                ctx.setVoiceChannelId(channel.id);
                ctx.setVoiceChannelName(channel.name);
                ctx.setVoiceConnectedAt(Date.now());
              }
            } else {
              ctx.handleChannelSelect(channel.id, `# ${channel.name}`);
            }
          }}
          style={{ flex: 1, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}
        >
          <span style={{ color: isVoiceChannel ? '#8e9297' : undefined }}>
            {isVoiceChannel ? '🔊' : '#'} {channel.name}
          </span>
          {isVoiceChannel && !isConnectedToVoice && (
            <span style={{ fontSize: '10px', color: '#8e9297', marginLeft: '4px' }}>Voice Channel</span>
          )}
          {isConnectedToVoice && (
            <span style={{ fontSize: '10px', color: '#43b581' }}>●</span>
          )}
        </div>
        <div className="channel-badges">
          {channelUnreads.mentions > 0 && (
            <div className="mention-badge">{channelUnreads.mentions > 9 ? '9+' : channelUnreads.mentions}</div>
          )}
          {channelUnreads.mentions === 0 && channelUnreads.count > 0 && (
            <div className="unread-badge">{channelUnreads.count > 99 ? '99+' : channelUnreads.count}</div>
          )}
          {canDeleteChannel && (
            <button onClick={(e) => { e.stopPropagation(); ctx.setDeleteChannelConfirm({ id: channel.id, name: channel.name }); }} className="channel-delete-btn" title="Delete channel">×</button>
          )}
        </div>
        {isConnectedToVoice && ctx.voiceChannelId === channel.id && (
          <div className="voice-channel-users">
            <div className="voice-channel-user">
              <div className="voice-user-avatar">
                {(ctx.appState.user?.display_name || "U")[0]}
              </div>
              <span className="voice-user-name">{ctx.appState.user?.display_name || "You"}</span>
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="channel-sidebar">
      <div className="sidebar-header">
        <div className="sidebar-header-row">
          <div style={{ display: 'flex', alignItems: 'center' }}>
            {ctx.servers[ctx.activeServer]}
            {ctx.serverAvailable && (
              <span className="connection-status">
                <span className={`connection-dot ${ctx.connectionInfo.status}`}>●</span>
                <span className="connection-label">
                  {ctx.connectionInfo.status === 'connected' && 'Connected'}
                  {ctx.connectionInfo.status === 'reconnecting' && `Reconnecting... ${ctx.connectionInfo.reconnectAttempt}/${ctx.connectionInfo.maxReconnectAttempts}`}
                  {ctx.connectionInfo.status === 'disconnected' && !ctx.appState.isConnected && 'Disconnected'}
                </span>
                {ctx.connectionInfo.status === 'disconnected' && !ctx.appState.isConnected && ctx.ws && (
                  <button className="connection-retry-btn" onClick={() => { ctx.setLastConnectionError(""); ctx.ws!.retry(); }}>Retry</button>
                )}
                {ctx.lastConnectionError && ctx.connectionInfo.status !== 'connected' && (
                  <span className="connection-error-detail" title={ctx.lastConnectionError} style={{ fontSize: 11, color: 'var(--error, #f04747)', display: 'block', marginTop: 2 }}>
                    {ctx.lastConnectionError.length > 60 ? ctx.lastConnectionError.substring(0, 57) + '...' : ctx.lastConnectionError}
                  </span>
                )}
              </span>
            )}
            {!ctx.serverAvailable && <span className="demo-badge">DEMO</span>}
          </div>
          
          <div className="sidebar-admin-buttons">
            {ctx.selectedNodeId && ctx.hasPermission(ctx.selectedNodeId, 'ManageInvites') && (
              <button onClick={ctx.handleGenerateInvite} className="sidebar-admin-btn" title="Generate Invite">Invite</button>
            )}
            {ctx.selectedNodeId && (
              <button onClick={() => ctx.setShowNodeSettings(true)} className="sidebar-admin-btn" title="Node Settings">⚙️</button>
            )}
          </div>
        </div>
        
        {ctx.selectedNodeId && ctx.userRoles[ctx.selectedNodeId] && (
          <div className="sidebar-role">{ctx.getRoleBadge(ctx.userRoles[ctx.selectedNodeId])} {ctx.userRoles[ctx.selectedNodeId]}</div>
        )}
        {ctx.selectedNodeId && ctx.nodes.find(n => n.id === ctx.selectedNodeId)?.description && (
          <div className="sidebar-description" title={ctx.nodes.find(n => n.id === ctx.selectedNodeId)?.description}>
            {ctx.nodes.find(n => n.id === ctx.selectedNodeId)?.description}
          </div>
        )}
      </div>
      
      <div className="channel-list">
        {/* Uncategorized channels */}
        {ctx.uncategorizedChannels.map(ch => renderChannel(ch))}
        
        {/* Categories with their children */}
        {ctx.categories.map(cat => {
          const children = ctx.categorizedChannels(cat.id);
          const isCollapsed = ctx.collapsedCategories.has(cat.id);
          return (
            <div key={cat.id} className="channel-category" style={{ position: 'relative' }}>
              {getDropIndicatorStyle(cat.id, 'category') && <div style={getDropIndicatorStyle(cat.id, 'category')!} />}
              <div
                className="category-header"
                onClick={() => ctx.toggleCategory(cat.id)}
                draggable={canManageChannels}
                onDragStart={(e) => handleDragStart(e, { type: 'category', id: cat.id, categoryId: null })}
                onDragEnd={handleDragEnd}
                onDragOver={(e) => handleCategoryDragOver(e, cat.id)}
                onDrop={handleDrop}
                style={{ cursor: canManageChannels ? 'grab' : undefined }}
              >
                <span className="category-arrow">{isCollapsed ? '▶' : '▼'}</span>
                <span className="category-name">{cat.name}</span>
              </div>
              {!isCollapsed && children.map(ch => renderChannel(ch))}
            </div>
          );
        })}
        
        {/* Create Channel Button for Admins */}
        {ctx.selectedNodeId && ctx.hasPermission(ctx.selectedNodeId, 'CreateChannel') && (
          <div style={{ marginTop: '4px', padding: '0 8px' }}>
            {!ctx.showCreateChannelForm ? (
              <button onClick={() => ctx.setShowCreateChannelForm(true)} className="btn btn-green btn-sm" style={{ width: '100%' }}>
                + Create Channel
              </button>
            ) : (
              <div className="create-channel-form">
                <input type="text" placeholder="Channel name" value={ctx.newChannelName} onChange={(e) => ctx.setNewChannelName(e.target.value)} />
                <select value={ctx.newChannelType} onChange={(e) => ctx.setNewChannelType(e.target.value)}>
                  <option value="text">Text Channel</option>
                  <option value="voice">Voice Channel</option>
                </select>
                <div className="create-channel-actions">
                  <button onClick={ctx.handleCreateChannel} className="btn btn-green btn-sm">Create</button>
                  <button onClick={() => { ctx.setShowCreateChannelForm(false); ctx.setNewChannelName(""); ctx.setNewChannelType("text"); }} className="btn btn-outline btn-sm">Cancel</button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Bot Panel */}
      {ctx.selectedNodeId && (
        <BotPanel
          nodeId={ctx.selectedNodeId}
          isAdmin={ctx.selectedNodeId ? ctx.hasPermission(ctx.selectedNodeId, 'ManageNode') : false}
        />
      )}

      {/* Direct Messages Section */}
      <DMSection />

      <UserPanel />

      {/* Custom Status Popover */}
      {ctx.showStatusPopover && (
        <div className="status-popover">
          <div className="status-popover-header">
            <span>Set Custom Status</span>
            <button onClick={() => ctx.setShowStatusPopover(false)} className="status-popover-close">×</button>
          </div>
          <input
            type="text"
            className="status-popover-input"
            placeholder="What's on your mind?"
            value={ctx.statusInput}
            onChange={(e) => ctx.setStatusInput(e.target.value.slice(0, 128))}
            onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleSaveCustomStatus(); if (e.key === 'Escape') ctx.setShowStatusPopover(false); }}
            maxLength={128}
            autoFocus
          />
          <div className="status-popover-footer">
            <span className="status-popover-count">{ctx.statusInput.length}/128</span>
            <div style={{ display: 'flex', gap: '8px' }}>
              {ctx.customStatus && (
                <button className="status-popover-clear" onClick={() => { ctx.setStatusInput(""); ctx.handleSaveCustomStatus(); ctx.setShowStatusPopover(false); }}>Clear</button>
              )}
              <button className="status-popover-save" onClick={ctx.handleSaveCustomStatus}>Save</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const DMSection: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className="dm-section">
      <div className="dm-header">
        Direct Messages
        <button onClick={() => ctx.setShowDmChannelCreate(!ctx.showDmChannelCreate)} className="dm-header-add-btn" title="Create DM">+</button>
      </div>
      
      <div className="dm-list">
        {ctx.dmChannels.map((dmChannel) => {
          const isActive = ctx.selectedDmChannel?.id === dmChannel.id;
          const dmUnreads = notificationManager.getChannelUnreads(`dm-${dmChannel.id}`, dmChannel.id);
          
          return (
            <div
              key={dmChannel.id}
              className={`dm-item ${isActive ? 'active' : ''}`}
              onClick={() => ctx.handleDmChannelSelect(dmChannel)}
            >
              <div className="dm-avatar">
                {(dmChannel.other_user_profile?.display_name || "?")[0].toUpperCase()}
                <span className={`presence-dot presence-${ctx.getPresenceStatus(dmChannel.other_user?.id || '')}`} />
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="dm-name">{dmChannel.other_user_profile.display_name}</div>
                {dmChannel.last_message && (
                  <div className="dm-last-message">{dmChannel.last_message.content.substring(0, 30)}</div>
                )}
              </div>
              
              <div className="dm-badges">
                {dmUnreads.mentions > 0 && (
                  <div className="mention-badge">
                    {dmUnreads.mentions > 9 ? '9+' : dmUnreads.mentions}
                  </div>
                )}
                {dmUnreads.mentions === 0 && dmUnreads.count > 0 && (
                  <div className="notification-dot" />
                )}
              </div>
            </div>
          );
        })}
        
        {ctx.dmChannels.length === 0 && (
          <div className="dm-empty">No direct messages yet</div>
        )}
      </div>
    </div>
  );
};

const UserPanel: React.FC = () => {
  const ctx = useAppContext();
  const [isMuted, setIsMuted] = React.useState(false);
  const [isDeafened, setIsDeafened] = React.useState(false);
  const [elapsed, setElapsed] = React.useState("00:00");

  const inVoice = !!ctx.voiceChannelId;

  React.useEffect(() => {
    if (!ctx.voiceConnectedAt) return;
    const interval = setInterval(() => {
      const secs = Math.floor((Date.now() - ctx.voiceConnectedAt!) / 1000);
      const m = String(Math.floor(secs / 60)).padStart(2, '0');
      const s = String(secs % 60).padStart(2, '0');
      setElapsed(`${m}:${s}`);
    }, 1000);
    return () => clearInterval(interval);
  }, [ctx.voiceConnectedAt]);

  return (
    <div className="user-panel">
      <div className="user-avatar">
        {ctx.appState.user?.id ? (
          <img 
            src={`${api.getUserAvatarUrl(ctx.appState.user.id)}`}
            alt={(ctx.appState.user?.display_name || "U")[0]}
            style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '50%' }}
            onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; (e.target as HTMLImageElement).parentElement!.textContent = (ctx.appState.user?.display_name || ctx.fingerprint(ctx.appState.user?.public_key_hash || ''))?.[0] || "U"; }}
          />
        ) : ((ctx.appState.user?.display_name || ctx.fingerprint(ctx.appState.user?.public_key_hash || ''))?.[0] || "U")}
      </div>
      <div className="user-info">
        <div className="username">{ctx.appState.user?.display_name || ctx.fingerprint(ctx.appState.user?.public_key_hash || '') || "You"}</div>
        <div className="user-status" onClick={() => { ctx.setStatusInput(ctx.customStatus); ctx.setShowStatusPopover(true); }} style={{ cursor: 'pointer' }} title="Click to set custom status">
          {ctx.customStatus || (ctx.appState.isConnected ? "Online" : "Offline")}
        </div>
        {inVoice && (
          <div className="user-panel-voice-info">
            <span className="voice-connection-dot">●</span>
            Voice Connected — #{ctx.voiceChannelName} {elapsed}
          </div>
        )}
        <div className="user-panel-controls">
          <button
            className={`voice-ctrl-btn ${isMuted ? 'active' : ''}`}
            onClick={() => setIsMuted(!isMuted)}
            title={isMuted ? 'Unmute' : 'Mute'}
          >
            {isMuted ? '🔇' : '🎤'}
          </button>
          <button
            className={`voice-ctrl-btn ${isDeafened ? 'active' : ''}`}
            onClick={() => { setIsDeafened(!isDeafened); if (!isDeafened) setIsMuted(true); }}
            title={isDeafened ? 'Undeafen' : 'Deafen'}
          >
            {isDeafened ? '🔇' : '🔊'}
          </button>
          <button
            onClick={() => ctx.setShowSettings(true)}
            className="voice-ctrl-btn"
            title="Settings (Ctrl+,)"
          >
            ⚙️
          </button>
          {inVoice && (
            <button
              className="voice-ctrl-btn voice-disconnect-btn"
              onClick={() => {
                ctx.setVoiceChannelId(null);
                ctx.setVoiceChannelName("");
                ctx.setVoiceConnectedAt(null);
              }}
              title="Disconnect"
            >
              📞
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
