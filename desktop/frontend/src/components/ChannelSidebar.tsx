import React from "react";
import { useAppContext } from "./AppContext";
import { Icon } from "./Icon";
import { api } from "../api";
import { notificationManager } from "../notifications";
import { avatarColor } from "../avatarColor";
import { Channel } from "../types";
import { ServerHeader } from "./ServerHeader";
// buildHash imports moved to MemberSidebar for trust indicator
const BotPanel = React.lazy(() => import("./BotPanel").then(m => ({ default: m.BotPanel })));

// Voice Connection Panel (kept for potential reuse; controls now merged into UserPanel)
export const VoiceConnectionPanel: React.FC<{
  channelName: string;
  connectedAt: number | null;
  onDisconnect: () => void;
}> = ({ channelName, connectedAt, onDisconnect }) => {
  const ctx = useAppContext();
  const [elapsed, setElapsed] = React.useState("00:00");
  const isMuted = ctx.voiceMuted;
  const setIsMuted = ctx.setVoiceMuted;
  const isDeafened = ctx.voiceDeafened;
  const setIsDeafened = ctx.setVoiceDeafened;

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
          <Icon name={isMuted ? 'mic-off' : 'mic'} size={18} />
        </button>
        <button
          className={`voice-ctrl-btn ${isDeafened ? 'active' : ''}`}
          onClick={() => { setIsDeafened(!isDeafened); if (!isDeafened) setIsMuted(true); }}
          title={isDeafened ? 'Undeafen' : 'Deafen'}
        >
          <Icon name={isDeafened ? 'speaker-off' : 'speaker'} size={18} />
        </button>
        <button
          className="voice-ctrl-btn voice-disconnect-btn"
          onClick={onDisconnect}
          title="Disconnect"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 9c-1.6 0-3.15.25-4.6.72v3.1c0 .39-.23.74-.56.9-.98.49-1.87 1.12-2.66 1.85-.18.18-.43.28-.7.28-.28 0-.53-.11-.71-.29L.29 13.08c-.18-.17-.29-.42-.29-.7 0-.28.11-.53.29-.71C3.34 8.78 7.46 7 12 7s8.66 1.78 11.71 4.67c.18.18.29.43.29.71 0 .28-.11.53-.29.71l-2.48 2.48c-.18.18-.43.29-.71.29-.27 0-.52-.11-.7-.28-.79-.73-1.68-1.36-2.66-1.85-.33-.16-.56-.5-.56-.9v-3.1C15.15 9.25 13.6 9 12 9z"/></svg>
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

  const [channelMenu, setChannelMenu] = React.useState<{ open: boolean; x: number; y: number; channelId: string } | null>(null);
  const channelMenuRef = React.useRef<HTMLDivElement>(null);

  const closeChannelMenu = React.useCallback(() => setChannelMenu(null), []);

  React.useEffect(() => {
    if (!channelMenu?.open) return;
    const handleClick = (e: MouseEvent) => {
      if (channelMenuRef.current && !channelMenuRef.current.contains(e.target as Node)) closeChannelMenu();
    };
    const handleEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') closeChannelMenu(); };
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleEsc);
    return () => { document.removeEventListener('mousedown', handleClick); document.removeEventListener('keydown', handleEsc); };
  }, [channelMenu?.open, closeChannelMenu]);

  const handleMarkChannelAsRead = React.useCallback((channelId: string) => {
    if (ctx.selectedNodeId) {
      notificationManager.markChannelAsRead(ctx.selectedNodeId, channelId);
      ctx.setForceUpdate((p: number) => p + 1);
    }
    closeChannelMenu();
  }, [ctx, closeChannelMenu]);

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
        role="option"
        aria-selected={isActive}
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); const isVoice = ctx.getChannelTypeNum(channel) === 2; if (isVoice) { if (ctx.voiceChannelId !== channel.id) { ctx.setVoiceChannelId(channel.id); ctx.setVoiceChannelName(channel.name); ctx.setVoiceConnectedAt(Date.now()); } } else { ctx.handleChannelSelect(channel.id, `# ${channel.name}`); } } }}
        draggable={canManageChannels}
        onDragStart={(e) => handleDragStart(e, { type: 'channel', id: channel.id, categoryId: channel.parent_id || null })}
        onDragEnd={handleDragEnd}
        onDragOver={(e) => handleDragOver(e, channel.id, 'channel')}
        onDrop={handleDrop}
        onContextMenu={(e) => {
          e.preventDefault();
          setChannelMenu({ open: true, x: e.clientX, y: e.clientY, channelId: channel.id });
        }}
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
          className="channel-item-inner"
        >
          <span className={isVoiceChannel ? 'channel-voice-text' : ''}>
            {isVoiceChannel ? <Icon name="speaker" size={16} /> : <span className="channel-hash">#</span>} {channel.name}
          </span>
          {isVoiceChannel && !isConnectedToVoice && (
            <span className="voice-channel-label" title="Join Voice">Join Voice</span>
          )}
          {isConnectedToVoice && (
            <span className="voice-channel-connected-dot">●</span>
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
        {isConnectedToVoice && ctx.voiceChannelId === channel.id && ctx.voiceChannelUsers.length > 0 && (
          <div className="voice-channel-users">
            {ctx.voiceChannelUsers.map(u => (
              <div key={u.userId} className={`voice-channel-user${u.isSpeaking ? ' speaking' : ''}`}>
                <div className={`voice-user-avatar${u.isSpeaking ? ' speaking' : ''}`}>
                  {(u.displayName || "U")[0].toUpperCase()}
                </div>
                <span className="voice-user-name">{u.displayName}</span>
                {u.isMuted && <Icon name="mic-off" size={12} />}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="channel-sidebar" role="navigation" aria-label="Channel sidebar">
      <ServerHeader />
      
      <div className="channel-list" role="listbox" aria-label="Channels">
        {/* Uncategorized channels */}
        {ctx.uncategorizedChannels.length > 0 && (
          <div className="channel-category channel-category-relative">
            <div
              className="category-header"
              onClick={() => ctx.toggleCategory('__uncategorized__')}
            >
              <span className="category-arrow">{ctx.collapsedCategories.has('__uncategorized__') ? '▶' : '▼'}</span>
              <span className="category-name">CHANNELS</span>
              {canManageChannels && (
                <button
                  className="category-add-btn"
                  title="Create Channel"
                  onClick={(e) => { e.stopPropagation(); ctx.setNewChannelCategoryId(''); ctx.setShowCreateChannelForm(true); }}
                >+</button>
              )}
            </div>
            {!ctx.collapsedCategories.has('__uncategorized__') && ctx.uncategorizedChannels.map(ch => renderChannel(ch))}
          </div>
        )}
        
        {/* Categories with their children */}
        {ctx.categories.map(cat => {
          const children = ctx.categorizedChannels(cat.id);
          const isCollapsed = ctx.collapsedCategories.has(cat.id);
          return (
            <div key={cat.id} className="channel-category channel-category-relative">
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
                {canManageChannels && (
                  <button
                    className="category-add-btn"
                    title={`Create Channel in ${cat.name}`}
                    onClick={(e) => { e.stopPropagation(); ctx.setNewChannelCategoryId(cat.id); ctx.setShowCreateChannelForm(true); }}
                  >+</button>
                )}
              </div>
              {!isCollapsed && children.map(ch => renderChannel(ch))}
            </div>
          );
        })}
        
        {/* Create Channel Button for Admins */}
        {ctx.selectedNodeId && ctx.hasPermission(ctx.selectedNodeId, 'CreateChannel') && (
          <div className="create-channel-wrapper">
            {!ctx.showCreateChannelForm ? (
              <button onClick={() => ctx.setShowCreateChannelForm(true)} className="create-channel-btn" title="Create Channel" aria-label="Create Channel">
                +
              </button>
            ) : (
              <div className="create-channel-form">
                <input type="text" placeholder="Channel name" value={ctx.newChannelName} onChange={(e) => ctx.setNewChannelName(e.target.value)} />
                <div className="create-channel-type-row">
                  <button
                    className={`create-channel-type-btn ${ctx.newChannelType === 'text' ? 'active' : ''}`}
                    onClick={() => ctx.setNewChannelType('text')}
                    title="Text Channel"
                    type="button"
                  >
                    <Icon name="hash" size={14} /> Text
                  </button>
                  <button
                    className={`create-channel-type-btn ${ctx.newChannelType === 'voice' ? 'active' : ''}`}
                    onClick={() => ctx.setNewChannelType('voice')}
                    title="Voice Channel"
                    type="button"
                  >
                    <Icon name="speaker" size={14} /> Voice
                  </button>
                </div>
                <input type="text" placeholder="Topic (optional)" value={ctx.newChannelTopic} onChange={(e) => ctx.setNewChannelTopic(e.target.value)} />
                {ctx.categories.length > 0 && (
                  <select value={ctx.newChannelCategoryId} onChange={(e) => ctx.setNewChannelCategoryId(e.target.value)}>
                    <option value="">No category</option>
                    {ctx.categories.map(cat => (
                      <option key={cat.id} value={cat.id}>{cat.name}</option>
                    ))}
                  </select>
                )}
                <div className="create-channel-actions">
                  <button onClick={ctx.handleCreateChannel} className="btn btn-green btn-sm">Create</button>
                  <button onClick={() => { ctx.setShowCreateChannelForm(false); ctx.setNewChannelName(""); ctx.setNewChannelType("text"); ctx.setNewChannelTopic(""); ctx.setNewChannelCategoryId(""); }} className="btn btn-outline btn-sm">Cancel</button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Bot Panel */}
      {ctx.selectedNodeId && (
        <React.Suspense fallback={null}>
          <BotPanel
            nodeId={ctx.selectedNodeId}
            isAdmin={ctx.selectedNodeId ? ctx.hasPermission(ctx.selectedNodeId, 'ManageNode') : false}
          />
        </React.Suspense>
      )}

      {/* Direct Messages Section */}
      <DMSection />

      <UserPanel />

      {/* Channel context menu */}
      {channelMenu?.open && (
        <>
          <div className="context-menu-backdrop" onClick={closeChannelMenu} />
          <div
            ref={channelMenuRef}
            className="context-menu"
            style={{ left: channelMenu.x, top: channelMenu.y }}
          >
            <div
              className="context-menu-item"
              onClick={() => handleMarkChannelAsRead(channelMenu.channelId)}
            >
              <span className="context-menu-icon">✓</span>
              <span>Mark as Read</span>
            </div>
          </div>
        </>
      )}

      {/* Custom Status Popover */}
      {ctx.showStatusPopover && (
        <div className="status-popover" role="dialog" aria-label="Set Custom Status" onKeyDown={(e) => { if (e.key === 'Escape') ctx.setShowStatusPopover(false); }}>
          <div className="status-popover-header">
            <span>Set Custom Status</span>
            <button onClick={() => ctx.setShowStatusPopover(false)} className="status-popover-close" aria-label="Close">×</button>
          </div>
          <div className="status-popover-input-row">
            <StatusEmojiPicker
              onSelect={(emoji) => {
                // Prefix the status with the emoji if not already there
                const current = ctx.statusInput;
                // Check if already starts with an emoji-like prefix
                const emojiRegex = /^(\p{Emoji_Presentation}|\p{Emoji}\uFE0F)\s*/u;
                const stripped = current.replace(emojiRegex, '');
                ctx.setStatusInput(`${emoji} ${stripped}`.slice(0, 128));
              }}
            />
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
          </div>
          <div className="status-popover-footer">
            <span className="status-popover-count">{ctx.statusInput.length}/128</span>
            <div className="status-popover-actions">
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

const STATUS_EMOJIS = ['😀', '😊', '🎮', '🎵', '📚', '💻', '🏠', '🌙', '☕', '🔴', '🟢', '⚡', '🎯', '🤔', '✨'];

const StatusEmojiPicker: React.FC<{ onSelect: (emoji: string) => void }> = ({ onSelect }) => {
  const [open, setOpen] = React.useState(false);
  return (
    <div className="status-emoji-picker-wrapper">
      <button className="status-emoji-btn" onClick={() => setOpen(!open)} title="Add emoji" type="button">😀</button>
      {open && (
        <div className="status-emoji-grid">
          {STATUS_EMOJIS.map(e => (
            <button key={e} className="status-emoji-option" onClick={() => { onSelect(e); setOpen(false); }}>{e}</button>
          ))}
        </div>
      )}
    </div>
  );
};

const DMSection: React.FC = () => {
  const ctx = useAppContext();
  const [hiddenDms, setHiddenDms] = React.useState<Set<string>>(() => {
    try {
      const stored = localStorage.getItem('accord_hidden_dms');
      return stored ? new Set(JSON.parse(stored)) : new Set();
    } catch { return new Set(); }
  });

  const hideDm = React.useCallback((e: React.MouseEvent, dmId: string) => {
    e.stopPropagation();
    setHiddenDms(prev => {
      const next = new Set(prev);
      next.add(dmId);
      localStorage.setItem('accord_hidden_dms', JSON.stringify([...next]));
      return next;
    });
  }, []);

  // Sort DMs by last message time (most recent first), then by created_at
  const sortedDms = React.useMemo(() => {
    return [...ctx.dmChannels]
      .filter(dm => !hiddenDms.has(dm.id))
      .sort((a, b) => {
        const aTime = a.last_message?.timestamp ?? a.created_at;
        const bTime = b.last_message?.timestamp ?? b.created_at;
        return bTime - aTime;
      });
  }, [ctx.dmChannels, hiddenDms]);

  return (
    <div className="dm-section">
      <div className="dm-header">
        Direct Messages
        <button onClick={() => ctx.setShowDmChannelCreate(!ctx.showDmChannelCreate)} className="dm-header-add-btn" title="New Direct Message" aria-label="Create direct message">+</button>
      </div>
      
      <div className="dm-list">
        {sortedDms.map((dmChannel) => {
          const isActive = ctx.selectedDmChannel?.id === dmChannel.id;
          const dmUnreads = notificationManager.getChannelUnreads(`dm-${dmChannel.id}`, dmChannel.id);
          const hasUnread = dmUnreads.count > 0 || dmUnreads.mentions > 0;
          
          return (
            <div
              key={dmChannel.id}
              className={`dm-item ${isActive ? 'active' : ''} ${hasUnread && !isActive ? 'dm-unread' : ''}`}
              onClick={() => ctx.handleDmChannelSelect(dmChannel)}
            >
              <div className="dm-avatar" style={{ background: avatarColor(dmChannel.other_user?.id || '') }}>
                {dmChannel.other_user?.id ? (
                  <img
                    src={`${api.getUserAvatarUrl(dmChannel.other_user.id)}`}
                    alt={(dmChannel.other_user_profile?.display_name || "?")[0]}
                    onError={(e) => { const img = e.target as HTMLImageElement; img.style.display = 'none'; if (img.parentElement) img.parentElement.textContent = (dmChannel.other_user_profile?.display_name || "?")[0].toUpperCase(); }}
                  />
                ) : (dmChannel.other_user_profile?.display_name || "?")[0].toUpperCase()}
                <span className={`presence-dot presence-${ctx.getPresenceStatus(dmChannel.other_user?.id || '')}`} />
              </div>
              <div className="dm-item-info">
                <div className={`dm-name ${hasUnread && !isActive ? 'dm-name-unread' : ''}`}>{dmChannel.other_user_profile.display_name}</div>
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
                  <div className="unread-badge dm-unread-badge">
                    {dmUnreads.count > 99 ? '99+' : dmUnreads.count}
                  </div>
                )}
                <button
                  className="dm-close-btn"
                  onClick={(e) => hideDm(e, dmChannel.id)}
                  title="Hide conversation"
                  aria-label="Hide DM conversation"
                >×</button>
              </div>
            </div>
          );
        })}
        
        {sortedDms.length === 0 && (
          <div className="dm-empty">No direct messages yet</div>
        )}
      </div>
    </div>
  );
};

const UserPanel: React.FC = () => {
  const ctx = useAppContext();
  const isMuted = ctx.voiceMuted;
  const setIsMuted = ctx.setVoiceMuted;
  const isDeafened = ctx.voiceDeafened;
  const setIsDeafened = ctx.setVoiceDeafened;
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
    <>
      {inVoice && (
        <div className="voice-connection-panel">
          <div className="voice-connection-info">
            <span className="voice-connection-dot voice-connection-dot-active">●</span>
            <div className="voice-connection-details">
              <span className="voice-connection-label">Voice Connected</span>
              <span className="voice-connection-channel">#{ctx.voiceChannelName} — {elapsed}</span>
            </div>
          </div>
          <div className="voice-connection-controls">
            <button className={`voice-ctrl-btn${isMuted ? ' active' : ''}`} onClick={() => setIsMuted(!isMuted)} title={isMuted ? 'Unmute' : 'Mute'}>
              <Icon name={isMuted ? 'mic-off' : 'mic'} size={18} />
            </button>
            <button className={`voice-ctrl-btn${isDeafened ? ' active' : ''}`} onClick={() => { setIsDeafened(!isDeafened); if (!isDeafened) setIsMuted(true); }} title={isDeafened ? 'Undeafen' : 'Deafen'}>
              <Icon name={isDeafened ? 'speaker-off' : 'speaker'} size={18} />
            </button>
            <button className="voice-ctrl-btn voice-disconnect-btn" onClick={() => {
              ctx.setVoiceChannelId(null); ctx.setVoiceChannelName(""); ctx.setVoiceConnectedAt(null);
              ctx.setVoiceMuted(false); ctx.setVoiceDeafened(false);
            }} title="Disconnect"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 9c-1.6 0-3.15.25-4.6.72v3.1c0 .39-.23.74-.56.9-.98.49-1.87 1.12-2.66 1.85-.18.18-.43.28-.7.28-.28 0-.53-.11-.71-.29L.29 13.08c-.18-.17-.29-.42-.29-.7 0-.28.11-.53.29-.71C3.34 8.78 7.46 7 12 7s8.66 1.78 11.71 4.67c.18.18.29.43.29.71 0 .28-.11.53-.29.71l-2.48 2.48c-.18.18-.43.29-.71.29-.27 0-.52-.11-.7-.28-.79-.74-1.69-1.36-2.67-1.85-.33-.16-.56-.5-.56-.9v-3.1C15.15 9.25 13.6 9 12 9z"/></svg></button>
          </div>
        </div>
      )}
      <div className="user-panel">
        <div className="user-avatar" style={{ background: avatarColor(ctx.appState.user?.id || ''), cursor: 'pointer' }} onClick={() => ctx.setShowStatusPicker(prev => !prev)}>
          {ctx.appState.user?.id ? (
            <img
              src={`${api.getUserAvatarUrl(ctx.appState.user.id)}`}
              alt={(ctx.appState.user?.display_name || "U")[0]}
              onError={(e) => { const img = e.target as HTMLImageElement; img.style.display = 'none'; img.removeAttribute('src'); if (img.parentElement) img.parentElement.textContent = (ctx.appState.user?.display_name || ctx.fingerprint(ctx.appState.user?.public_key_hash || ''))?.[0] || "U"; }}
            />
          ) : ((ctx.appState.user?.display_name || ctx.fingerprint(ctx.appState.user?.public_key_hash || ''))?.[0] || "U")}
          <span className={`presence-dot presence-${ctx.userPresenceStatus === 'invisible' as any ? 'offline' : ctx.userPresenceStatus}`} />
        </div>
        {ctx.showStatusPicker && (
          <div className="status-picker" role="menu" aria-label="Set status">
            <div className="status-picker-item" role="menuitem" onClick={() => ctx.handleSetPresenceStatus('online' as any)}>
              <span className="presence-dot presence-online" /> Online
            </div>
            <div className="status-picker-item" role="menuitem" onClick={() => ctx.handleSetPresenceStatus('idle' as any)}>
              <span className="presence-dot presence-idle" /> Idle
            </div>
            <div className="status-picker-item" role="menuitem" onClick={() => ctx.handleSetPresenceStatus('dnd' as any)}>
              <span className="presence-dot presence-dnd" /> Do Not Disturb
            </div>
            <div className="status-picker-item" role="menuitem" onClick={() => ctx.handleSetPresenceStatus('invisible' as any)}>
              <span className="presence-dot presence-offline" /> Invisible
            </div>
            <div className="status-picker-divider" />
            <div className="status-picker-item" role="menuitem" onClick={() => { ctx.setShowStatusPicker(false); ctx.setStatusInput(ctx.customStatus); ctx.setShowStatusPopover(true); }}>
              ✏️ Set Custom Status
            </div>
          </div>
        )}
        <div className="user-info user-info-clickable" onClick={() => { ctx.setStatusInput(ctx.customStatus); ctx.setShowStatusPopover(true); }}>
          <div className="username">{ctx.appState.user?.display_name || ctx.fingerprint(ctx.appState.user?.public_key_hash || '') || "You"}</div>
          <div className="user-status">
            {ctx.customStatus || (() => {
              if (!ctx.appState.isConnected && ctx.nodes.length > 0) return 'Offline';
              if (!ctx.appState.isConnected) return 'Ready';
              switch (ctx.userPresenceStatus) {
                case 'dnd' as any: return 'Do Not Disturb';
                case 'idle' as any: return 'Idle';
                case 'invisible' as any: return 'Invisible';
                default: return 'Online';
              }
            })()}
          </div>
        </div>
        <div className="user-panel-controls">
          <button className={`voice-ctrl-btn ${isMuted ? 'active' : ''}`} onClick={() => setIsMuted(!isMuted)} title={isMuted ? 'Unmute' : 'Mute'} aria-label={isMuted ? 'Unmute' : 'Mute'} role="switch" aria-checked={isMuted}>
            <Icon name={isMuted ? 'mic-off' : 'mic'} size={18} />
          </button>
          <button className={`voice-ctrl-btn ${isDeafened ? 'active' : ''}`} onClick={() => { setIsDeafened(!isDeafened); if (!isDeafened) setIsMuted(true); }} title={isDeafened ? 'Undeafen' : 'Deafen'} aria-label={isDeafened ? 'Undeafen' : 'Deafen'} role="switch" aria-checked={isDeafened}>
            <Icon name={isDeafened ? 'speaker-off' : 'speaker'} size={18} />
          </button>
          <button onClick={() => ctx.setShowSettings(true)} className="voice-ctrl-btn" title="Settings (Ctrl+,)" aria-label="Settings"><Icon name="settings" size={18} /></button>
        </div>
      </div>
    </>
  );
};
