import React from "react";
import { useAppContext } from "./AppContext";
import { notificationManager } from "../notifications";
import { Channel } from "../types";
import { BotPanel } from "./BotPanel";
import channelStyles from './layout/ChannelItem.module.css';
import listStyles from './layout/ChannelListContent.module.css';
import clsx from 'clsx';

// Voice Connection Panel (kept for reuse)
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
        <button className={`voice-ctrl-btn ${isMuted ? 'active' : ''}`} onClick={() => setIsMuted(!isMuted)} title={isMuted ? 'Unmute' : 'Mute'}>
          {isMuted ? '🔇' : '🎤'}
        </button>
        <button className={`voice-ctrl-btn ${isDeafened ? 'active' : ''}`} onClick={() => { setIsDeafened(!isDeafened); if (!isDeafened) setIsMuted(true); }} title={isDeafened ? 'Undeafen' : 'Deafen'}>
          {isDeafened ? '🔇' : '🔊'}
        </button>
        <button className="voice-ctrl-btn voice-disconnect-btn" onClick={onDisconnect} title="Disconnect">📞</button>
      </div>
    </div>
  );
};

export const ChannelSidebar: React.FC = () => {
  const ctx = useAppContext();
  const renderChannel = (channel: Channel) => {
    const isVoiceChannel = ctx.getChannelTypeNum(channel) === 2;
    const isActive = channel.id === ctx.selectedChannelId;
    const isConnectedToVoice = isVoiceChannel && ctx.voiceChannelId === channel.id;
    const clientUnreads = ctx.selectedNodeId
      ? notificationManager.getChannelUnreads(ctx.selectedNodeId, channel.id)
      : { count: 0, mentions: 0 };
    const channelUnreads = clientUnreads.count > 0 ? clientUnreads
      : { count: (channel as any).unread_count || 0, mentions: clientUnreads.mentions };
    const hasUnread = channelUnreads.count > 0 || channelUnreads.mentions > 0;

    return (
      <div key={channel.id} className={channelStyles.container}>
        {/* Unread indicator pill */}
        {hasUnread && !isActive && (
          <div className={channelStyles.unreadIndicator} />
        )}

        <div
          className={clsx(
            channelStyles.channelItem,
            channelStyles.channelItemRegular,
            channelStyles.channelItemHoverable,
            isActive && channelStyles.channelItemSelected,
            hasUnread && !isActive && channelStyles.channelItemHighlight,
          )}
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
          title={channel.topic || undefined}
        >
          {/* Channel icon */}
          <span className={clsx(
            channelStyles.channelItemIcon,
            isActive ? channelStyles.channelItemIconSelected : channelStyles.channelItemIconUnselected,
            hasUnread && !isActive && channelStyles.channelItemIconHighlight,
          )}>
            {isVoiceChannel ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 3a1 1 0 0 0-1 1v8.26A4.97 4.97 0 0 0 9 12a5 5 0 0 0-5 5 5 5 0 0 0 5 5 5 5 0 0 0 5-5V4a1 1 0 0 0-1-1z"/>
              </svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                <path d="M5.88657 21C5.57547 21 5.3399 20.7189 5.39427 20.4126L6.00001 17H2.59511C2.28449 17 2.04905 16.7198 2.10259 16.4138L2.27759 15.4138C2.31946 15.1746 2.52722 15 2.77011 15H6.35001L7.41001 9H4.00511C3.69449 9 3.45905 8.71977 3.51259 8.41381L3.68759 7.41381C3.72946 7.17456 3.93722 7 4.18011 7H7.76001L8.39677 3.41262C8.43914 3.17391 8.64664 3 8.88907 3H9.87344C10.1845 3 10.4201 3.28107 10.3657 3.58738L9.76001 7H15.76L16.3968 3.41262C16.4391 3.17391 16.6466 3 16.8891 3H17.8734C18.1845 3 18.4201 3.28107 18.3657 3.58738L17.76 7H21.1649C21.4755 7 21.711 7.28023 21.6574 7.58619L21.4824 8.58619C21.4406 8.82544 21.2328 9 20.9899 9H17.41L16.35 15H19.7549C20.0655 15 20.301 15.2802 20.2474 15.5862L20.0724 16.5862C20.0306 16.8254 19.8228 17 19.5799 17H16L15.3632 20.5874C15.3209 20.8261 15.1134 21 14.8709 21H13.8866C13.5755 21 13.3399 20.7189 13.3943 20.4126L14 17H8.00001L7.36325 20.5874C7.32088 20.8261 7.11337 21 6.87094 21H5.88657ZM9.41045 9L8.35045 15H14.3504L15.4104 9H9.41045Z"/>
              </svg>
            )}
          </span>

          {/* Channel name */}
          <span className={channelStyles.channelName}>{channel.name}</span>

          {/* Voice connected indicator */}
          {isConnectedToVoice && (
            <span style={{ fontSize: '10px', color: 'var(--status-online, #3ba55c)', marginLeft: 'auto' }}>●</span>
          )}

          {/* Badges */}
          <div className={channelStyles.channelItemActions}>
            {channelUnreads.mentions > 0 && (
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                minWidth: '16px', height: '16px', borderRadius: '8px',
                backgroundColor: 'var(--status-danger, #f04747)', color: 'white',
                fontSize: '11px', fontWeight: 700, padding: '0 4px',
              }}>
                {channelUnreads.mentions > 9 ? '9+' : channelUnreads.mentions}
              </div>
            )}
          </div>
        </div>

        {/* Voice channel connected users */}
        {isConnectedToVoice && ctx.voiceChannelId === channel.id && (
          <div style={{ paddingLeft: '2.5rem', paddingBottom: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', color: 'var(--text-tertiary-muted)' }}>
              <div style={{
                width: '20px', height: '20px', borderRadius: '50%',
                backgroundColor: 'var(--brand-primary)', color: 'white',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: '10px', fontWeight: 600,
              }}>
                {(ctx.appState.user?.display_name || "U")[0]}
              </div>
              <span>{ctx.appState.user?.display_name || "You"}</span>
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className={listStyles.channelListScrollerWrapper}>
      <div className={listStyles.navigationContainer}>
        <div className={listStyles.channelGroupsContainer}>
          {/* Uncategorized channels */}
          <div className={listStyles.channelGroup}>
            {ctx.uncategorizedChannels.map(ch => renderChannel(ch))}
          </div>

          {/* Categories with children */}
          {ctx.categories.map(cat => {
            const children = ctx.categorizedChannels(cat.id);
            const isCollapsed = ctx.collapsedCategories.has(cat.id);

            return (
              <div key={cat.id} className={listStyles.channelGroup}>
                {/* Category header */}
                <div className={channelStyles.container}>
                  <div
                    className={clsx(
                      channelStyles.channelItem,
                      channelStyles.channelItemCategory,
                    )}
                    onClick={() => ctx.toggleCategory(cat.id)}
                    role="button"
                  >
                    <svg
                      className={channelStyles.categoryIcon}
                      width="12" height="12" viewBox="0 0 12 12"
                      fill="currentColor"
                      style={{
                        transform: isCollapsed ? 'rotate(-90deg)' : 'rotate(0deg)',
                        transition: 'transform 100ms ease',
                      }}
                    >
                      <path d="M2 4l4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                    <span className={channelStyles.categoryName}>{cat.name.toUpperCase()}</span>

                    {/* Create channel in category */}
                    {ctx.selectedNodeId && ctx.hasPermission(ctx.selectedNodeId, 'CreateChannel') && (
                      <div className={clsx(channelStyles.channelItemActions, channelStyles.hoverAffordance)}>
                        <button
                          className={channelStyles.createChannelButton}
                          onClick={(e) => { e.stopPropagation(); ctx.setShowCreateChannelForm(true); }}
                          title="Create Channel"
                        >
                          <svg className={channelStyles.createChannelIcon} width="16" height="16" viewBox="0 0 16 16" fill="none">
                            <path d="M8 3v10M3 8h10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                          </svg>
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* Channel children */}
                {!isCollapsed && children.map(ch => renderChannel(ch))}
              </div>
            );
          })}
        </div>

        {/* Create Channel Button */}
        {ctx.selectedNodeId && ctx.hasPermission(ctx.selectedNodeId, 'CreateChannel') && (
          <div style={{ padding: '8px 8px 4px' }}>
            {!ctx.showCreateChannelForm ? (
              <div
                className={clsx(channelStyles.channelItem, channelStyles.channelItemRegular, channelStyles.channelItemHoverable)}
                onClick={() => ctx.setShowCreateChannelForm(true)}
                style={{ cursor: 'pointer', marginLeft: '0.5rem' }}
              >
                <svg width="20" height="20" viewBox="0 0 20 20" fill="none" style={{ color: 'var(--text-tertiary-muted)' }}>
                  <path d="M10 4v12M4 10h12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                </svg>
                <span className={channelStyles.channelName} style={{ color: 'var(--text-tertiary-muted)' }}>Create Channel</span>
              </div>
            ) : (
              <div style={{ padding: '4px 0', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <input
                  type="text"
                  placeholder="Channel name"
                  value={ctx.newChannelName}
                  onChange={(e) => ctx.setNewChannelName(e.target.value)}
                  style={{
                    background: 'var(--background-tertiary)',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '6px 8px',
                    color: 'var(--text-primary)',
                    fontSize: '14px',
                    outline: 'none',
                  }}
                />
                <select
                  value={ctx.newChannelType}
                  onChange={(e) => ctx.setNewChannelType(e.target.value)}
                  style={{
                    background: 'var(--background-tertiary)',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '6px 8px',
                    color: 'var(--text-primary)',
                    fontSize: '13px',
                  }}
                >
                  <option value="text">Text Channel</option>
                  <option value="voice">Voice Channel</option>
                </select>
                <div style={{ display: 'flex', gap: '6px' }}>
                  <button onClick={ctx.handleCreateChannel} style={{
                    background: 'var(--brand-primary)',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '4px 12px',
                    color: 'white',
                    fontSize: '13px',
                    cursor: 'pointer',
                  }}>Create</button>
                  <button onClick={() => { ctx.setShowCreateChannelForm(false); ctx.setNewChannelName(""); ctx.setNewChannelType("text"); }} style={{
                    background: 'transparent',
                    border: '1px solid var(--background-modifier-accent)',
                    borderRadius: '4px',
                    padding: '4px 12px',
                    color: 'var(--text-secondary)',
                    fontSize: '13px',
                    cursor: 'pointer',
                  }}>Cancel</button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Bot Panel */}
        {ctx.selectedNodeId && (
          <BotPanel
            nodeId={ctx.selectedNodeId}
            isAdmin={ctx.selectedNodeId ? ctx.hasPermission(ctx.selectedNodeId, 'ManageNode') : false}
          />
        )}

        {/* DM Section */}
        <DMSection />

        <div className={listStyles.bottomSpacer} />
      </div>

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
    <div style={{ marginTop: '8px' }}>
      <div className={channelStyles.container}>
        <div
          className={clsx(channelStyles.channelItem, channelStyles.channelItemCategory)}
          style={{ cursor: 'default' }}
        >
          <span className={channelStyles.categoryName}>DIRECT MESSAGES</span>
          <div className={clsx(channelStyles.channelItemActions)}>
            <button
              className={channelStyles.createChannelButton}
              onClick={() => ctx.setShowDmChannelCreate(!ctx.showDmChannelCreate)}
              title="Create DM"
            >
              <svg className={channelStyles.createChannelIcon} width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M8 3v10M3 8h10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              </svg>
            </button>
          </div>
        </div>
      </div>

      {ctx.dmChannels.map((dmChannel) => {
        const isActive = ctx.selectedDmChannel?.id === dmChannel.id;
        const dmUnreads = notificationManager.getChannelUnreads(`dm-${dmChannel.id}`, dmChannel.id);

        return (
          <div key={dmChannel.id} className={channelStyles.container}>
            <div
              className={clsx(
                channelStyles.channelItem,
                channelStyles.channelItemRegular,
                channelStyles.channelItemHoverable,
                isActive && channelStyles.channelItemSelected,
              )}
              onClick={() => ctx.handleDmChannelSelect(dmChannel)}
            >
              <div style={{
                width: '20px', height: '20px', borderRadius: '50%',
                backgroundColor: 'var(--brand-primary)', color: 'white',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: '10px', fontWeight: 600, flexShrink: 0,
              }}>
                {(dmChannel.other_user_profile?.display_name || "?")[0].toUpperCase()}
              </div>
              <span className={channelStyles.channelName}>{dmChannel.other_user_profile.display_name}</span>

              {/* DM badges */}
              <div className={channelStyles.channelItemActions}>
                {dmUnreads.mentions > 0 && (
                  <div style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    minWidth: '16px', height: '16px', borderRadius: '8px',
                    backgroundColor: 'var(--status-danger, #f04747)', color: 'white',
                    fontSize: '11px', fontWeight: 700, padding: '0 4px',
                  }}>
                    {dmUnreads.mentions > 9 ? '9+' : dmUnreads.mentions}
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })}

      {ctx.dmChannels.length === 0 && (
        <div style={{ padding: '8px 16px', fontSize: '13px', color: 'var(--text-tertiary-muted)' }}>
          No direct messages yet
        </div>
      )}
    </div>
  );
};
