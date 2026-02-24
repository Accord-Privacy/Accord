import styles from './UserArea.module.css';
import { useAppContext } from '../AppContext';
import { api } from '../../api';
import clsx from 'clsx';

interface UserAreaProps {
  children?: React.ReactNode;
}

export function UserArea({ children }: UserAreaProps) {
  const ctx = useAppContext();
  const isMuted = ctx.voiceMuted;
  const isDeafened = ctx.voiceDeafened;

  return (
    <div className={styles.userAreaInnerWrapper}>
      {/* Voice connection panel */}
      {ctx.voiceChannelId && <VoiceConnectionBar />}

      <div className={styles.separator} />
      <div className={styles.userAreaContainer}>
        {/* User info */}
        <div
          className={styles.userInfo}
          onClick={() => { ctx.setStatusInput(ctx.customStatus); ctx.setShowStatusPopover(true); }}
        >
          {/* Avatar */}
          <div style={{
            width: '32px', height: '32px', borderRadius: '50%', overflow: 'hidden',
            position: 'relative', flexShrink: 0,
          }}>
            {ctx.appState.user?.id ? (
              <img
                src={`${api.getUserAvatarUrl(ctx.appState.user.id)}`}
                alt={(ctx.appState.user?.display_name || "U")[0]}
                style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                onError={(e) => {
                  const img = e.target as HTMLImageElement;
                  img.style.display = 'none';
                  if (img.parentElement) {
                    img.parentElement.textContent = (ctx.appState.user?.display_name || "U")[0];
                    img.parentElement.setAttribute('style', 'width:32px;height:32px;border-radius:50%;background:var(--brand-primary);color:white;display:flex;align-items:center;justify-content:center;font-weight:600;font-size:14px;flex-shrink:0;');
                  }
                }}
              />
            ) : (
              <div style={{
                width: '32px', height: '32px', borderRadius: '50%',
                background: 'var(--brand-primary)', color: 'white',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontWeight: 600, fontSize: '14px',
              }}>
                {(ctx.appState.user?.display_name || ctx.fingerprint(ctx.appState.user?.public_key_hash || ''))?.[0] || "U"}
              </div>
            )}
            {/* Presence dot */}
            <span style={{
              position: 'absolute', bottom: '-1px', right: '-1px',
              width: '10px', height: '10px', borderRadius: '50%',
              border: '2px solid var(--panel-control-bg)',
              backgroundColor: ctx.appState.isConnected ? 'var(--status-online, #3ba55c)' : 'var(--text-tertiary-muted)',
            }} />
          </div>

          {/* Name and status */}
          <div className={styles.userInfoText}>
            <span className={styles.userName}>
              {ctx.appState.user?.display_name || ctx.fingerprint(ctx.appState.user?.public_key_hash || '') || "You"}
            </span>
            <span className={styles.userStatus}>
              {ctx.customStatus || (ctx.appState.isConnected ? "Online" : (ctx.nodes.length === 0 ? "Ready" : "Offline"))}
            </span>
          </div>
        </div>

        {/* Control buttons */}
        <div className={styles.controlsContainer}>
          <button
            className={clsx(styles.controlButton, isMuted && styles.active)}
            onClick={() => ctx.setVoiceMuted(!isMuted)}
            title={isMuted ? 'Unmute' : 'Mute'}
          >
            <svg className={styles.controlIcon} viewBox="0 0 24 24" fill="currentColor">
              {isMuted ? (
                <path d="M19 11h-1.7c0 .74-.16 1.43-.43 2.05l1.23 1.23c.56-.98.9-2.09.9-3.28zm-4.02.17c0-.06.02-.11.02-.17V5c0-1.66-1.34-3-3-3S9 3.34 9 5v.18l5.98 5.99zM4.27 3L3 4.27l6.01 6.01V11c0 1.66 1.33 3 2.99 3 .22 0 .44-.03.65-.08l1.66 1.66c-.71.33-1.5.52-2.31.52-2.76 0-5.3-2.1-5.3-5.1H5c0 3.41 2.72 6.23 6 6.72V21h2v-3.28c.91-.13 1.77-.45 2.55-.9l4.17 4.18L21 19.73 4.27 3z"/>
              ) : (
                <path d="M12 14c1.66 0 2.99-1.34 2.99-3L15 5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3zm5.3-3c0 3-2.54 5.1-5.3 5.1S6.7 14 6.7 11H5c0 3.41 2.72 6.23 6 6.72V21h2v-3.28c3.28-.48 6-3.3 6-6.72h-1.7z"/>
              )}
            </svg>
          </button>
          <button
            className={clsx(styles.controlButton, isDeafened && styles.active)}
            onClick={() => { ctx.setVoiceDeafened(!isDeafened); if (!isDeafened) ctx.setVoiceMuted(true); }}
            title={isDeafened ? 'Undeafen' : 'Deafen'}
          >
            <svg className={styles.controlIcon} viewBox="0 0 24 24" fill="currentColor">
              {isDeafened ? (
                <path d="M4.34 2.93L2.93 4.34 7.29 8.7 7 9H3v6h4l5 5v-6.59l4.18 4.18c-.65.49-1.38.88-2.18 1.11v2.06c1.34-.3 2.57-.97 3.6-1.88l2.05 2.05 1.41-1.41L4.34 2.93zM19 12c0 .82-.15 1.61-.41 2.34l1.53 1.53c.56-1.17.88-2.48.88-3.87 0-4.28-2.99-7.86-7-8.77v2.06c2.89.86 5 3.54 5 6.71zm-7-8l-1.88 1.88L12 7.76V4zm4.5 8A4.5 4.5 0 0 0 14 7.97v2.21l2.45 2.45c.03-.2.05-.41.05-.63z"/>
              ) : (
                <path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3A4.5 4.5 0 0 0 14 7.97v8.05c1.48-.73 2.5-2.25 2.5-3.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/>
              )}
            </svg>
          </button>
          <button
            className={styles.controlButton}
            onClick={() => ctx.setShowSettings(true)}
            title="Settings"
          >
            <svg className={styles.controlIcon} viewBox="0 0 24 24" fill="currentColor">
              <path d="M19.14,12.94c0.04-0.3,0.06-0.61,0.06-0.94c0-0.32-0.02-0.64-0.07-0.94l2.03-1.58c0.18-0.14,0.23-0.41,0.12-0.61 l-1.92-3.32c-0.12-0.22-0.37-0.29-0.59-0.22l-2.39,0.96c-0.5-0.38-1.03-0.7-1.62-0.94L14.4,2.81c-0.04-0.24-0.24-0.41-0.48-0.41 h-3.84c-0.24,0-0.43,0.17-0.47,0.41L9.25,5.35C8.66,5.59,8.12,5.92,7.63,6.29L5.24,5.33c-0.22-0.08-0.47,0-0.59,0.22L2.74,8.87 C2.62,9.08,2.66,9.34,2.86,9.48l2.03,1.58C4.84,11.36,4.8,11.69,4.8,12s0.02,0.64,0.07,0.94l-2.03,1.58 c-0.18,0.14-0.23,0.41-0.12,0.61l1.92,3.32c0.12,0.22,0.37,0.29,0.59,0.22l2.39-0.96c0.5,0.38,1.03,0.7,1.62,0.94l0.36,2.54 c0.05,0.24,0.24,0.41,0.48,0.41h3.84c0.24,0,0.44-0.17,0.47-0.41l0.36-2.54c0.59-0.24,1.13-0.56,1.62-0.94l2.39,0.96 c0.22,0.08,0.47,0,0.59-0.22l1.92-3.32c0.12-0.22,0.07-0.47-0.12-0.61L19.14,12.94z M12,15.6c-1.98,0-3.6-1.62-3.6-3.6 s1.62-3.6,3.6-3.6s3.6,1.62,3.6,3.6S13.98,15.6,12,15.6z"/>
            </svg>
          </button>
        </div>
      </div>
      {children}
    </div>
  );
}

function VoiceConnectionBar() {
  const ctx = useAppContext();
  const [elapsed, setElapsed] = React.useState("00:00");

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
    <div style={{
      padding: '8px 12px',
      borderBottom: '1px solid var(--user-area-divider-color)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
        <span style={{ color: 'var(--status-online, #3ba55c)', fontSize: '12px' }}>●</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--status-online, #3ba55c)' }}>Voice Connected</div>
          <div style={{ fontSize: '11px', color: 'var(--text-tertiary-muted)' }}>#{ctx.voiceChannelName} — {elapsed}</div>
        </div>
        <button
          onClick={() => {
            ctx.setVoiceChannelId(null); ctx.setVoiceChannelName(""); ctx.setVoiceConnectedAt(null);
            ctx.setVoiceMuted(false); ctx.setVoiceDeafened(false);
          }}
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--text-tertiary-muted)', fontSize: '16px',
          }}
          title="Disconnect"
        >
          📞
        </button>
      </div>
    </div>
  );
}

// Re-export for use in imports (needs React)
import React from 'react';
