import React, { useState, useEffect, useCallback } from 'react';

// Types for the updater API
interface UpdateInfo {
  version: string;
  body?: string;
}

type UpdateStatus = 'idle' | 'checking' | 'available' | 'downloading' | 'upToDate' | 'error';

// Detect if running inside Tauri
const isTauri = () => typeof (window as any).__TAURI_INTERNALS__ !== 'undefined';

/**
 * Hook that manages update checking via Tauri's updater plugin.
 */
export function useUpdateChecker() {
  const [status, setStatus] = useState<UpdateStatus>('idle');
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [downloadProgress, setDownloadProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const checkForUpdate = useCallback(async () => {
    if (!isTauri()) {
      setStatus('idle');
      return;
    }

    setStatus('checking');
    setError(null);

    try {
      const { check } = await import('@tauri-apps/plugin-updater');
      const update = await check();

      if (update) {
        setUpdateInfo({ version: update.version, body: update.body || undefined });
        setStatus('available');
      } else {
        setStatus('upToDate');
      }
    } catch (err: unknown) {
      console.warn('Update check failed:', err);
      setError(err instanceof Error ? err.message : 'Failed to check for updates');
      setStatus('error');
    }
  }, []);

  const installUpdate = useCallback(async () => {
    if (!isTauri()) return;

    setStatus('downloading');
    setDownloadProgress(0);

    try {
      const { check } = await import('@tauri-apps/plugin-updater');
      const update = await check();

      if (!update) {
        setStatus('upToDate');
        return;
      }

      let totalBytes = 0;
      let downloadedBytes = 0;

      await update.downloadAndInstall((event) => {
        if (event.event === 'Started' && event.data?.contentLength) {
          totalBytes = event.data.contentLength;
        } else if (event.event === 'Progress' && event.data?.chunkLength) {
          downloadedBytes += event.data.chunkLength;
          if (totalBytes > 0) {
            setDownloadProgress(Math.round((downloadedBytes / totalBytes) * 100));
          }
        } else if (event.event === 'Finished') {
          setDownloadProgress(100);
        }
      });

      // Relaunch after install
      const { relaunch } = await import('@tauri-apps/plugin-process');
      await relaunch();
    } catch (err: unknown) {
      console.error('Update install failed:', err);
      setError(err instanceof Error ? err.message : 'Failed to install update');
      setStatus('error');
    }
  }, []);

  return { status, updateInfo, downloadProgress, error, checkForUpdate, installUpdate };
}

/**
 * Non-blocking notification bar shown at the top of the app when an update is available.
 */
export const UpdateBanner: React.FC = () => {
  const { status, updateInfo, downloadProgress, checkForUpdate, installUpdate } = useUpdateChecker();
  const [dismissed, setDismissed] = useState(false);

  // Check on mount (app launch)
  useEffect(() => {
    if (isTauri()) {
      // Delay slightly so the app loads first
      const timer = setTimeout(checkForUpdate, 3000);
      return () => clearTimeout(timer);
    }
  }, [checkForUpdate]);

  if (dismissed || status === 'idle' || status === 'checking' || status === 'upToDate') {
    return null;
  }

  if (status === 'error') {
    return null; // Don't show errors on auto-check
  }

  if (status === 'available' && updateInfo) {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '12px',
        padding: '8px 16px',
        background: 'var(--accent, #5865f2)',
        color: '#fff',
        fontSize: '14px',
        zIndex: 9999,
        flexShrink: 0,
      }}>
        <span>🎉 Accord {updateInfo.version} is available!</span>
        <button
          onClick={installUpdate}
          style={{
            background: 'rgba(255,255,255,0.2)',
            border: '1px solid rgba(255,255,255,0.4)',
            color: '#fff',
            padding: '4px 12px',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '13px',
          }}
        >
          Update now
        </button>
        <button
          onClick={() => setDismissed(true)}
          style={{
            background: 'none',
            border: 'none',
            color: 'rgba(255,255,255,0.7)',
            cursor: 'pointer',
            fontSize: '18px',
            padding: '0 4px',
          }}
        >
          ×
        </button>
      </div>
    );
  }

  if (status === 'downloading') {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '12px',
        padding: '8px 16px',
        background: 'var(--accent, #5865f2)',
        color: '#fff',
        fontSize: '14px',
        zIndex: 9999,
        flexShrink: 0,
      }}>
        <span>⬇️ Downloading update... {downloadProgress}%</span>
        <div style={{
          width: '120px',
          height: '6px',
          background: 'rgba(255,255,255,0.2)',
          borderRadius: '3px',
          overflow: 'hidden',
        }}>
          <div style={{
            width: `${downloadProgress}%`,
            height: '100%',
            background: '#fff',
            borderRadius: '3px',
            transition: 'width 0.3s ease',
          }} />
        </div>
      </div>
    );
  }

  return null;
};

/**
 * Settings panel section for update checking (used in About tab).
 */
export const UpdateSection: React.FC = () => {
  const { status, updateInfo, downloadProgress, error, checkForUpdate, installUpdate } = useUpdateChecker();

  if (!isTauri()) {
    return (
      <div className="settings-group">
        <label className="settings-label">Updates</label>
        <div className="settings-help">
          Auto-updates are only available in the desktop app.
        </div>
      </div>
    );
  }

  return (
    <div className="settings-group">
      <label className="settings-label">Updates</label>

      {status === 'idle' && (
        <button className="test-button" onClick={checkForUpdate}>
          🔄 Check for updates
        </button>
      )}

      {status === 'checking' && (
        <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
          Checking for updates...
        </div>
      )}

      {status === 'upToDate' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ color: 'var(--green, #4caf50)', fontSize: '14px' }}>
            ✅ You're on the latest version
          </span>
          <button className="test-button" onClick={checkForUpdate} style={{ fontSize: '12px' }}>
            Check again
          </button>
        </div>
      )}

      {status === 'available' && updateInfo && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ color: 'var(--text-primary)', fontSize: '14px' }}>
            🎉 Version <strong>{updateInfo.version}</strong> is available
          </div>
          {updateInfo.body && (
            <div style={{ color: 'var(--text-secondary)', fontSize: '13px', maxHeight: '80px', overflow: 'auto' }}>
              {updateInfo.body}
            </div>
          )}
          <button className="btn btn-primary" style={{ width: 'auto', padding: '8px 16px' }} onClick={installUpdate}>
            ⬇️ Update now
          </button>
        </div>
      )}

      {status === 'downloading' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ color: 'var(--text-primary)', fontSize: '14px' }}>
            ⬇️ Downloading update... {downloadProgress}%
          </div>
          <div style={{
            width: '100%',
            height: '8px',
            background: 'var(--bg-tertiary)',
            borderRadius: '4px',
            overflow: 'hidden',
          }}>
            <div style={{
              width: `${downloadProgress}%`,
              height: '100%',
              background: 'var(--accent, #5865f2)',
              borderRadius: '4px',
              transition: 'width 0.3s ease',
            }} />
          </div>
        </div>
      )}

      {status === 'error' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ color: 'var(--red, #f44)', fontSize: '14px' }}>
            ❌ {error || 'Update check failed'}
          </div>
          <button className="test-button" onClick={checkForUpdate}>
            Try again
          </button>
        </div>
      )}
    </div>
  );
};
