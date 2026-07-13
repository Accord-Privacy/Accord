import { useEffect, useState } from 'react';

/**
 * Custom frameless title bar. The window runs with `decorations: false`, so this
 * provides the drag region + min/maximize/close controls, themed to match the
 * app (the native GTK/Win title bar clashed hard with the dark UI). On the web
 * build there's no Tauri window, so it renders nothing and the browser chrome
 * stays.
 */
function tauriWindow(): any {
  return (window as any).__TAURI__?.window?.getCurrentWindow?.();
}

export function TitleBar() {
  const [maximized, setMaximized] = useState(false);
  const available = !!(window as any).__TAURI__?.window?.getCurrentWindow;

  useEffect(() => {
    if (!available) return;
    const w = tauriWindow();
    let unlisten: (() => void) | undefined;
    w?.isMaximized?.().then(setMaximized).catch(() => {});
    w?.onResized?.(() => w.isMaximized().then(setMaximized).catch(() => {}))
      .then((fn: () => void) => { unlisten = fn; })
      .catch(() => {});
    return () => unlisten?.();
  }, [available]);

  if (!available) return null;

  return (
    <div className="titlebar" data-tauri-drag-region>
      <div className="titlebar-brand" data-tauri-drag-region>
        <img src="/logo.png?v=2" alt="" className="titlebar-logo" draggable={false} />
        <span className="titlebar-title">Accord</span>
      </div>
      <div className="titlebar-controls">
        <button
          className="titlebar-btn"
          aria-label="Minimize"
          onClick={() => tauriWindow()?.minimize()}
        >
          <svg width="10" height="10" viewBox="0 0 10 10"><rect x="0" y="4.5" width="10" height="1" fill="currentColor" /></svg>
        </button>
        <button
          className="titlebar-btn"
          aria-label={maximized ? 'Restore' : 'Maximize'}
          onClick={() => tauriWindow()?.toggleMaximize()}
        >
          {maximized ? (
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1">
              <rect x="0.5" y="2.5" width="6" height="6" /><path d="M2.5 2.5V0.5H9.5V7.5H7.5" />
            </svg>
          ) : (
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1">
              <rect x="0.5" y="0.5" width="9" height="9" />
            </svg>
          )}
        </button>
        <button
          className="titlebar-btn titlebar-close"
          aria-label="Close"
          onClick={() => tauriWindow()?.close()}
        >
          <svg width="10" height="10" viewBox="0 0 10 10" stroke="currentColor" strokeWidth="1.1">
            <path d="M0.5 0.5L9.5 9.5M9.5 0.5L0.5 9.5" />
          </svg>
        </button>
      </div>
    </div>
  );
}
