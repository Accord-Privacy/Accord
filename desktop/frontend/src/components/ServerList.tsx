import React, { useState, useCallback, useEffect, useRef } from "react";
import { useAppContext } from "./AppContext";
import { api } from "../api";
import { notificationManager } from "../notifications";

interface ServerContextMenuState {
  open: boolean;
  x: number;
  y: number;
  nodeId: string;
}

export const ServerList: React.FC = () => {
  const ctx = useAppContext();
  const [serverMenu, setServerMenu] = useState<ServerContextMenuState | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const closeMenu = useCallback(() => setServerMenu(null), []);

  useEffect(() => {
    if (!serverMenu?.open) return;
    const handleClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) closeMenu();
    };
    const handleEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') closeMenu(); };
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleEsc);
    return () => { document.removeEventListener('mousedown', handleClick); document.removeEventListener('keydown', handleEsc); };
  }, [serverMenu?.open, closeMenu]);

  const handleMarkAllAsRead = useCallback((nodeId: string) => {
    notificationManager.markAllNodeChannelsAsRead(nodeId);
    ctx.setForceUpdate((p: number) => p + 1);
    closeMenu();
  }, [closeMenu, ctx]);

  return (
    <div className="server-list" role="navigation" aria-label="Servers" key={ctx.forceUpdate}>
      <div className="server-icon accord-home active" title="Home" role="button" aria-label="Home" tabIndex={0}>
        <img src="/logo.png?v=2" alt="A" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
      </div>
      <div className="server-list-separator" />
      {ctx.nodes.length > 0 && ctx.servers.map((s, i) => {
        const nodeId = ctx.nodes.length > 0 ? ctx.nodes[i]?.id : null;
        const nodeUnreads = nodeId ? notificationManager.getNodeUnreads(nodeId) : { totalUnreads: 0, totalMentions: 0 };
        
        return (
          <div
            key={nodeId || s}
            className={`server-icon ${i === ctx.activeServer ? "active" : ""}${nodeUnreads.totalUnreads > 0 && i !== ctx.activeServer ? " has-unread" : ""}`}
            role="button"
            tabIndex={0}
            aria-label={s}
            aria-current={i === ctx.activeServer ? 'true' : undefined}
            onClick={() => {
              if (nodeId) {
                ctx.handleNodeSelect(nodeId, i);
              }
            }}
            onContextMenu={(e) => {
              if (nodeId) {
                e.preventDefault();
                setServerMenu({ open: true, x: e.clientX, y: e.clientY, nodeId });
              }
            }}
            onKeyDown={(e) => { if ((e.key === 'Enter' || e.key === ' ') && nodeId) { e.preventDefault(); ctx.handleNodeSelect(nodeId, i); } }}
            title={s}
          >
            {ctx.nodes[i]?.icon_hash ? (
              <img 
                src={`${api.getNodeIconUrl(ctx.nodes[i].id)}?v=${ctx.nodes[i].icon_hash}`}
                alt={s[0]}
                onError={(e) => { const img = e.target as HTMLImageElement; img.style.display = 'none'; img.removeAttribute('src'); if (img.parentElement) img.parentElement.textContent = s[0]; }}
              />
            ) : s[0]}
            {nodeUnreads.totalMentions > 0 && (
              <div className="server-notification mention">
                {nodeUnreads.totalMentions > 9 ? '9+' : nodeUnreads.totalMentions}
              </div>
            )}
            {nodeUnreads.totalMentions === 0 && nodeUnreads.totalUnreads > 0 && (
              <div className="server-notification dot" />
            )}
          </div>
        );
      })}
      <div 
        className="server-icon add-server" 
        title="Join or Create Node"
        aria-label="Join or Create Node"
        role="button"
        tabIndex={0}
        onClick={() => ctx.setShowJoinNodeModal(true)}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); ctx.setShowJoinNodeModal(true); } }}
      >
        +
      </div>

      {serverMenu?.open && (
        <>
          <div className="context-menu-backdrop" onClick={closeMenu} />
          <div
            ref={menuRef}
            className="context-menu"
            style={{ left: serverMenu.x, top: serverMenu.y }}
          >
            <div
              className="context-menu-item"
              onClick={() => handleMarkAllAsRead(serverMenu.nodeId)}
            >
              <span className="context-menu-icon">✓</span>
              <span>Mark All as Read</span>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
