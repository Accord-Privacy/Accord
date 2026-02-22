import React from "react";
import { useAppContext } from "./AppContext";
import { api } from "../api";
import { notificationManager } from "../notifications";

export const ServerList: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className="server-list" key={ctx.forceUpdate}>
      <div className="server-icon accord-home" title="Accord" style={{ marginBottom: '8px', borderBottom: '2px solid var(--border-color, #333)', paddingBottom: '8px', background: '#000', overflow: 'hidden' }}>
        <img src="/logo.png" alt="Accord" style={{ width: '100%', height: '100%', objectFit: 'cover' }} onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
      </div>
      {ctx.nodes.length > 0 && ctx.servers.map((s, i) => {
        const nodeId = ctx.nodes.length > 0 ? ctx.nodes[i]?.id : null;
        const nodeUnreads = nodeId ? notificationManager.getNodeUnreads(nodeId) : { totalUnreads: 0, totalMentions: 0 };
        
        return (
          <div
            key={nodeId || s}
            className={`server-icon ${i === ctx.activeServer ? "active" : ""}`}
            onClick={() => {
              if (nodeId) {
                ctx.handleNodeSelect(nodeId, i);
              }
            }}
            title={s}
          >
            {ctx.nodes[i]?.icon_hash ? (
              <img 
                src={`${api.getNodeIconUrl(ctx.nodes[i].id)}?v=${ctx.nodes[i].icon_hash}`}
                alt={s[0]}
                style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: 'inherit' }}
                onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; (e.target as HTMLImageElement).parentElement!.textContent = s[0]; }}
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
        onClick={() => ctx.setShowCreateNodeModal(true)}
        style={{ cursor: 'pointer' }}
      >
        +
      </div>
    </div>
  );
};
