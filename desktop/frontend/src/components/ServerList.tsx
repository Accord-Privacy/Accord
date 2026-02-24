import React, { useState } from "react";
import { useAppContext } from "./AppContext";
import { api } from "../api";
import { notificationManager } from "../notifications";
import styles from './layout/GuildsLayout.module.css';
import clsx from 'clsx';

export const ServerList: React.FC = () => {
  const ctx = useAppContext();
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [homeHovered, setHomeHovered] = useState(false);
  const [addHovered, setAddHovered] = useState(false);

  return (
    <>
      {/* Top section: Home button */}
      <div className={styles.guildListTopSection}>
        <div
          className={styles.fluxerButton}
          onMouseEnter={() => setHomeHovered(true)}
          onMouseLeave={() => setHomeHovered(false)}
          onClick={() => {
            // Could navigate to DMs/home in future
          }}
          role="button"
          tabIndex={0}
        >
          {(homeHovered) && (
            <div className={styles.guildIndicator}>
              <span className={styles.guildIndicatorBar} style={{ height: homeHovered ? 20 : 8 }} />
            </div>
          )}
          <div className={styles.relative}>
            <div
              className={clsx(styles.fluxerButtonIcon)}
              style={{ borderRadius: homeHovered ? '30%' : '50%' }}
            >
              <img
                src="/logo.png?v=2"
                alt="A"
                style={{ width: '60%', height: '60%', objectFit: 'contain' }}
                onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Divider */}
      <div className={styles.guildDivider} />

      {/* Guild list */}
      <div className={styles.guildListGuildsSection}>
        <div className={styles.guildListItems}>
          {ctx.nodes.length > 0 && ctx.servers.map((s, i) => {
            const nodeId = ctx.nodes[i]?.id ?? null;
            const nodeUnreads = nodeId ? notificationManager.getNodeUnreads(nodeId) : { totalUnreads: 0, totalMentions: 0 };
            const isSelected = i === ctx.activeServer;
            const isHovering = hoveredIndex === i;
            const hasUnread = nodeUnreads.totalUnreads > 0 || nodeUnreads.totalMentions > 0;
            const hasIcon = !!ctx.nodes[i]?.icon_hash;
            const initials = s[0] || '?';

            const indicatorHeight = isSelected ? 40 : isHovering ? 20 : 8;
            const showIndicator = isSelected || isHovering || hasUnread;

            return (
              <div
                key={nodeId || s}
                className={styles.guildListItem}
                onMouseEnter={() => setHoveredIndex(i)}
                onMouseLeave={() => setHoveredIndex(null)}
                onClick={() => {
                  if (nodeId) ctx.handleNodeSelect(nodeId, i);
                }}
                role="button"
                tabIndex={0}
                title={s}
              >
                {showIndicator && (
                  <div className={styles.guildIndicator}>
                    <span
                      className={styles.guildIndicatorBar}
                      style={{ height: indicatorHeight, opacity: 1 }}
                    />
                  </div>
                )}

                <div className={styles.relative}>
                  <div
                    className={clsx(
                      styles.guildIcon,
                      !hasIcon && styles.guildIconNoImage,
                      isSelected && !hasIcon && styles.guildIconSelected,
                      isSelected && hasIcon && styles.guildIconSelected,
                    )}
                    style={{
                      borderRadius: (isSelected || isHovering) ? '30%' : '50%',
                      backgroundImage: hasIcon
                        ? `url(${api.getNodeIconUrl(ctx.nodes[i].id)}?v=${ctx.nodes[i].icon_hash})`
                        : undefined,
                      transition: 'border-radius 70ms ease-out, background-color 70ms ease-out, color 70ms ease-out',
                    }}
                  >
                    {!hasIcon && <span className={styles.guildIconInitials}>{initials}</span>}
                  </div>

                  {/* Mention badge */}
                  {nodeUnreads.totalMentions > 0 && (
                    <div className={clsx(styles.guildBadge, styles.guildBadgeActive)}>
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        minWidth: '16px',
                        height: '16px',
                        borderRadius: '8px',
                        backgroundColor: 'var(--status-danger, #f04747)',
                        color: 'white',
                        fontSize: '11px',
                        fontWeight: 700,
                        padding: '0 4px',
                      }}>
                        {nodeUnreads.totalMentions > 9 ? '9+' : nodeUnreads.totalMentions}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Add server button */}
        <div
          className={styles.addGuildButton}
          onMouseEnter={() => setAddHovered(true)}
          onMouseLeave={() => setAddHovered(false)}
          onClick={() => ctx.setShowCreateNodeModal(true)}
          role="button"
          tabIndex={0}
          title="Join or Create Node"
        >
          <div
            className={styles.addGuildButtonIcon}
            style={{
              borderRadius: addHovered ? '30%' : '50%',
              borderColor: addHovered ? 'var(--text-primary)' : undefined,
            }}
          >
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
              <path d="M10 3v14M3 10h14" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </div>
        </div>
      </div>
    </>
  );
};
