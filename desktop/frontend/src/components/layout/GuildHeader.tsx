import styles from './GuildHeader.module.css';
import { useAppContext } from '../AppContext';

interface GuildHeaderProps {
  name?: string;
  onClick?: () => void;
}

export function GuildHeader({ name, onClick }: GuildHeaderProps) {
  const ctx = useAppContext();
  const serverName = name || ctx.servers[ctx.activeServer] || '';

  return (
    <div className={styles.headerWrapper}>
      <div className={styles.headerContainer}>
        <div className={styles.headerContent} onClick={onClick || (() => ctx.selectedNodeId && ctx.setShowNodeSettings(true))} role="button" tabIndex={0}>
          <span className={styles.guildNameDefault}>{serverName}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          {ctx.selectedNodeId && ctx.hasPermission(ctx.selectedNodeId, 'ManageInvites') && (
            <button onClick={ctx.handleGenerateInvite} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-tertiary-muted)', fontSize: '12px', padding: '2px 6px',
            }} title="Generate Invite">Invite</button>
          )}
        </div>
      </div>
    </div>
  );
}
