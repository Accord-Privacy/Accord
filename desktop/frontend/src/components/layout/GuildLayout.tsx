import styles from './GuildLayout.module.css';

interface GuildLayoutProps {
  navbar: React.ReactNode;
  children: React.ReactNode;
}

export function GuildLayout({ navbar, children }: GuildLayoutProps) {
  return (
    <div className={styles.guildLayoutContainer}>
      <div className={styles.guildLayoutContent}>
        {navbar}
        <div className={styles.guildMainContent}>
          {children}
        </div>
      </div>
    </div>
  );
}
