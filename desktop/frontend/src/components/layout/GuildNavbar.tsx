import styles from './GuildNavbar.module.css';

interface GuildNavbarProps {
  header: React.ReactNode;
  children: React.ReactNode;
}

export function GuildNavbar({ header, children }: GuildNavbarProps) {
  return (
    <div className={styles.guildNavbarContainer}>
      {header}
      {children}
    </div>
  );
}
