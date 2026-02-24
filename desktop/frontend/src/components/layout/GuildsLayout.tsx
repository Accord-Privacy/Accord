import styles from './GuildsLayout.module.css';
import clsx from 'clsx';

interface GuildsLayoutProps {
  guildList: React.ReactNode;
  userArea: React.ReactNode;
  children: React.ReactNode;
}

export function GuildsLayout({ guildList, userArea, children }: GuildsLayoutProps) {
  return (
    <div className={clsx(styles.guildsLayoutContainer, styles.guildsLayoutReserveSpace)}>
      <div className={styles.guildListScrollerWrapper}>
        <div className={styles.guildListScrollContainer}>
          <div className={styles.guildListContent}>
            {guildList}
          </div>
        </div>
      </div>
      <div className={clsx(styles.contentContainer, styles.contentContainerRounded)}>
        <div className={styles.contentInner}>
          {children}
        </div>
      </div>
      <div className={styles.userAreaWrapper}>
        {userArea}
      </div>
    </div>
  );
}
