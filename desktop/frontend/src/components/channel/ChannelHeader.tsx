import styles from './ChannelHeader.module.css';

interface ChannelHeaderProps {
  name: string;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
}

export function ChannelHeader({ name, icon, actions }: ChannelHeaderProps) {
  return (
    <div className={styles.headerWrapper}>
      <div className={styles.headerContainer}>
        <div className={styles.headerLeftSection}>
          {icon && <span className={styles.channelIcon}>{icon}</span>}
          <span className={styles.channelName}>{name}</span>
        </div>
        {actions && <div className={styles.headerRightSection}>{actions}</div>}
      </div>
    </div>
  );
}
