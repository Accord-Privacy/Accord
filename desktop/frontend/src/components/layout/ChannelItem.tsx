import styles from './ChannelItem.module.css';
import clsx from 'clsx';

interface ChannelItemProps {
  name: string;
  selected?: boolean;
  unread?: boolean;
  icon?: React.ReactNode;
  onClick?: () => void;
}

export function ChannelItem({ name, selected, unread, icon, onClick }: ChannelItemProps) {
  return (
    <div className={styles.container}>
      {unread && !selected && <div className={styles.unreadIndicator} />}
      <div
        className={clsx(
          styles.channelItem,
          styles.channelItemRegular,
          styles.channelItemHoverable,
          selected && styles.channelItemSelected,
          unread && !selected && styles.channelItemHighlight,
        )}
        onClick={onClick}
        role="button"
        tabIndex={0}
      >
        {icon && <div className={styles.iconContainer}>{icon}</div>}
        <span className={styles.channelName}>{name}</span>
      </div>
    </div>
  );
}
