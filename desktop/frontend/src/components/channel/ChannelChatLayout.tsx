import styles from './ChannelChatLayout.module.css';

interface ChannelChatLayoutProps {
  header: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
}

export function ChannelChatLayout({ header, children, footer }: ChannelChatLayoutProps) {
  return (
    <div className={styles.container}>
      {header}
      <div className={styles.messagesArea}>
        {children}
      </div>
      {footer && <div className={styles.textareaArea}>{footer}</div>}
    </div>
  );
}
