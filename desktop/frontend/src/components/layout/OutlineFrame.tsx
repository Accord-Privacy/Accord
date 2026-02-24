import styles from './OutlineFrame.module.css';
import clsx from 'clsx';

interface OutlineFrameProps {
  sidebarDivider?: boolean;
  hideTopBorder?: boolean;
  children: React.ReactNode;
  className?: string;
}

export function OutlineFrame({ sidebarDivider, hideTopBorder, children, className }: OutlineFrameProps) {
  return (
    <div
      className={clsx(
        styles.frame,
        !hideTopBorder && styles.frameShowTop,
        hideTopBorder && styles.frameHideTop,
        className,
      )}
    >
      <div className={styles.contentWrapper}>
        {sidebarDivider && <div className={styles.divider} aria-hidden />}
        <div className={styles.body}>{children}</div>
      </div>
    </div>
  );
}
