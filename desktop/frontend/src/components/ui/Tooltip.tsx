import React, { useState, useRef, useCallback } from 'react';
import clsx from 'clsx';
import styles from '../uikit/tooltip/Tooltip.module.css';

type TooltipPosition = 'top' | 'bottom' | 'left' | 'right';

interface TooltipProps {
  content: string;
  position?: TooltipPosition;
  delay?: number;
  children: React.ReactElement<{ onMouseEnter?: React.MouseEventHandler; onMouseLeave?: React.MouseEventHandler }>;
}

const positionClass: Record<TooltipPosition, string> = {
  top: styles.tooltipTop,
  bottom: styles.tooltipBottom,
  left: styles.tooltipLeft,
  right: styles.tooltipRight,
};

export const Tooltip: React.FC<TooltipProps> = ({
  content,
  position = 'top',
  delay = 400,
  children,
}) => {
  const [visible, setVisible] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  const show = useCallback(() => {
    timerRef.current = setTimeout(() => setVisible(true), delay);
  }, [delay]);

  const hide = useCallback(() => {
    clearTimeout(timerRef.current);
    setVisible(false);
  }, []);

  return (
    <div className={styles.triggerWrapper} onMouseEnter={show} onMouseLeave={hide} style={{ position: 'relative' }}>
      {children}
      {visible && (
        <div className={clsx(styles.tooltip, styles.tooltipPrimary, positionClass[position])} role="tooltip"
          style={{ position: 'absolute', zIndex: 'var(--z-index-tooltip, 9999)' as any }}>
          <div className={styles.tooltipContent}>{content}</div>
          <div className={clsx(styles.tooltipPointer)} />
        </div>
      )}
    </div>
  );
};
