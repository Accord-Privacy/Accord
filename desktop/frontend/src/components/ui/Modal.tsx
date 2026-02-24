import React, { useEffect, useRef } from 'react';
import clsx from 'clsx';
import styles from '../modals/Modal.module.css';

type ModalSize = 'small' | 'medium' | 'large';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  description?: string;
  size?: ModalSize;
  /** @deprecated use size instead */
  maxWidth?: number;
  children: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}

export const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  description,
  size = 'small',
  maxWidth,
  children,
  actions,
  className,
}) => {
  const overlayRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen) return;
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      ref={overlayRef}
      className={styles.layer}
      style={{ pointerEvents: 'auto', zIndex: 1000 }}
      onClick={(e) => {
        if (e.target === overlayRef.current) onClose();
      }}
    >
      <div className={styles.backdropCentered} style={{ position: 'absolute', inset: 0 }} onClick={onClose} />
      <div className={clsx(styles.root, styles[size], className)} style={maxWidth ? { width: maxWidth, maxWidth } : undefined} onClick={(e) => e.stopPropagation()}>
        {title && (
          <div className={clsx(styles.layout, styles.header)}>
            <div className={styles.headerInner}>
              <div className={styles.headerText}>
                <h3>{title}</h3>
              </div>
              <button onClick={onClose} aria-label="Close">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M18.4 4L12 10.4L5.6 4L4 5.6L10.4 12L4 18.4L5.6 20L12 13.6L18.4 20L20 18.4L13.6 12L20 5.6L18.4 4Z" />
                </svg>
              </button>
            </div>
            {description && <p className={styles.description}>{description}</p>}
          </div>
        )}
        <div className={styles.content}>
          {children}
        </div>
        {actions && (
          <div className={clsx(styles.layout, styles.footer)}>
            {actions}
          </div>
        )}
      </div>
    </div>
  );
};
