import React, { useEffect, useRef, useState, useCallback } from 'react';
import clsx from 'clsx';
import styles from '../uikit/context_menu/ContextMenu.module.css';

export interface ContextMenuItem {
  label: string;
  icon?: string;
  danger?: boolean;
  disabled?: boolean;
  separator?: boolean;
  onClick?: () => void;
}

interface ContextMenuProps {
  items: ContextMenuItem[];
  children: React.ReactNode;
}

interface MenuState {
  open: boolean;
  x: number;
  y: number;
}

export const ContextMenu: React.FC<ContextMenuProps> = ({ items, children }) => {
  const [menu, setMenu] = useState<MenuState>({ open: false, x: 0, y: 0 });
  const menuRef = useRef<HTMLDivElement>(null);

  const handleContext = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const x = Math.min(e.clientX, window.innerWidth - 200);
    const y = Math.min(e.clientY, window.innerHeight - items.length * 36 - 16);
    setMenu({ open: true, x, y });
  }, [items.length]);

  const close = useCallback(() => setMenu(prev => ({ ...prev, open: false })), []);

  useEffect(() => {
    if (!menu.open) return;
    const handleClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) close();
    };
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleEsc);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleEsc);
    };
  }, [menu.open, close]);

  return (
    <>
      <div onContextMenu={handleContext}>{children}</div>
      {menu.open && (
        <div className={styles.contextMenuOverlay} style={{ pointerEvents: 'auto' }}>
          <div className={styles.backdrop} onClick={close} />
          <div
            ref={menuRef}
            className={styles.contextMenu}
            style={{ position: 'fixed', left: menu.x, top: menu.y, zIndex: 'var(--z-index-contextmenu, 10000)' as any }}
          >
            {items.map((item, i) => {
              if (item.separator) {
                return <div key={i} className={styles.separator} />;
              }
              return (
                <div
                  key={i}
                  className={clsx(
                    styles.item,
                    item.danger && styles.danger,
                    item.disabled && styles.disabled,
                  )}
                  onClick={() => {
                    if (item.disabled) return;
                    item.onClick?.();
                    close();
                  }}
                >
                  <span className={styles.itemLabel}>{item.label}</span>
                  {item.icon && (
                    <span className={styles.itemIcon}>{item.icon}</span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </>
  );
};
