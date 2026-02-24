import React from 'react';
import clsx from 'clsx';

interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: string;
  description?: string;
  disabled?: boolean;
  className?: string;
}

export const Toggle: React.FC<ToggleProps> = ({
  checked,
  onChange,
  label,
  description,
  disabled = false,
  className,
}) => {
  return (
    <label className={clsx('toggle-row', disabled && 'toggle-disabled', className)}
      style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', cursor: disabled ? 'not-allowed' : 'pointer' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        {label && <span style={{ display: 'block', fontWeight: 500, color: 'var(--text-primary)', fontSize: '14px' }}>{label}</span>}
        {description && <span style={{ display: 'block', fontSize: '13px', color: 'var(--text-tertiary-muted)', marginTop: '2px' }}>{description}</span>}
      </div>
      <div
        role="switch"
        aria-checked={checked}
        tabIndex={disabled ? -1 : 0}
        onClick={() => !disabled && onChange(!checked)}
        onKeyDown={(e) => {
          if (!disabled && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            onChange(!checked);
          }
        }}
        style={{
          width: '40px', height: '24px', borderRadius: '12px', position: 'relative',
          backgroundColor: checked ? 'var(--accent)' : 'var(--background-tertiary)',
          transition: 'background-color 0.15s ease', cursor: disabled ? 'not-allowed' : 'pointer',
          flexShrink: 0, marginLeft: '12px',
        }}
      >
        <div style={{
          width: '18px', height: '18px', borderRadius: '50%',
          backgroundColor: '#ffffff',
          position: 'absolute', top: '3px',
          left: checked ? '19px' : '3px',
          transition: 'left 0.15s ease',
        }} />
      </div>
    </label>
  );
};
