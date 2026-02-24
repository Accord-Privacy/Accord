import React, { forwardRef } from 'react';
import clsx from 'clsx';

type InputSize = 'sm' | 'md' | 'lg';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
  inputSize?: InputSize;
  fullWidth?: boolean;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(({
  label,
  error,
  hint,
  inputSize = 'md',
  fullWidth = true,
  className,
  id,
  ...props
}, ref) => {
  const inputId = id || (label ? `input-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      {label && <label htmlFor={inputId} style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)' }}>{label}</label>}
      <input
        ref={ref}
        id={inputId}
        className={clsx(className)}
        style={{
          width: fullWidth ? '100%' : undefined,
          padding: inputSize === 'sm' ? '8px 10px' : '10px 12px',
          fontSize: '14px',
          backgroundColor: 'var(--background-tertiary)',
          border: '1px solid transparent',
          borderRadius: '6px',
          color: 'var(--text-primary)',
          outline: 'none',
          transition: 'border-color 0.15s',
          boxSizing: 'border-box',
        }}
        onFocus={(e) => { e.currentTarget.style.borderColor = 'var(--accent)'; props.onFocus?.(e); }}
        onBlur={(e) => { e.currentTarget.style.borderColor = 'transparent'; props.onBlur?.(e); }}
        {...props}
      />
      {error && <span style={{ fontSize: '12px', color: 'var(--red)' }}>{error}</span>}
      {hint && !error && <span style={{ fontSize: '12px', color: 'var(--text-tertiary-muted)' }}>{hint}</span>}
    </div>
  );
});

Input.displayName = 'Input';

interface TextAreaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  error?: string;
  hint?: string;
  fullWidth?: boolean;
}

export const TextArea = forwardRef<HTMLTextAreaElement, TextAreaProps>(({
  label,
  error,
  hint,
  fullWidth = true,
  className,
  id,
  ...props
}, ref) => {
  const inputId = id || (label ? `textarea-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      {label && <label htmlFor={inputId} style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)' }}>{label}</label>}
      <textarea
        ref={ref}
        id={inputId}
        className={clsx(className)}
        style={{
          width: fullWidth ? '100%' : undefined,
          padding: '10px 12px',
          fontSize: '14px',
          backgroundColor: 'var(--background-tertiary)',
          border: '1px solid transparent',
          borderRadius: '6px',
          color: 'var(--text-primary)',
          outline: 'none',
          resize: 'vertical',
          fontFamily: 'inherit',
          transition: 'border-color 0.15s',
          boxSizing: 'border-box',
        }}
        {...props}
      />
      {error && <span style={{ fontSize: '12px', color: 'var(--red)' }}>{error}</span>}
      {hint && !error && <span style={{ fontSize: '12px', color: 'var(--text-tertiary-muted)' }}>{hint}</span>}
    </div>
  );
});

TextArea.displayName = 'TextArea';
