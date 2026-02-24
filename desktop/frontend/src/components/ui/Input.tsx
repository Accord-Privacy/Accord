import React, { forwardRef } from 'react';

type InputSize = 'sm' | 'md' | 'lg';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
  inputSize?: InputSize;
  fullWidth?: boolean;
}

const sizeClass: Record<InputSize, string> = {
  sm: 'form-input-sm',
  md: '',
  lg: 'form-input-lg',
};

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
  const classes = [
    'form-input',
    sizeClass[inputSize],
    error ? 'form-input-error' : '',
    fullWidth ? 'form-input-full' : '',
    className,
  ].filter(Boolean).join(' ');

  return (
    <div className="form-group">
      {label && <label htmlFor={inputId} className="form-label">{label}</label>}
      <input ref={ref} id={inputId} className={classes} {...props} />
      {error && <span className="form-error">{error}</span>}
      {hint && !error && <span className="form-hint">{hint}</span>}
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
  const classes = [
    'form-input',
    'form-textarea',
    error ? 'form-input-error' : '',
    fullWidth ? 'form-input-full' : '',
    className,
  ].filter(Boolean).join(' ');

  return (
    <div className="form-group">
      {label && <label htmlFor={inputId} className="form-label">{label}</label>}
      <textarea ref={ref} id={inputId} className={classes} {...props} />
      {error && <span className="form-error">{error}</span>}
      {hint && !error && <span className="form-hint">{hint}</span>}
    </div>
  );
});

TextArea.displayName = 'TextArea';
