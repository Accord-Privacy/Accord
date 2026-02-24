import React from 'react';
import clsx from 'clsx';
import styles from '../uikit/button/Button.module.css';

type ButtonVariant = 'primary' | 'secondary' | 'danger-primary' | 'danger-secondary' | 'inverted' | 'green' | 'danger' | 'outline' | 'ghost';
type ButtonSize = 'default' | 'small' | 'compact' | 'super-compact';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  fitContent?: boolean;
  fitContainer?: boolean;
  square?: boolean;
}

const variantClass: Record<ButtonVariant, string> = {
  primary: styles.primary,
  secondary: styles.secondary,
  'danger-primary': styles.dangerPrimary,
  'danger-secondary': styles.dangerSecondary,
  inverted: styles.inverted,
  // Legacy aliases
  green: styles.primary,
  danger: styles.dangerPrimary,
  outline: styles.secondary,
  ghost: styles.secondary,
};

const sizeClass: Record<ButtonSize, string> = {
  default: '',
  small: styles.small,
  compact: styles.compact,
  'super-compact': styles.superCompact,
};

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'default',
  loading = false,
  fitContent = false,
  fitContainer = false,
  square = false,
  disabled,
  className,
  children,
  ...props
}) => {
  return (
    <button
      className={clsx(
        styles.button,
        variantClass[variant],
        sizeClass[size],
        fitContent && styles.fitContent,
        fitContainer && styles.fitContainer,
        square && styles.square,
        className,
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <div className={styles.spinner}>
          <div className={styles.spinnerInner}>
            <div className={styles.spinnerItem} />
            <div className={styles.spinnerItem} />
            <div className={styles.spinnerItem} />
          </div>
        </div>
      ) : children}
    </button>
  );
};

// Legacy compat aliases
export const BtnPrimary = (props: Omit<ButtonProps, 'variant'>) => <Button variant="primary" {...props} />;
export const BtnDanger = (props: Omit<ButtonProps, 'variant'>) => <Button variant="danger-primary" {...props} />;
export const BtnSecondary = (props: Omit<ButtonProps, 'variant'>) => <Button variant="secondary" {...props} />;
