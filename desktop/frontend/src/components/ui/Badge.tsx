import React from 'react';

type BadgeVariant = 'default' | 'accent' | 'green' | 'red' | 'yellow';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  count?: number;
  dot?: boolean;
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  count,
  dot = false,
  className,
}) => {
  // Count-only badge (no children wrapper)
  if (count !== undefined && !children) {
    return (
      <span className={`badge badge-${variant} ${className || ''}`}>
        {count > 99 ? '99+' : count}
      </span>
    );
  }

  // Dot/count on top of children
  if (dot || count !== undefined) {
    return (
      <div className={`badge-wrapper ${className || ''}`}>
        {children}
        {dot && <span className="badge-dot" />}
        {!dot && count !== undefined && count > 0 && (
          <span className={`badge badge-${variant} badge-overlay`}>
            {count > 99 ? '99+' : count}
          </span>
        )}
      </div>
    );
  }

  // Inline badge
  return (
    <span className={`badge badge-${variant} ${className || ''}`}>
      {children}
    </span>
  );
};
