import React, { useState } from 'react';
import { api } from '../../api';

interface AvatarProps {
  userId?: string;
  src?: string;
  name?: string;
  size?: number;
  className?: string;
  style?: React.CSSProperties;
}

export const Avatar: React.FC<AvatarProps> = ({
  userId,
  src,
  name = '?',
  size = 40,
  className,
  style,
}) => {
  const [failed, setFailed] = useState(false);
  const initial = (name || '?')[0].toUpperCase();
  const imgSrc = src || (userId ? api.getUserAvatarUrl(userId) : undefined);

  if (!imgSrc || failed) {
    return (
      <div
        className={`avatar-fallback ${className || ''}`}
        style={{
          width: size,
          height: size,
          borderRadius: '50%',
          background: 'var(--accent)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 600,
          color: 'var(--text-on-accent)',
          fontSize: size * 0.4,
          flexShrink: 0,
          ...style,
        }}
      >
        {initial}
      </div>
    );
  }

  return (
    <img
      className={className}
      src={imgSrc}
      alt={initial}
      style={{
        width: size,
        height: size,
        borderRadius: '50%',
        objectFit: 'cover',
        flexShrink: 0,
        ...style,
      }}
      onError={(e) => {
        const img = e.target as HTMLImageElement;
        img.removeAttribute('src');
        setFailed(true);
      }}
    />
  );
};
