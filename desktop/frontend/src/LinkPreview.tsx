import React, { useState, useEffect, useRef } from 'react';

// URL detection regex
const URL_REGEX = /https?:\/\/[^\s<>"')\]]+/i;

// In-memory cache
const previewCache = new Map<string, LinkPreviewData | null>();

interface LinkPreviewData {
  title: string | null;
  description: string | null;
  image: string | null;
  siteName: string | null;
  url: string;
}

interface LinkPreviewProps {
  content: string;
  token: string;
}

export function extractFirstUrl(content: string): string | null {
  const match = content.match(URL_REGEX);
  return match ? match[0] : null;
}

export const LinkPreview: React.FC<LinkPreviewProps> = ({ content, token }) => {
  const [preview, setPreview] = useState<LinkPreviewData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const url = extractFirstUrl(content);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!url) return;

    // Check cache
    if (previewCache.has(url)) {
      setPreview(previewCache.get(url) || null);
      return;
    }

    setLoading(true);
    setError(false);

    const controller = new AbortController();
    abortRef.current = controller;

    const baseUrl = (window as any).__ACCORD_SERVER_URL__ || localStorage.getItem('accord_server_url') || import.meta.env.VITE_ACCORD_SERVER_URL || 'http://localhost:8080';

    fetch(`${baseUrl}/api/link-preview?token=${encodeURIComponent(token)}&url=${encodeURIComponent(url)}`, {
      signal: controller.signal,
    })
      .then(res => {
        if (!res.ok) throw new Error('fetch failed');
        return res.json();
      })
      .then((data: LinkPreviewData) => {
        if (!data.title && !data.description && !data.image) {
          previewCache.set(url, null);
          setPreview(null);
        } else {
          previewCache.set(url, data);
          setPreview(data);
        }
        setLoading(false);
      })
      .catch(err => {
        if (err.name !== 'AbortError') {
          previewCache.set(url, null);
          setError(true);
          setLoading(false);
        }
      });

    return () => {
      controller.abort();
    };
  }, [url, token]);

  if (!url) return null;
  if (error || (!loading && !preview)) return null;

  if (loading) {
    return (
      <div className="link-preview link-preview-loading">
        <div className="link-preview-skeleton-title" />
        <div className="link-preview-skeleton-desc" />
      </div>
    );
  }

  if (!preview) return null;

  const truncatedDesc = preview.description && preview.description.length > 200
    ? preview.description.slice(0, 200) + '…'
    : preview.description;

  return (
    <div className="link-preview">
      <div className="link-preview-content">
        {preview.siteName && (
          <div className="link-preview-site">{preview.siteName}</div>
        )}
        {preview.title && (
          <a href={preview.url} target="_blank" rel="noopener noreferrer" className="link-preview-title">
            {preview.title}
          </a>
        )}
        {truncatedDesc && (
          <div className="link-preview-desc">{truncatedDesc}</div>
        )}
      </div>
      {preview.image && (
        <img
          className="link-preview-image"
          src={preview.image}
          alt=""
          loading="lazy"
          onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }}
        />
      )}
    </div>
  );
};
