import React, { useState, useEffect, useRef } from 'react';

// URL detection regex - global to find ALL urls
const URL_REGEX = /https?:\/\/[^\s<>"')\]]+/gi;
const IMAGE_URL_REGEX = /\.(png|jpe?g|gif|webp)(\?[^\s]*)?$/i;
const YOUTUBE_REGEX = /(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/)([a-zA-Z0-9_-]{11})/;

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
  const regex = new RegExp(URL_REGEX.source, 'i');
  const match = content.match(regex);
  return match ? match[0] : null;
}

export function extractAllUrls(content: string): string[] {
  const matches = content.match(URL_REGEX);
  if (!matches) return [];
  // Deduplicate
  return [...new Set(matches)];
}

function getYouTubeId(url: string): string | null {
  const match = url.match(YOUTUBE_REGEX);
  return match ? match[1] : null;
}

function isImageUrl(url: string): boolean {
  try {
    const pathname = new URL(url).pathname;
    return IMAGE_URL_REGEX.test(pathname);
  } catch {
    return IMAGE_URL_REGEX.test(url);
  }
}

/** Inline image embed for direct image URLs */
const ImageEmbed: React.FC<{ url: string; onDismiss: () => void }> = ({ url, onDismiss }) => (
  <div className="link-preview link-preview-image-embed">
    <button className="link-preview-dismiss" onClick={onDismiss} title="Hide preview">×</button>
    <a href={url} target="_blank" rel="noopener noreferrer">
      <img
        src={url}
        alt=""
        className="link-preview-inline-image"
        loading="lazy"
        onError={(e) => { (e.target as HTMLImageElement).closest('.link-preview-image-embed')!.remove(); }}
      />
    </a>
  </div>
);

/** YouTube embed with thumbnail and play button */
const YouTubeEmbed: React.FC<{ url: string; videoId: string; onDismiss: () => void }> = ({ url, videoId, onDismiss }) => (
  <div className="link-preview link-preview-youtube">
    <button className="link-preview-dismiss" onClick={onDismiss} title="Hide preview">×</button>
    <a href={url} target="_blank" rel="noopener noreferrer" className="link-preview-youtube-link">
      <div className="link-preview-youtube-thumb-wrapper">
        <img
          src={`https://img.youtube.com/vi/${videoId}/mqdefault.jpg`}
          alt=""
          className="link-preview-youtube-thumb"
          loading="lazy"
        />
        <div className="link-preview-youtube-play">▶</div>
      </div>
    </a>
  </div>
);

/** Standard OG link preview card */
const OGPreviewCard: React.FC<{ preview: LinkPreviewData; onDismiss: () => void }> = ({ preview, onDismiss }) => {
  const truncatedDesc = preview.description && preview.description.length > 200
    ? preview.description.slice(0, 200) + '…'
    : preview.description;

  return (
    <div className="link-preview">
      <button className="link-preview-dismiss" onClick={onDismiss} title="Hide preview">×</button>
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

/** Single URL preview - fetches OG data if needed */
const SingleUrlPreview: React.FC<{ url: string; token: string; dismissed: boolean; onDismiss: () => void }> = ({ url, token, dismissed, onDismiss }) => {
  const [preview, setPreview] = useState<LinkPreviewData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const youtubeId = getYouTubeId(url);
  const isImage = isImageUrl(url);

  useEffect(() => {
    // Don't fetch OG data for images or YouTube - we handle those specially
    if (isImage || youtubeId) return;

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
  }, [url, token, isImage, youtubeId]);

  if (dismissed) return null;

  // Image URL - inline embed
  if (isImage) {
    return <ImageEmbed url={url} onDismiss={onDismiss} />;
  }

  // YouTube - special embed
  if (youtubeId) {
    return <YouTubeEmbed url={url} videoId={youtubeId} onDismiss={onDismiss} />;
  }

  // Standard OG preview
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

  return <OGPreviewCard preview={preview} onDismiss={onDismiss} />;
};

export const LinkPreview: React.FC<LinkPreviewProps> = ({ content, token }) => {
  const urls = extractAllUrls(content);
  const [dismissedUrls, setDismissedUrls] = useState<Set<string>>(new Set());

  if (urls.length === 0) return null;

  const handleDismiss = (url: string) => {
    setDismissedUrls(prev => new Set(prev).add(url));
  };

  return (
    <>
      {urls.map(url => (
        <SingleUrlPreview
          key={url}
          url={url}
          token={token}
          dismissed={dismissedUrls.has(url)}
          onDismiss={() => handleDismiss(url)}
        />
      ))}
    </>
  );
};
