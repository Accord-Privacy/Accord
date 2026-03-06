import React, { useMemo } from 'react';

// Patterns for media URL detection
const GIF_REGEX = /https?:\/\/[^\s<>"')\]]+\.gif(?:\?[^\s<>"')\]]*)?/gi;
const VIDEO_REGEX = /https?:\/\/[^\s<>"')\]]+\.(?:mp4|webm)(?:\?[^\s<>"')\]]*)?/gi;
const YOUTUBE_REGEX = /https?:\/\/(?:www\.)?(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})(?:[^\s<>"')\]]*)?/gi;

interface MediaEmbedsProps {
  content: string;
  onImageClick: (src: string) => void;
}

function extractYouTubeId(url: string): string | null {
  const m = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
  return m ? m[1] : null;
}

export const MediaEmbeds: React.FC<MediaEmbedsProps> = ({ content, onImageClick }) => {
  const embeds = useMemo(() => {
    const gifs: string[] = [];
    const videos: string[] = [];
    const youtubeIds: { id: string; url: string }[] = [];
    const seen = new Set<string>();

    // YouTube first (so we don't also match them as generic URLs)
    let m: RegExpExecArray | null;
    const ytRegex = new RegExp(YOUTUBE_REGEX.source, YOUTUBE_REGEX.flags);
    while ((m = ytRegex.exec(content)) !== null) {
      const id = extractYouTubeId(m[0]);
      if (id && !seen.has(id)) {
        seen.add(id);
        youtubeIds.push({ id, url: m[0] });
      }
    }

    const gifRegex = new RegExp(GIF_REGEX.source, GIF_REGEX.flags);
    while ((m = gifRegex.exec(content)) !== null) {
      if (!seen.has(m[0])) {
        seen.add(m[0]);
        gifs.push(m[0]);
      }
    }

    const vidRegex = new RegExp(VIDEO_REGEX.source, VIDEO_REGEX.flags);
    while ((m = vidRegex.exec(content)) !== null) {
      if (!seen.has(m[0])) {
        seen.add(m[0]);
        videos.push(m[0]);
      }
    }

    return { gifs, videos, youtubeIds };
  }, [content]);

  if (embeds.gifs.length === 0 && embeds.videos.length === 0 && embeds.youtubeIds.length === 0) {
    return null;
  }

  return (
    <div className="media-embeds">
      {embeds.gifs.map((url) => (
        <img
          key={url}
          src={url}
          alt="GIF"
          className="media-embed-gif"
          loading="lazy"
          onClick={() => onImageClick(url)}
        />
      ))}
      {embeds.videos.map((url) => (
        <video
          key={url}
          src={url}
          className="media-embed-video"
          controls
          muted
          preload="metadata"
        />
      ))}
      {embeds.youtubeIds.map(({ id, url }) => (
        <a
          key={id}
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="media-embed-youtube"
        >
          <img
            src={`https://img.youtube.com/vi/${id}/hqdefault.jpg`}
            alt="YouTube video"
            className="media-embed-youtube-thumb"
            loading="lazy"
          />
          <div className="media-embed-youtube-play">▶</div>
        </a>
      ))}
    </div>
  );
};
