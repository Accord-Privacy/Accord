import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MediaEmbeds } from '../components/MediaEmbeds';

describe('MediaEmbeds', () => {
  const onImageClick = vi.fn();

  beforeEach(() => { vi.clearAllMocks(); });

  it('renders nothing for plain text with no media URLs', () => {
    const { container } = render(
      <MediaEmbeds content="Just some plain text with no URLs" onImageClick={onImageClick} />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders a GIF image for a .gif URL', () => {
    render(
      <MediaEmbeds content="Check this out https://example.com/funny.gif" onImageClick={onImageClick} />
    );
    const img = screen.getByRole('img', { name: 'GIF' });
    expect(img).toBeInTheDocument();
    expect(img).toHaveAttribute('src', 'https://example.com/funny.gif');
  });

  it('calls onImageClick when a GIF is clicked', () => {
    render(
      <MediaEmbeds content="https://example.com/funny.gif" onImageClick={onImageClick} />
    );
    const img = screen.getByRole('img', { name: 'GIF' });
    img.click();
    expect(onImageClick).toHaveBeenCalledWith('https://example.com/funny.gif');
  });

  it('renders a video element for .mp4 URLs', () => {
    const { container } = render(
      <MediaEmbeds content="Watch https://example.com/clip.mp4" onImageClick={onImageClick} />
    );
    const video = container.querySelector('video');
    expect(video).toBeInTheDocument();
    expect(video).toHaveAttribute('src', 'https://example.com/clip.mp4');
  });

  it('renders a video element for .webm URLs', () => {
    const { container } = render(
      <MediaEmbeds content="https://example.com/video.webm" onImageClick={onImageClick} />
    );
    const video = container.querySelector('video');
    expect(video).toBeInTheDocument();
    expect(video).toHaveAttribute('src', 'https://example.com/video.webm');
  });

  it('renders a YouTube embed for youtube.com/watch URLs', () => {
    const url = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
    render(<MediaEmbeds content={`Watch this ${url}`} onImageClick={onImageClick} />);
    const link = screen.getByRole('link');
    expect(link).toHaveAttribute('href', url);
    const thumb = screen.getByAltText('YouTube video');
    expect(thumb).toHaveAttribute('src', 'https://img.youtube.com/vi/dQw4w9WgXcQ/hqdefault.jpg');
  });

  it('renders a YouTube embed for youtu.be short URLs', () => {
    const url = 'https://youtu.be/dQw4w9WgXcQ';
    render(<MediaEmbeds content={url} onImageClick={onImageClick} />);
    const thumb = screen.getByAltText('YouTube video');
    expect(thumb).toHaveAttribute('src', 'https://img.youtube.com/vi/dQw4w9WgXcQ/hqdefault.jpg');
  });

  it('does not render duplicate embeds for the same URL', () => {
    render(
      <MediaEmbeds
        content="https://example.com/a.gif https://example.com/a.gif"
        onImageClick={onImageClick}
      />
    );
    const gifs = screen.getAllByRole('img', { name: 'GIF' });
    expect(gifs).toHaveLength(1);
  });

  it('renders multiple different GIFs in one message', () => {
    render(
      <MediaEmbeds
        content="https://example.com/a.gif and https://example.com/b.gif"
        onImageClick={onImageClick}
      />
    );
    const gifs = screen.getAllByRole('img', { name: 'GIF' });
    expect(gifs).toHaveLength(2);
  });

  it('renders nothing for an invalid / non-media URL', () => {
    const { container } = render(
      <MediaEmbeds content="Visit https://example.com/page" onImageClick={onImageClick} />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders GIF with query string correctly', () => {
    render(
      <MediaEmbeds content="https://media.giphy.com/media/abc.gif?cid=xyz" onImageClick={onImageClick} />
    );
    const img = screen.getByRole('img', { name: 'GIF' });
    expect(img).toHaveAttribute('src', 'https://media.giphy.com/media/abc.gif?cid=xyz');
  });
});
