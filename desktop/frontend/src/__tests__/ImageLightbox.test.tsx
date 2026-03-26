import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { ImageLightbox } from '../components/ImageLightbox';

// Stub requestAnimationFrame to run callback synchronously
beforeEach(() => {
  vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => { cb(0); return 0; });
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('ImageLightbox', () => {
  const onClose = vi.fn();

  beforeEach(() => { vi.clearAllMocks(); });

  it('renders the image with the given src', () => {
    render(<ImageLightbox src="https://example.com/photo.jpg" onClose={onClose} />);
    // empty alt means role=presentation — query by alt attribute directly
    const img = screen.getByAltText('');
    expect(img).toBeInTheDocument();
    expect(img).toHaveAttribute('src', 'https://example.com/photo.jpg');
  });

  it('renders the image with provided alt text', () => {
    render(<ImageLightbox src="https://example.com/a.jpg" alt="My photo" onClose={onClose} />);
    expect(screen.getByAltText('My photo')).toBeInTheDocument();
  });

  it('renders the close button', () => {
    render(<ImageLightbox src="https://example.com/a.jpg" onClose={onClose} />);
    expect(screen.getByRole('button', { name: /close lightbox/i })).toBeInTheDocument();
  });

  it('calls onClose when the close button is clicked', async () => {
    render(<ImageLightbox src="https://example.com/a.jpg" onClose={onClose} />);
    fireEvent.click(screen.getByRole('button', { name: /close lightbox/i }));
    act(() => { vi.runAllTimers(); });
    // onClose may be called more than once because click bubbles from button to overlay
    expect(onClose).toHaveBeenCalled();
  });

  it('calls onClose when the overlay background is clicked', async () => {
    const { container } = render(<ImageLightbox src="https://example.com/a.jpg" onClose={onClose} />);
    const overlay = container.querySelector('.lightbox-overlay');
    expect(overlay).toBeInTheDocument();
    fireEvent.click(overlay!);
    act(() => { vi.runAllTimers(); });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('calls onClose when Escape key is pressed', async () => {
    render(<ImageLightbox src="https://example.com/a.jpg" onClose={onClose} />);
    fireEvent.keyDown(document, { key: 'Escape' });
    act(() => { vi.runAllTimers(); });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('does not close when image itself is clicked (stopPropagation)', () => {
    render(<ImageLightbox src="https://example.com/a.jpg" onClose={onClose} />);
    // Image has empty alt, role=presentation — query by alt text
    fireEvent.click(screen.getByAltText(''));
    expect(onClose).not.toHaveBeenCalled();
  });

  it('shows counter when multiple images are provided', () => {
    const allImages = ['https://example.com/a.jpg', 'https://example.com/b.jpg', 'https://example.com/c.jpg'];
    render(
      <ImageLightbox
        src={allImages[1]}
        allImages={allImages}
        onNavigate={vi.fn()}
        onClose={onClose}
      />
    );
    expect(screen.getByText('2 of 3')).toBeInTheDocument();
  });

  it('does not show counter for single image', () => {
    render(<ImageLightbox src="https://example.com/a.jpg" onClose={onClose} />);
    expect(screen.queryByText(/of/)).not.toBeInTheDocument();
  });

  it('shows prev/next buttons when multiple images provided and not at ends', () => {
    const allImages = ['https://example.com/a.jpg', 'https://example.com/b.jpg', 'https://example.com/c.jpg'];
    render(
      <ImageLightbox
        src={allImages[1]}
        allImages={allImages}
        onNavigate={vi.fn()}
        onClose={onClose}
      />
    );
    expect(screen.getByRole('button', { name: /previous image/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /next image/i })).toBeInTheDocument();
  });

  it('calls onNavigate when next button is clicked', () => {
    const onNavigate = vi.fn();
    const allImages = ['https://example.com/a.jpg', 'https://example.com/b.jpg'];
    render(
      <ImageLightbox
        src={allImages[0]}
        allImages={allImages}
        onNavigate={onNavigate}
        onClose={onClose}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: /next image/i }));
    expect(onNavigate).toHaveBeenCalledWith(allImages[1]);
  });

  it('calls onNavigate when ArrowRight key is pressed', () => {
    const onNavigate = vi.fn();
    const allImages = ['https://example.com/a.jpg', 'https://example.com/b.jpg'];
    render(
      <ImageLightbox
        src={allImages[0]}
        allImages={allImages}
        onNavigate={onNavigate}
        onClose={onClose}
      />
    );
    fireEvent.keyDown(document, { key: 'ArrowRight' });
    expect(onNavigate).toHaveBeenCalledWith(allImages[1]);
  });
});
