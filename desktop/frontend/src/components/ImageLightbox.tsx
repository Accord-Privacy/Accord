import { useEffect, useState, useCallback } from "react";
import "../styles/lightbox.css";

interface ImageLightboxProps {
  src: string;
  alt?: string;
  onClose: () => void;
  /** All image URLs in the channel for gallery navigation */
  allImages?: string[];
  /** Callback to change the current image */
  onNavigate?: (src: string) => void;
}

export function ImageLightbox({ src, alt, onClose, allImages, onNavigate }: ImageLightboxProps) {
  const [visible, setVisible] = useState(false);

  const currentIndex = allImages ? allImages.indexOf(src) : -1;
  const totalImages = allImages?.length ?? 0;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < totalImages - 1;

  useEffect(() => {
    requestAnimationFrame(() => setVisible(true));
  }, []);

  const handleClose = useCallback(() => {
    setVisible(false);
    setTimeout(onClose, 200);
  }, [onClose]);

  const navigatePrev = useCallback(() => {
    if (hasPrev && allImages && onNavigate) {
      onNavigate(allImages[currentIndex - 1]);
    }
  }, [hasPrev, allImages, onNavigate, currentIndex]);

  const navigateNext = useCallback(() => {
    if (hasNext && allImages && onNavigate) {
      onNavigate(allImages[currentIndex + 1]);
    }
  }, [hasNext, allImages, onNavigate, currentIndex]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleClose();
      else if (e.key === "ArrowLeft") navigatePrev();
      else if (e.key === "ArrowRight") navigateNext();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [handleClose, navigatePrev, navigateNext]);

  return (
    <div
      className={`lightbox-overlay${visible ? " lightbox-visible" : ""}`}
      onClick={handleClose}
    >
      {/* Counter */}
      {totalImages > 1 && currentIndex >= 0 && (
        <div className="lightbox-counter" onClick={(e) => e.stopPropagation()}>
          {currentIndex + 1} of {totalImages}
        </div>
      )}

      {/* Prev button */}
      {hasPrev && (
        <button
          className="lightbox-nav lightbox-nav-prev"
          onClick={(e) => { e.stopPropagation(); navigatePrev(); }}
          aria-label="Previous image"
        >
          ‹
        </button>
      )}

      <img src={src} alt={alt || ""} onClick={(e) => e.stopPropagation()} />

      {/* Next button */}
      {hasNext && (
        <button
          className="lightbox-nav lightbox-nav-next"
          onClick={(e) => { e.stopPropagation(); navigateNext(); }}
          aria-label="Next image"
        >
          ›
        </button>
      )}

      <button className="lightbox-close" onClick={handleClose} aria-label="Close lightbox">
        ✕
      </button>
    </div>
  );
}
