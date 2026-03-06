import { useEffect, useState, useCallback } from "react";
import "../styles/lightbox.css";

interface ImageLightboxProps {
  src: string;
  alt?: string;
  onClose: () => void;
}

export function ImageLightbox({ src, alt, onClose }: ImageLightboxProps) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    // Trigger fade-in on mount
    requestAnimationFrame(() => setVisible(true));
  }, []);

  const handleClose = useCallback(() => {
    setVisible(false);
    setTimeout(onClose, 200); // match CSS transition duration
  }, [onClose]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [handleClose]);

  return (
    <div
      className={`lightbox-overlay${visible ? " lightbox-visible" : ""}`}
      onClick={handleClose}
    >
      <img src={src} alt={alt || ""} onClick={(e) => e.stopPropagation()} />
      <button className="lightbox-close" onClick={handleClose} aria-label="Close lightbox">
        ✕
      </button>
    </div>
  );
}
