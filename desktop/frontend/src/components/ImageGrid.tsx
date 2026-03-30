import { useEffect, useState } from "react";
import { api } from "../api";
import { getChannelKey, decryptFile } from "../crypto";
import type { FileMetadata } from "../types";

function isImageFilename(filename: string): boolean {
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  return ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'].includes(ext);
}

interface ImageGridProps {
  files: FileMetadata[];
  token: string;
  channelId: string;
  keyPair: CryptoKeyPair | null;
  encryptionEnabled: boolean;
  onImageClick: (src: string) => void;
}

interface LoadedImage {
  fileId: string;
  url: string;
}

export function ImageGrid({ files, token, channelId, keyPair, encryptionEnabled, onImageClick }: ImageGridProps) {
  const imageFiles = files.filter(f => isImageFilename(f.encrypted_filename));
  const [loaded, setLoaded] = useState<LoadedImage[]>([]);

  useEffect(() => {
    let cancelled = false;
    const loadAll = async () => {
      const results: LoadedImage[] = [];
      for (const file of imageFiles) {
        try {
          const buffer = await api.downloadFile(file.id, token);
          let finalBuffer = buffer;
          if (encryptionEnabled && keyPair) {
            try {
              const channelKey = await getChannelKey(keyPair.privateKey, channelId);
              finalBuffer = await decryptFile(channelKey, buffer);
            } catch { /* use raw */ }
          }
          if (cancelled) return;
          const ext = file.encrypted_filename.split('.').pop()?.toLowerCase() || 'png';
          const mimeMap: Record<string, string> = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml', bmp: 'image/bmp' };
          const blob = new Blob([finalBuffer], { type: mimeMap[ext] || 'image/png' });
          results.push({ fileId: file.id, url: URL.createObjectURL(blob) });
        } catch {
          // skip
        }
      }
      if (!cancelled) setLoaded(results);
    };
    if (imageFiles.length >= 2) loadAll();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [imageFiles.map(f => f.id).join(','), token, channelId]);

  useEffect(() => {
    return () => { loaded.forEach(l => URL.revokeObjectURL(l.url)); };
  }, [loaded]);

  if (imageFiles.length < 2) return null;

  const displayCount = Math.min(imageFiles.length, 4);
  const extraCount = imageFiles.length - 4;
  const gridClass = `message-image-grid grid-${displayCount}`;

  return (
    <div className={gridClass}>
      {loaded.slice(0, displayCount).map((img, i) => (
        <div
          key={img.fileId}
          className="grid-image"
          onClick={(e) => { e.stopPropagation(); onImageClick(img.url); }}
        >
          <img src={img.url} alt="" loading="lazy" />
          {i === 3 && extraCount > 0 && (
            <div className="grid-image-more-overlay">+{extraCount}</div>
          )}
        </div>
      ))}
    </div>
  );
}

/** Returns the non-image files from a list (for rendering normally alongside the grid) */
export function getNonImageFiles(files: FileMetadata[]): FileMetadata[] {
  return files.filter(f => !isImageFilename(f.encrypted_filename));
}

/** Returns whether files contain 2+ images (grid should be shown) */
export function hasImageGrid(files: FileMetadata[]): boolean {
  return files.filter(f => isImageFilename(f.encrypted_filename)).length >= 2;
}
