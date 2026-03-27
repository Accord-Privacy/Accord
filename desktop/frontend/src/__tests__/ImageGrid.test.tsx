import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ImageGrid, getNonImageFiles, hasImageGrid } from '../components/ImageGrid';
import type { FileMetadata } from '../types';
import * as apiModule from '../api';

vi.mock('../api', () => ({
  api: {
    downloadFile: vi.fn(),
  },
}));

vi.mock('../crypto', () => ({
  getChannelKey: vi.fn(),
  decryptFile: vi.fn(),
}));

const mockFile = (id: string, filename: string): FileMetadata => ({
  id,
  encrypted_filename: filename,
  file_size_bytes: 1024,
  uploader_id: 'user-1',
  created_at: Date.now(),
});

describe('ImageGrid', () => {
  const mockOnImageClick = vi.fn();
  let mockCreateObjectURL: ReturnType<typeof vi.fn>;
  let mockRevokeObjectURL: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockCreateObjectURL = vi.fn(() => `blob:${Math.random()}`);
    mockRevokeObjectURL = vi.fn();
    global.URL.createObjectURL = mockCreateObjectURL as any;
    global.URL.revokeObjectURL = mockRevokeObjectURL as any;

    (apiModule.api.downloadFile as any).mockResolvedValue(new ArrayBuffer(100));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders null when fewer than 2 image files', () => {
    const files = [mockFile('f1', 'image1.png')];
    const { container } = render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders null when no image files', () => {
    const files = [mockFile('f1', 'document.pdf'), mockFile('f2', 'file.txt')];
    const { container } = render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders grid with 2 images', async () => {
    const files = [mockFile('f1', 'img1.png'), mockFile('f2', 'img2.jpg')];
    const { container } = render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );

    await waitFor(() => {
      expect(container.querySelector('.message-image-grid')).toBeInTheDocument();
    });

    expect(container.querySelector('.grid-2')).toBeInTheDocument();
  });

  it('renders grid with 3 images', async () => {
    const files = [
      mockFile('f1', 'img1.png'),
      mockFile('f2', 'img2.jpg'),
      mockFile('f3', 'img3.gif'),
    ];
    const { container } = render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );

    await waitFor(() => {
      expect(container.querySelector('.grid-3')).toBeInTheDocument();
    });
  });

  it('renders grid with max 4 images when more are provided', async () => {
    const files = [
      mockFile('f1', 'img1.png'),
      mockFile('f2', 'img2.jpg'),
      mockFile('f3', 'img3.gif'),
      mockFile('f4', 'img4.png'),
      mockFile('f5', 'img5.jpg'),
      mockFile('f6', 'img6.png'),
    ];
    const { container } = render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );

    await waitFor(() => {
      const images = container.querySelectorAll('.grid-image');
      expect(images).toHaveLength(4);
    });

    expect(container.querySelector('.grid-4')).toBeInTheDocument();
  });

  it('displays +N overlay on 4th image when more than 4 images', async () => {
    const files = [
      mockFile('f1', 'img1.png'),
      mockFile('f2', 'img2.jpg'),
      mockFile('f3', 'img3.gif'),
      mockFile('f4', 'img4.png'),
      mockFile('f5', 'img5.jpg'),
      mockFile('f6', 'img6.png'),
    ];
    render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('+2')).toBeInTheDocument();
    });
  });

  it('calls onImageClick when an image is clicked', async () => {
    const files = [mockFile('f1', 'img1.png'), mockFile('f2', 'img2.jpg')];
    const { container } = render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );

    await waitFor(() => {
      expect(container.querySelector('.grid-image')).toBeInTheDocument();
    });

    const firstImage = container.querySelector('.grid-image');
    fireEvent.click(firstImage!);

    expect(mockOnImageClick).toHaveBeenCalledTimes(1);
    expect(mockOnImageClick).toHaveBeenCalledWith(expect.stringContaining('blob:'));
  });

  it('stops propagation when image is clicked', async () => {
    const files = [mockFile('f1', 'img1.png'), mockFile('f2', 'img2.jpg')];
    const { container } = render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );

    await waitFor(() => {
      expect(container.querySelector('.grid-image')).toBeInTheDocument();
    });

    const event = new MouseEvent('click', { bubbles: true, cancelable: true });
    const stopPropagationSpy = vi.spyOn(event, 'stopPropagation');
    const firstImage = container.querySelector('.grid-image');
    fireEvent(firstImage!, event);

    expect(stopPropagationSpy).toHaveBeenCalled();
  });

  it('downloads files with correct token', async () => {
    const files = [mockFile('f1', 'img1.png'), mockFile('f2', 'img2.jpg')];

    render(
      <ImageGrid
        files={files}
        token="my-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );

    await waitFor(() => {
      expect(apiModule.api.downloadFile).toHaveBeenCalledWith('f1', 'my-token');
      expect(apiModule.api.downloadFile).toHaveBeenCalledWith('f2', 'my-token');
    });
  });

  it('creates blob URLs for loaded images', async () => {
    const files = [mockFile('f1', 'img1.png'), mockFile('f2', 'img2.jpg')];

    render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );

    await waitFor(() => {
      expect(mockCreateObjectURL).toHaveBeenCalledTimes(2);
    });
  });

  it('revokes blob URLs on unmount', async () => {
    const files = [mockFile('f1', 'img1.png'), mockFile('f2', 'img2.jpg')];

    const { unmount } = render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );

    await waitFor(() => {
      expect(mockCreateObjectURL).toHaveBeenCalled();
    });

    unmount();

    expect(mockRevokeObjectURL).toHaveBeenCalled();
  });

  it('filters non-image files', async () => {
    const files = [
      mockFile('f1', 'image.png'),
      mockFile('f2', 'document.pdf'),
      mockFile('f3', 'photo.jpg'),
      mockFile('f4', 'file.txt'),
    ];

    render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );

    // Should only process image files
    await waitFor(() => {
      expect(apiModule.api.downloadFile).toHaveBeenCalledWith('f1', expect.any(String));
      expect(apiModule.api.downloadFile).toHaveBeenCalledWith('f3', expect.any(String));
      expect(apiModule.api.downloadFile).not.toHaveBeenCalledWith('f2', expect.any(String));
      expect(apiModule.api.downloadFile).not.toHaveBeenCalledWith('f4', expect.any(String));
    });
  });

  it('handles various image extensions', async () => {
    const files = [
      mockFile('f1', 'img.png'),
      mockFile('f2', 'img.jpg'),
      mockFile('f3', 'img.jpeg'),
      mockFile('f4', 'img.gif'),
      mockFile('f5', 'img.webp'),
    ];

    const { container } = render(
      <ImageGrid
        files={files}
        token="test-token"
        channelId="ch-1"
        keyPair={null}
        encryptionEnabled={false}
        onImageClick={mockOnImageClick}
      />
    );

    await waitFor(() => {
      expect(container.querySelector('.message-image-grid')).toBeInTheDocument();
    });
  });
});

describe('getNonImageFiles', () => {
  it('returns only non-image files', () => {
    const files = [
      mockFile('f1', 'image.png'),
      mockFile('f2', 'document.pdf'),
      mockFile('f3', 'photo.jpg'),
      mockFile('f4', 'file.txt'),
    ];
    const result = getNonImageFiles(files);
    expect(result).toHaveLength(2);
    expect(result[0].id).toBe('f2');
    expect(result[1].id).toBe('f4');
  });

  it('returns empty array when all files are images', () => {
    const files = [mockFile('f1', 'img1.png'), mockFile('f2', 'img2.jpg')];
    const result = getNonImageFiles(files);
    expect(result).toEqual([]);
  });

  it('returns all files when none are images', () => {
    const files = [mockFile('f1', 'doc.pdf'), mockFile('f2', 'file.txt')];
    const result = getNonImageFiles(files);
    expect(result).toHaveLength(2);
  });
});

describe('hasImageGrid', () => {
  it('returns true when 2+ image files exist', () => {
    const files = [mockFile('f1', 'img1.png'), mockFile('f2', 'img2.jpg')];
    expect(hasImageGrid(files)).toBe(true);
  });

  it('returns false when fewer than 2 image files', () => {
    const files = [mockFile('f1', 'img1.png')];
    expect(hasImageGrid(files)).toBe(false);
  });

  it('returns false when no image files', () => {
    const files = [mockFile('f1', 'doc.pdf'), mockFile('f2', 'file.txt')];
    expect(hasImageGrid(files)).toBe(false);
  });

  it('returns true when 2+ images mixed with non-images', () => {
    const files = [
      mockFile('f1', 'img1.png'),
      mockFile('f2', 'doc.pdf'),
      mockFile('f3', 'img2.jpg'),
    ];
    expect(hasImageGrid(files)).toBe(true);
  });
});
