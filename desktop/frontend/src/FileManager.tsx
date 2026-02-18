import React, { useState, useRef, useEffect, useCallback } from 'react';
import { api } from './api';
import { FileMetadata, UploadProgress } from './types';
import { 
  getChannelKey, 
  encryptFile, 
  decryptFile, 
  encryptFilename, 
  decryptFilename 
} from './crypto';

export interface StagedFile {
  file: File;
  previewUrl?: string; // blob URL for image previews
  name: string;
}

interface FileManagerProps {
  channelId: string;
  token: string;
  keyPair: CryptoKeyPair | null;
  encryptionEnabled: boolean;
}

interface FileUploadState {
  isUploading: boolean;
  progress: UploadProgress | null;
  fileName: string;
}

// =================== File Upload Button ===================
interface FileUploadButtonProps extends FileManagerProps {
  onFilesStaged?: (files: StagedFile[]) => void;
}

export const FileUploadButton: React.FC<FileUploadButtonProps> = ({
  channelId,
  token,
  keyPair,
  encryptionEnabled,
  onFilesStaged,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploadState, setUploadState] = useState<FileUploadState>({
    isUploading: false,
    progress: null,
    fileName: '',
  });

  const handleFileSelect = () => {
    fileInputRef.current?.click();
  };

  const uploadFile = useCallback(async (file: File) => {
    setUploadState({
      isUploading: true,
      progress: { loaded: 0, total: file.size, percentage: 0 },
      fileName: file.name,
    });

    try {
      let fileToUpload = file;
      let encryptedFilename: string | undefined;

      if (encryptionEnabled && keyPair) {
        try {
          const channelKey = await getChannelKey(keyPair.privateKey, channelId);
          const fileBuffer = await file.arrayBuffer();
          const encryptedBuffer = await encryptFile(channelKey, fileBuffer);
          encryptedFilename = await encryptFilename(channelKey, file.name);
          fileToUpload = new File([encryptedBuffer], 'encrypted_file', {
            type: 'application/octet-stream'
          });
        } catch (error) {
          console.warn('Failed to encrypt file, uploading plaintext:', error);
        }
      }

      await api.uploadFile(
        channelId,
        fileToUpload,
        token,
        encryptedFilename,
        (loaded, total) => {
          const percentage = Math.round((loaded / total) * 100);
          setUploadState(prev => ({
            ...prev,
            progress: { loaded, total, percentage }
          }));
        }
      );

      setUploadState({ isUploading: false, progress: null, fileName: '' });
      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch (error) {
      console.error('File upload failed:', error);
      alert(`File upload failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      setUploadState({ isUploading: false, progress: null, fileName: '' });
    }
  }, [channelId, token, keyPair, encryptionEnabled]);

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = event.target.files;
    if (!selectedFiles || selectedFiles.length === 0) return;

    if (onFilesStaged) {
      // Stage files for preview before sending
      const staged: StagedFile[] = [];
      for (let i = 0; i < selectedFiles.length; i++) {
        const file = selectedFiles[i];
        const previewUrl = isImageFile(file.name) ? URL.createObjectURL(file) : undefined;
        staged.push({ file, previewUrl, name: file.name });
      }
      onFilesStaged(staged);
      if (fileInputRef.current) fileInputRef.current.value = '';
    } else {
      // Direct upload (legacy behavior)
      for (let i = 0; i < selectedFiles.length; i++) {
        await uploadFile(selectedFiles[i]);
      }
    }
  };

  return (
    <div className="file-upload-wrapper">
      <input
        ref={fileInputRef}
        type="file"
        multiple
        onChange={handleFileChange}
        style={{ display: 'none' }}
        disabled={uploadState.isUploading}
      />
      
      <button
        onClick={handleFileSelect}
        disabled={uploadState.isUploading}
        className="file-upload-btn"
        title="Attach file"
      >
        📎
      </button>

      {uploadState.isUploading && uploadState.progress && (
        <div className="file-upload-progress">
          <div className="file-upload-progress-name">
            Uploading {uploadState.fileName}
          </div>
          <div className="file-upload-progress-bar-track">
            <div
              className="file-upload-progress-bar-fill"
              style={{ width: `${uploadState.progress.percentage}%` }}
            />
          </div>
          <div className="file-upload-progress-text">
            {uploadState.progress.percentage}% ({formatFileSize(uploadState.progress.loaded)} / {formatFileSize(uploadState.progress.total)})
          </div>
        </div>
      )}
    </div>
  );
};

// =================== Drag & Drop Wrapper ===================
interface DropZoneProps {
  channelId: string;
  token: string;
  keyPair: CryptoKeyPair | null;
  encryptionEnabled: boolean;
  children: React.ReactNode;
  onFilesStaged?: (files: StagedFile[]) => void;
}

export const FileDropZone: React.FC<DropZoneProps> = ({
  channelId,
  token,
  keyPair,
  encryptionEnabled,
  children,
  onFilesStaged,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [uploadState, setUploadState] = useState<FileUploadState>({
    isUploading: false,
    progress: null,
    fileName: '',
  });
  const dragCounter = useRef(0);

  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current++;
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setIsDragging(true);
    }
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current--;
    if (dragCounter.current === 0) {
      setIsDragging(false);
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const uploadSingleFile = useCallback(async (file: File) => {
    let fileToUpload = file;
    let encryptedFilename: string | undefined;

    if (encryptionEnabled && keyPair) {
      try {
        const channelKey = await getChannelKey(keyPair.privateKey, channelId);
        const fileBuffer = await file.arrayBuffer();
        const encryptedBuffer = await encryptFile(channelKey, fileBuffer);
        encryptedFilename = await encryptFilename(channelKey, file.name);
        fileToUpload = new File([encryptedBuffer], 'encrypted_file', {
          type: 'application/octet-stream'
        });
      } catch (error) {
        console.warn('Failed to encrypt file, uploading plaintext:', error);
      }
    }

    await api.uploadFile(
      channelId,
      fileToUpload,
      token,
      encryptedFilename,
      (loaded, total) => {
        const percentage = Math.round((loaded / total) * 100);
        setUploadState(prev => ({
          ...prev,
          progress: { loaded, total, percentage }
        }));
      }
    );
  }, [channelId, token, keyPair, encryptionEnabled]);

  const handleDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    dragCounter.current = 0;

    const files = e.dataTransfer.files;
    if (!files || files.length === 0) return;

    if (onFilesStaged) {
      // Stage files for preview
      const staged: StagedFile[] = [];
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const previewUrl = isImageFile(file.name) ? URL.createObjectURL(file) : undefined;
        staged.push({ file, previewUrl, name: file.name });
      }
      onFilesStaged(staged);
      return;
    }

    // Direct upload all files sequentially (legacy behavior)
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      setUploadState({
        isUploading: true,
        progress: { loaded: 0, total: file.size, percentage: 0 },
        fileName: `${file.name}${files.length > 1 ? ` (${i + 1}/${files.length})` : ''}`,
      });

      try {
        await uploadSingleFile(file);
      } catch (error) {
        console.error('File upload failed:', error);
        alert(`File upload failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
    setUploadState({ isUploading: false, progress: null, fileName: '' });
  }, [onFilesStaged, uploadSingleFile]);

  return (
    <div
      className="file-drop-zone"
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      {children}
      {isDragging && (
        <div className="file-drop-overlay">
          <div className="file-drop-overlay-content">
            <span className="file-drop-icon">📁</span>
            <span>Drop files to upload</span>
          </div>
        </div>
      )}
      {uploadState.isUploading && uploadState.progress && (
        <div className="file-drop-upload-toast">
          <div className="file-upload-progress-name">
            Uploading {uploadState.fileName}
          </div>
          <div className="file-upload-progress-bar-track">
            <div
              className="file-upload-progress-bar-fill"
              style={{ width: `${uploadState.progress.percentage}%` }}
            />
          </div>
          <div className="file-upload-progress-text">
            {uploadState.progress.percentage}%
          </div>
        </div>
      )}
    </div>
  );
};

// =================== Staged Files Preview ===================
interface StagedFilesPreviewProps {
  files: StagedFile[];
  onRemove: (index: number) => void;
  onClear: () => void;
}

export const StagedFilesPreview: React.FC<StagedFilesPreviewProps> = ({
  files,
  onRemove,
  onClear,
}) => {
  if (files.length === 0) return null;

  return (
    <div className="staged-files-preview">
      <div className="staged-files-header">
        <span className="staged-files-count">{files.length} file{files.length > 1 ? 's' : ''} attached</span>
        <button className="staged-files-clear" onClick={onClear} title="Remove all">✕</button>
      </div>
      <div className="staged-files-list">
        {files.map((sf, index) => (
          <div key={index} className="staged-file-item">
            {sf.previewUrl ? (
              <img src={sf.previewUrl} alt={sf.name} className="staged-file-thumb" />
            ) : (
              <span className="staged-file-icon">{getFileTypeIcon(sf.name)}</span>
            )}
            <span className="staged-file-name" title={sf.name}>{sf.name}</span>
            <span className="staged-file-size">{formatFileSize(sf.file.size)}</span>
            <button className="staged-file-remove" onClick={() => onRemove(index)} title="Remove">✕</button>
          </div>
        ))}
      </div>
    </div>
  );
};

// =================== File Attachment Display (in messages) ===================
interface FileAttachmentProps {
  file: FileMetadata;
  token: string;
  channelId: string;
  keyPair: CryptoKeyPair | null;
  encryptionEnabled: boolean;
}

export const FileAttachment: React.FC<FileAttachmentProps> = ({
  file,
  token,
  channelId,
  keyPair,
  encryptionEnabled,
}) => {
  const [decryptedName, setDecryptedName] = useState<string>(file.encrypted_filename);
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const init = async () => {
      let filename = file.encrypted_filename;
      if (encryptionEnabled && keyPair) {
        try {
          const channelKey = await getChannelKey(keyPair.privateKey, channelId);
          filename = await decryptFilename(channelKey, file.encrypted_filename);
        } catch {
          // keep encrypted name
        }
      }
      if (!cancelled) {
        setDecryptedName(filename);
        // Check if image
        if (isImageFile(filename)) {
          try {
            const buffer = await api.downloadFile(file.id, token);
            let finalBuffer = buffer;
            if (encryptionEnabled && keyPair) {
              try {
                const channelKey = await getChannelKey(keyPair.privateKey, channelId);
                finalBuffer = await decryptFile(channelKey, buffer);
              } catch { /* use raw */ }
            }
            if (!cancelled) {
              const blob = new Blob([finalBuffer]);
              setImageUrl(URL.createObjectURL(blob));
            }
          } catch {
            // no preview
          }
        }
      }
    };
    init();
    return () => { cancelled = true; };
  }, [file.id, file.encrypted_filename, channelId, token, keyPair, encryptionEnabled]);

  // Cleanup blob URL
  useEffect(() => {
    return () => {
      if (imageUrl) URL.revokeObjectURL(imageUrl);
    };
  }, [imageUrl]);

  const handleDownload = async () => {
    setDownloading(true);
    try {
      const buffer = await api.downloadFile(file.id, token);
      let finalBuffer = buffer;
      let filename = decryptedName;

      if (encryptionEnabled && keyPair) {
        try {
          const channelKey = await getChannelKey(keyPair.privateKey, channelId);
          finalBuffer = await decryptFile(channelKey, buffer);
          filename = await decryptFilename(channelKey, file.encrypted_filename);
        } catch {
          // use raw
        }
      }

      const blob = new Blob([finalBuffer]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Download failed:', error);
      alert(`Download failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setDownloading(false);
    }
  };

  const icon = getFileTypeIcon(decryptedName);

  return (
    <div className="file-attachment">
      {imageUrl && (
        <div className="file-attachment-image-preview">
          <img src={imageUrl} alt={decryptedName} onClick={handleDownload} />
        </div>
      )}
      <div className="file-attachment-info">
        <span className="file-attachment-icon">{icon}</span>
        <div className="file-attachment-details">
          <span className="file-attachment-name" title={decryptedName}>{decryptedName}</span>
          <span className="file-attachment-size">{formatFileSize(file.file_size_bytes)}</span>
        </div>
        <button
          className="file-attachment-download"
          onClick={handleDownload}
          disabled={downloading}
          title="Download"
        >
          {downloading ? '⏳' : '⬇️'}
        </button>
      </div>
    </div>
  );
};

// =================== File List Panel ===================
export const FileList: React.FC<FileManagerProps> = ({
  channelId,
  token,
  keyPair,
  encryptionEnabled,
}) => {
  const [files, setFiles] = useState<FileMetadata[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isVisible, setIsVisible] = useState(false);

  const loadFiles = useCallback(async () => {
    if (!isVisible) return;
    
    setIsLoading(true);
    try {
      const fileList = await api.getChannelFiles(channelId, token);
      setFiles(fileList);
    } catch (error) {
      console.error('Failed to load files:', error);
    } finally {
      setIsLoading(false);
    }
  }, [channelId, token, isVisible]);

  useEffect(() => {
    loadFiles();
  }, [loadFiles]);

  const handleDownload = async (file: FileMetadata) => {
    try {
      const encryptedBuffer = await api.downloadFile(file.id, token);
      
      let finalBuffer = encryptedBuffer;
      let filename = file.encrypted_filename;

      if (encryptionEnabled && keyPair) {
        try {
          const channelKey = await getChannelKey(keyPair.privateKey, channelId);
          finalBuffer = await decryptFile(channelKey, encryptedBuffer);
          filename = await decryptFilename(channelKey, file.encrypted_filename);
        } catch (error) {
          console.warn('Failed to decrypt file, using encrypted data:', error);
        }
      }

      const blob = new Blob([finalBuffer]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('File download failed:', error);
      alert(`File download failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const handleDelete = async (file: FileMetadata) => {
    if (!confirm(`Are you sure you want to delete "${file.encrypted_filename}"?`)) {
      return;
    }

    try {
      await api.deleteFile(file.id, token);
      await loadFiles();
    } catch (error) {
      console.error('File deletion failed:', error);
      alert(`File deletion failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const formatTimestamp = (timestamp: number): string => {
    const date = new Date(timestamp * 1000);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { 
      hour: '2-digit', 
      minute: '2-digit' 
    });
  };

  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      <button
        onClick={() => setIsVisible(!isVisible)}
        className="file-list-toggle-btn"
        title="Show files"
      >
        📁
      </button>

      {isVisible && (
        <div className="file-list-panel">
          <div className="file-list-header">
            <div className="file-list-title">Channel Files</div>
            <button className="file-list-close" onClick={() => setIsVisible(false)}>✕</button>
          </div>

          {isLoading ? (
            <div className="file-list-empty">Loading files...</div>
          ) : files.length === 0 ? (
            <div className="file-list-empty">No files uploaded yet</div>
          ) : (
            <div className="file-list-items">
              {files.map((file) => (
                <div key={file.id} className="file-list-item">
                  <div className="file-list-item-icon">{getFileTypeIcon(file.encrypted_filename)}</div>
                  <div className="file-list-item-info">
                    <div className="file-list-item-name">{file.encrypted_filename}</div>
                    <div className="file-list-item-meta">
                      {formatFileSize(file.file_size_bytes)} • {formatTimestamp(file.created_at)}
                    </div>
                  </div>
                  <div className="file-list-item-actions">
                    <button onClick={() => handleDownload(file)} className="file-list-item-download" title="Download">⬇</button>
                    <button onClick={() => handleDelete(file)} className="file-list-item-delete" title="Delete">🗑</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// =================== Helpers ===================

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function isImageFile(filename: string): boolean {
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  return ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'].includes(ext);
}

function getFileTypeIcon(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'].includes(ext)) return '🖼️';
  if (['mp4', 'webm', 'mov', 'avi'].includes(ext)) return '🎬';
  if (['mp3', 'wav', 'ogg', 'flac', 'aac'].includes(ext)) return '🎵';
  if (['pdf'].includes(ext)) return '📕';
  if (['zip', 'tar', 'gz', 'rar', '7z'].includes(ext)) return '📦';
  if (['doc', 'docx', 'txt', 'md', 'rtf'].includes(ext)) return '📄';
  if (['xls', 'xlsx', 'csv'].includes(ext)) return '📊';
  if (['js', 'ts', 'py', 'rs', 'go', 'c', 'cpp', 'h', 'java'].includes(ext)) return '💻';
  if (['json', 'yaml', 'yml', 'toml', 'xml'].includes(ext)) return '⚙️';
  return '📎';
}
