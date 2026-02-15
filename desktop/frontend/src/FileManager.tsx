import React, { useState, useRef, useEffect } from 'react';
import { api } from './api';
import { FileMetadata, UploadProgress } from './types';
import { 
  getChannelKey, 
  encryptFile, 
  decryptFile, 
  encryptFilename, 
  decryptFilename 
} from './crypto';

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

export const FileUploadButton: React.FC<FileManagerProps> = ({
  channelId,
  token,
  keyPair,
  encryptionEnabled,
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

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setUploadState({
      isUploading: true,
      progress: { loaded: 0, total: file.size, percentage: 0 },
      fileName: file.name,
    });

    try {
      let fileToUpload = file;
      let encryptedFilename: string | undefined;

      // Encrypt file and filename if encryption is enabled and we have keys
      if (encryptionEnabled && keyPair) {
        try {
          const channelKey = await getChannelKey(keyPair.privateKey, channelId);
          
          // Read file as ArrayBuffer
          const fileBuffer = await file.arrayBuffer();
          
          // Encrypt the file content
          const encryptedBuffer = await encryptFile(channelKey, fileBuffer);
          
          // Encrypt the filename
          encryptedFilename = await encryptFilename(channelKey, file.name);
          
          // Create a new File from encrypted buffer
          fileToUpload = new File([encryptedBuffer], 'encrypted_file', {
            type: 'application/octet-stream'
          });
        } catch (error) {
          console.warn('Failed to encrypt file, uploading plaintext:', error);
        }
      }

      // Upload the file
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

      // Reset state on success
      setUploadState({
        isUploading: false,
        progress: null,
        fileName: '',
      });

      // Clear the input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }

    } catch (error) {
      console.error('File upload failed:', error);
      alert(`File upload failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      setUploadState({
        isUploading: false,
        progress: null,
        fileName: '',
      });
    }
  };

  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      <input
        ref={fileInputRef}
        type="file"
        onChange={handleFileChange}
        style={{ display: 'none' }}
        disabled={uploadState.isUploading}
      />
      
      <button
        onClick={handleFileSelect}
        disabled={uploadState.isUploading}
        style={{
          background: 'none',
          border: 'none',
          color: '#b9bbbe',
          cursor: uploadState.isUploading ? 'not-allowed' : 'pointer',
          fontSize: '18px',
          padding: '6px',
          borderRadius: '4px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          opacity: uploadState.isUploading ? 0.5 : 1,
        }}
        title="Attach file"
      >
        📎
      </button>

      {uploadState.isUploading && uploadState.progress && (
        <div
          style={{
            position: 'absolute',
            top: '100%',
            left: '0',
            marginTop: '4px',
            background: '#36393f',
            border: '1px solid #40444b',
            borderRadius: '4px',
            padding: '8px 12px',
            minWidth: '200px',
            zIndex: 1000,
            fontSize: '12px',
            color: '#dcddde',
          }}
        >
          <div style={{ marginBottom: '4px', fontWeight: 'bold' }}>
            Uploading {uploadState.fileName}
          </div>
          <div
            style={{
              background: '#40444b',
              borderRadius: '2px',
              height: '4px',
              marginBottom: '4px',
              overflow: 'hidden',
            }}
          >
            <div
              style={{
                background: '#7289da',
                height: '100%',
                width: `${uploadState.progress.percentage}%`,
                transition: 'width 0.2s ease',
              }}
            />
          </div>
          <div style={{ color: '#b9bbbe' }}>
            {uploadState.progress.percentage}% ({Math.round(uploadState.progress.loaded / 1024)} KB / {Math.round(uploadState.progress.total / 1024)} KB)
          </div>
        </div>
      )}
    </div>
  );
};

export const FileList: React.FC<FileManagerProps> = ({
  channelId,
  token,
  keyPair,
  encryptionEnabled,
}) => {
  const [files, setFiles] = useState<FileMetadata[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isVisible, setIsVisible] = useState(false);

  const loadFiles = async () => {
    if (!isVisible) return;
    
    setIsLoading(true);
    try {
      const fileList = await api.getChannelFiles(channelId, token);
      setFiles(fileList);
    } catch (error) {
      console.error('Failed to load files:', error);
      // Don't show error for demo mode
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadFiles();
  }, [channelId, isVisible]);

  const handleDownload = async (file: FileMetadata) => {
    try {
      // Download the file
      const encryptedBuffer = await api.downloadFile(file.id, token);
      
      let finalBuffer = encryptedBuffer;
      let filename = file.encrypted_filename;

      // Decrypt if encryption is enabled and we have keys
      if (encryptionEnabled && keyPair) {
        try {
          const channelKey = await getChannelKey(keyPair.privateKey, channelId);
          
          // Decrypt the file content
          finalBuffer = await decryptFile(channelKey, encryptedBuffer);
          
          // Decrypt the filename
          filename = await decryptFilename(channelKey, file.encrypted_filename);
        } catch (error) {
          console.warn('Failed to decrypt file, using encrypted data:', error);
        }
      }

      // Create and trigger download
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
      // Refresh the file list
      await loadFiles();
    } catch (error) {
      console.error('File deletion failed:', error);
      alert(`File deletion failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
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
        style={{
          background: 'none',
          border: 'none',
          color: '#b9bbbe',
          cursor: 'pointer',
          fontSize: '16px',
          padding: '6px',
          borderRadius: '4px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
        title="Show files"
      >
        📁
      </button>

      {isVisible && (
        <div
          style={{
            position: 'absolute',
            top: '100%',
            right: '0',
            marginTop: '4px',
            background: '#36393f',
            border: '1px solid #40444b',
            borderRadius: '8px',
            padding: '12px',
            minWidth: '400px',
            maxWidth: '500px',
            maxHeight: '400px',
            overflowY: 'auto',
            zIndex: 1000,
            fontSize: '12px',
            color: '#dcddde',
          }}
        >
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center', 
            marginBottom: '8px',
            borderBottom: '1px solid #40444b',
            paddingBottom: '8px'
          }}>
            <div style={{ fontWeight: 'bold', fontSize: '14px' }}>
              Channel Files
            </div>
            <button
              onClick={() => setIsVisible(false)}
              style={{
                background: 'none',
                border: 'none',
                color: '#b9bbbe',
                cursor: 'pointer',
                fontSize: '16px',
              }}
            >
              ✕
            </button>
          </div>

          {isLoading ? (
            <div style={{ textAlign: 'center', color: '#b9bbbe', padding: '20px' }}>
              Loading files...
            </div>
          ) : files.length === 0 ? (
            <div style={{ textAlign: 'center', color: '#b9bbbe', padding: '20px' }}>
              No files uploaded yet
            </div>
          ) : (
            <div>
              {files.map((file) => (
                <div
                  key={file.id}
                  style={{
                    background: '#40444b',
                    borderRadius: '4px',
                    padding: '8px',
                    marginBottom: '8px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div style={{ 
                      fontWeight: 'bold', 
                      marginBottom: '2px',
                      wordBreak: 'break-all'
                    }}>
                      {file.encrypted_filename}
                    </div>
                    <div style={{ color: '#b9bbbe', fontSize: '11px' }}>
                      {formatFileSize(file.file_size_bytes)} • {formatTimestamp(file.created_at)}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '4px', marginLeft: '8px' }}>
                    <button
                      onClick={() => handleDownload(file)}
                      style={{
                        background: '#7289da',
                        border: 'none',
                        color: 'white',
                        padding: '4px 8px',
                        borderRadius: '3px',
                        cursor: 'pointer',
                        fontSize: '11px',
                      }}
                      title="Download"
                    >
                      ⬇
                    </button>
                    <button
                      onClick={() => handleDelete(file)}
                      style={{
                        background: '#f04747',
                        border: 'none',
                        color: 'white',
                        padding: '4px 8px',
                        borderRadius: '3px',
                        cursor: 'pointer',
                        fontSize: '11px',
                      }}
                      title="Delete"
                    >
                      🗑
                    </button>
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