import React, { useMemo } from "react";
import { renderMessageMarkdown } from "../markdown";

interface MessagePreviewProps {
  text: string;
  currentUsername?: string;
  visible: boolean;
  onClose: () => void;
}

export const MessagePreview: React.FC<MessagePreviewProps> = ({
  text,
  currentUsername,
  visible,
  onClose,
}) => {
  const html = useMemo(
    () => (text.trim() ? renderMessageMarkdown(text, currentUsername) : ""),
    [text, currentUsername]
  );

  if (!visible || !text.trim()) return null;

  return (
    <div className="message-preview-panel">
      <div className="message-preview-header">
        <span className="message-preview-title">Preview</span>
        <button
          className="message-preview-close"
          onClick={onClose}
          title="Close preview (Ctrl+Shift+P)"
          aria-label="Close preview"
        >
          ×
        </button>
      </div>
      <div
        className="message-preview-body message-content"
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </div>
  );
};
