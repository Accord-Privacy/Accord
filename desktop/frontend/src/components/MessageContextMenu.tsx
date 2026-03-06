import React, { useCallback, useMemo } from 'react';
import { ContextMenu, ContextMenuItem } from './ui/ContextMenu';
import { useAppContext } from './AppContext';
import type { Message } from '../types';

interface MessageContextMenuProps {
  message: Message;
  children: React.ReactNode;
  onMarkUnread?: (messageId: string) => void;
}

export const MessageContextMenu: React.FC<MessageContextMenuProps> = ({
  message,
  children,
  onMarkUnread,
}) => {
  const ctx = useAppContext();
  const currentUser = ctx.appState.user;

  const isOwnMessage = useMemo(() => {
    if (!currentUser) return false;
    const displayName = currentUser.display_name || ctx.fingerprint(currentUser.public_key_hash);
    return message.author === displayName;
  }, [currentUser, message.author, ctx]);

  const handleCopyText = useCallback(() => {
    navigator.clipboard.writeText(message.content).catch(() => {});
  }, [message.content]);

  const handleCopyLink = useCallback(() => {
    const channelId = message.channel_id || ctx.selectedChannelId || '';
    const link = `#${channelId}/${message.id}`;
    navigator.clipboard.writeText(link).catch(() => {});
  }, [message.id, message.channel_id, ctx.selectedChannelId]);

  const handleReply = useCallback(() => {
    ctx.handleReply(message);
  }, [ctx, message]);

  const handleEdit = useCallback(() => {
    ctx.handleStartEdit(message.id, message.content);
  }, [ctx, message.id, message.content]);

  const handleDelete = useCallback(() => {
    ctx.setShowDeleteConfirm(message.id);
  }, [ctx, message.id]);

  const handlePin = useCallback(() => {
    if (message.pinned_at) {
      ctx.handleUnpinMessage(message.id);
    } else {
      ctx.setShowPinConfirm(message.id);
    }
  }, [ctx, message.id, message.pinned_at]);

  const handleMarkUnread = useCallback(() => {
    onMarkUnread?.(message.id);
  }, [onMarkUnread, message.id]);

  const items = useMemo((): ContextMenuItem[] => {
    const result: ContextMenuItem[] = [
      { label: 'Reply', icon: '↩', onClick: handleReply },
    ];

    if (isOwnMessage) {
      result.push({ label: 'Edit Message', icon: '✏', onClick: handleEdit });
    }

    if (isOwnMessage || (currentUser && ctx.canDeleteMessage(message))) {
      result.push({ label: 'Delete Message', icon: '🗑', danger: true, onClick: handleDelete });
    }

    result.push({ separator: true, label: '' });

    if (currentUser && ctx.canDeleteMessage(message)) {
      result.push({
        label: message.pinned_at ? 'Unpin Message' : 'Pin Message',
        icon: '📌',
        onClick: handlePin,
      });
    }

    result.push(
      { label: 'Copy Text', icon: '📋', onClick: handleCopyText },
      { label: 'Copy Message Link', icon: '🔗', onClick: handleCopyLink },
      { separator: true, label: '' },
      { label: 'Mark as Unread', icon: '⬤', onClick: handleMarkUnread },
    );

    return result;
  }, [
    isOwnMessage, currentUser, message, ctx,
    handleReply, handleEdit, handleDelete, handlePin,
    handleCopyText, handleCopyLink, handleMarkUnread,
  ]);

  return (
    <ContextMenu items={items}>
      {children}
    </ContextMenu>
  );
};
