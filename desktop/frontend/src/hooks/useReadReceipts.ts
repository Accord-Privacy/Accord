import { useState, useCallback, useRef } from "react";
import { api } from "../api";
import type { ReadReceipt } from "../types";

export function useReadReceipts() {
  const [readReceipts, setReadReceipts] = useState<Map<string, ReadReceipt[]>>(new Map());
  const lastReadSent = useRef<Map<string, string>>(new Map());

  const sendReadReceipt = useCallback((channelId: string, messageId: string, token?: string) => {
    if (!token || !messageId || !channelId) return;
    if (lastReadSent.current.get(channelId) === messageId) return;
    lastReadSent.current.set(channelId, messageId);
    api.markChannelRead(channelId, messageId, token).catch(() => {});
  }, []);

  const handleReadReceiptEvent = useCallback((channelId: string, userId: string, messageId: string, timestamp: number) => {
    setReadReceipts(prev => {
      const newMap = new Map(prev);
      const channelReceipts = (newMap.get(channelId) || []).filter(
        r => r.user_id !== userId
      );
      channelReceipts.push({ user_id: userId, message_id: messageId, timestamp });
      newMap.set(channelId, channelReceipts);
      return newMap;
    });
  }, []);

  return {
    readReceipts,
    sendReadReceipt,
    handleReadReceiptEvent,
  };
}
