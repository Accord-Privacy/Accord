import { useState, useCallback, useEffect } from "react";
import type { TypingUser } from "../types";
import type { AccordWebSocket } from "../ws";
import type { NodeMember, User } from "../types";

export function useTyping(
  ws: AccordWebSocket | null,
  members: Array<NodeMember & { user: User }>,
) {
  const [typingUsers, setTypingUsers] = useState<Map<string, TypingUser[]>>(new Map());
  const [typingTimeouts, setTypingTimeouts] = useState<Map<string, number>>(new Map());
  const [lastTypingSent, setLastTypingSent] = useState<number>(0);
  const typingIndicatorsEnabled = useState(() =>
    localStorage.getItem('accord-typing-indicators') !== 'false'
  )[0];

  const sendTypingIndicator = useCallback((channelId: string) => {
    if (!typingIndicatorsEnabled || !ws || !channelId) return;

    const now = Date.now();
    const timeSinceLastTyping = now - lastTypingSent;

    if (timeSinceLastTyping >= 3000) {
      ws.sendTypingStart(channelId);
      setLastTypingSent(now);
    }
  }, [ws, typingIndicatorsEnabled, lastTypingSent]);

  const formatTypingUsers = useCallback((channelId: string): string => {
    const tusers = typingUsers.get(channelId) || [];
    const currentUserId = localStorage.getItem('accord_user_id');
    const filtered = tusers.filter(u => u.user_id !== currentUserId);

    if (filtered.length === 0) return '';

    const getName = (tu: TypingUser) => {
      const member = members.find(m => m.user_id === tu.user_id);
      if (member?.user?.display_name) return member.user.display_name;
      if (member?.profile?.display_name) return member.profile.display_name;
      return tu.displayName;
    };

    if (filtered.length === 1) return `${getName(filtered[0])} is typing`;
    if (filtered.length === 2) return `${getName(filtered[0])} and ${getName(filtered[1])} are typing`;
    return 'Several people are typing';
  }, [typingUsers, members]);

  const handleTypingStart = useCallback((channelId: string, userId: string, displayName: string) => {
    const typingUser: TypingUser = {
      user_id: userId,
      displayName,
      startedAt: Date.now(),
    };

    setTypingUsers(prev => {
      const newMap = new Map(prev);
      const channelTyping = newMap.get(channelId) || [];
      const filteredTyping = channelTyping.filter(user => user.user_id !== userId);
      newMap.set(channelId, [...filteredTyping, typingUser]);
      return newMap;
    });

    const timeoutKey = `${channelId}_${userId}`;
    setTypingTimeouts(prev => {
      const newMap = new Map(prev);
      const existingTimeout = newMap.get(timeoutKey);
      if (existingTimeout) {
        clearTimeout(existingTimeout);
      }

      const timeout = window.setTimeout(() => {
        setTypingUsers(prevTyping => {
          const newTypingMap = new Map(prevTyping);
          const ct = newTypingMap.get(channelId) || [];
          const ft = ct.filter(user => user.user_id !== userId);
          if (ft.length > 0) {
            newTypingMap.set(channelId, ft);
          } else {
            newTypingMap.delete(channelId);
          }
          return newTypingMap;
        });
        setTypingTimeouts(prevTimeouts => {
          const newTimeoutsMap = new Map(prevTimeouts);
          newTimeoutsMap.delete(timeoutKey);
          return newTimeoutsMap;
        });
      }, 5000);

      newMap.set(timeoutKey, timeout);
      return newMap;
    });
  }, []);

  // Cleanup typing timeouts on unmount
  useEffect(() => {
    return () => {
      typingTimeouts.forEach(timeout => clearTimeout(timeout));
    };
  }, [typingTimeouts]);

  return {
    typingUsers,
    sendTypingIndicator,
    formatTypingUsers,
    handleTypingStart,
  };
}
