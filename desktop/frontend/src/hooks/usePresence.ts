import { useState, useCallback } from "react";
import type { PresenceStatus } from "../types";
import type { NodeMember, User } from "../types";

export function usePresence(
  members: Array<NodeMember & { user: User }>,
) {
  const [presenceMap, setPresenceMap] = useState<Map<string, PresenceStatus>>(new Map());
  const [lastMessageTimes, setLastMessageTimes] = useState<Map<string, number>>(new Map());

  const getPresenceStatus = useCallback((userId: string): PresenceStatus => {
    const explicit = presenceMap.get(userId);
    if (explicit) return explicit;
    const lastMsg = lastMessageTimes.get(userId);
    if (lastMsg && Date.now() - lastMsg < 5 * 60 * 1000) {
      return 'online' as PresenceStatus;
    }
    const member = members.find(m => m.user_id === userId);
    if (member?.status) return member.status;
    if (member?.profile?.status) return member.profile.status;
    return 'offline' as PresenceStatus;
  }, [presenceMap, lastMessageTimes, members]);

  const recordMessageTime = useCallback((userId: string) => {
    setLastMessageTimes(prev => {
      const newMap = new Map(prev);
      newMap.set(userId, Date.now());
      return newMap;
    });
  }, []);

  return {
    presenceMap, setPresenceMap,
    lastMessageTimes, setLastMessageTimes,
    getPresenceStatus,
    recordMessageTime,
  };
}
