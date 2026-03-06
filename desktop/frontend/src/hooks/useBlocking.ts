import { useState, useCallback, useEffect } from "react";
import { api } from "../api";

export function useBlocking(token: string | undefined, isAuthenticated: boolean) {
  const [blockedUsers, setBlockedUsers] = useState<Set<string>>(new Set());

  const handleBlockUser = useCallback(async (userId: string) => {
    if (!token) return;
    try {
      await api.blockUser(userId, token);
      setBlockedUsers(prev => new Set(prev).add(userId));
    } catch (err) {
      console.error('Failed to block user:', err);
      throw err;
    }
  }, [token]);

  const handleUnblockUser = useCallback(async (userId: string) => {
    if (!token) return;
    try {
      await api.unblockUser(userId, token);
      setBlockedUsers(prev => {
        const next = new Set(prev);
        next.delete(userId);
        return next;
      });
    } catch (err) {
      console.error('Failed to unblock user:', err);
      throw err;
    }
  }, [token]);

  // Fetch blocked users on login
  useEffect(() => {
    if (isAuthenticated && token) {
      api.getBlockedUsers(token).then(resp => {
        setBlockedUsers(new Set(resp.blocked_users.map(b => b.user_id)));
      }).catch(err => console.warn('Failed to load blocked users:', err));
    }
  }, [isAuthenticated, token]);

  return {
    blockedUsers,
    handleBlockUser,
    handleUnblockUser,
  };
}
