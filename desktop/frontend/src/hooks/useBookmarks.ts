import { useState, useCallback, useEffect } from 'react';

export interface SavedMessage {
  id: string;
  content: string;
  channelId: string;
  channelName: string;
  author: string;
  timestamp: number;
  savedAt: number;
}

const STORAGE_KEY = 'accord_saved_messages';

function loadBookmarks(): SavedMessage[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveBookmarks(bookmarks: SavedMessage[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(bookmarks));
}

export function useBookmarks() {
  const [bookmarks, setBookmarks] = useState<SavedMessage[]>(loadBookmarks);

  // Sync state to localStorage
  useEffect(() => {
    saveBookmarks(bookmarks);
  }, [bookmarks]);

  const addBookmark = useCallback((msg: SavedMessage) => {
    setBookmarks(prev => {
      if (prev.some(b => b.id === msg.id)) return prev;
      return [msg, ...prev];
    });
  }, []);

  const removeBookmark = useCallback((messageId: string) => {
    setBookmarks(prev => prev.filter(b => b.id !== messageId));
  }, []);

  const isBookmarked = useCallback((messageId: string) => {
    return bookmarks.some(b => b.id === messageId);
  }, [bookmarks]);

  return { bookmarks, addBookmark, removeBookmark, isBookmarked };
}
