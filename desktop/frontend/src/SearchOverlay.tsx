import React, { useState, useEffect, useCallback, useRef } from "react";
import { api } from "./api";
import { Channel } from "./types";

interface SearchResult {
  message_id: string;
  channel_id: string;
  channel_name: string;
  sender_id: string;
  sender_username: string;
  timestamp: number;
}

interface SearchOverlayProps {
  isVisible: boolean;
  onClose: () => void;
  nodeId: string | null;
  channels: Channel[];
  token: string | null;
  onNavigateToMessage: (channelId: string, messageId: string) => void;
}

export const SearchOverlay: React.FC<SearchOverlayProps> = ({
  isVisible,
  onClose,
  nodeId,
  channels,
  token,
  onNavigateToMessage,
}) => {
  const [query, setQuery] = useState("");
  const [selectedChannelId, setSelectedChannelId] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  
  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchTimeoutRef = useRef<number | undefined>(undefined);

  // Auto-focus when overlay opens
  useEffect(() => {
    if (isVisible && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [isVisible]);

  // Debounced search function
  const performSearch = useCallback(async (searchQuery: string, channelFilter?: string) => {
    if (!nodeId || !token || !searchQuery.trim()) {
      setResults([]);
      setNote("");
      return;
    }

    setIsLoading(true);
    setError("");
    
    try {
      const response = await api.searchMessages(
        nodeId,
        searchQuery.trim(),
        token,
        channelFilter || undefined
      );
      setResults(response.results);
      setNote(response.note || "");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
      setResults([]);
      setNote("");
    } finally {
      setIsLoading(false);
    }
  }, [nodeId, token]);

  // Handle search input with debouncing
  const handleSearchInput = useCallback((value: string) => {
    setQuery(value);
    
    // Clear existing timeout
    if (searchTimeoutRef.current) {
      window.clearTimeout(searchTimeoutRef.current);
    }
    
    // Set new timeout for debounced search
    searchTimeoutRef.current = window.setTimeout(() => {
      performSearch(value, selectedChannelId);
    }, 300);
  }, [performSearch, selectedChannelId]);

  // Handle channel filter change
  const handleChannelFilterChange = useCallback((channelId: string) => {
    setSelectedChannelId(channelId);
    if (query.trim()) {
      performSearch(query, channelId);
    }
  }, [query, performSearch]);

  // Handle result click
  const handleResultClick = (result: SearchResult) => {
    onNavigateToMessage(result.channel_id, result.message_id);
    onClose();
  };

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isVisible) {
        onClose();
      }
    };

    if (isVisible) {
      document.addEventListener("keydown", handleKeyDown);
      return () => {
        document.removeEventListener("keydown", handleKeyDown);
      };
    }
  }, [isVisible, onClose]);

  // Clean up timeout on unmount
  useEffect(() => {
    return () => {
      if (searchTimeoutRef.current) {
        window.clearTimeout(searchTimeoutRef.current);
      }
    };
  }, []);

  if (!isVisible) return null;

  return (
    <div className="search-overlay">
      <div className="search-overlay-backdrop" onClick={onClose} />
      <div className="search-overlay-content">
        <div className="search-overlay-header">
          <h3>Search Messages</h3>
          <button className="search-overlay-close" onClick={onClose}>
            ×
          </button>
        </div>
        
        <div className="search-overlay-body">
          <div className="search-controls">
            <div className="search-input-container">
              <input
                ref={searchInputRef}
                type="text"
                placeholder="Search messages..."
                value={query}
                onChange={(e) => handleSearchInput(e.target.value)}
                className="search-input"
              />
              {isLoading && <div className="search-loading">🔍</div>}
            </div>
            
            <div className="search-filter">
              <select
                value={selectedChannelId}
                onChange={(e) => handleChannelFilterChange(e.target.value)}
                className="channel-filter-select"
              >
                <option value="">All channels</option>
                {channels.map(channel => (
                  <option key={channel.id} value={channel.id}>
                    #{channel.name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {note && (
            <div className="search-note">
              ℹ️ {note}
            </div>
          )}

          {error && (
            <div className="search-error">
              ⚠️ {error}
            </div>
          )}

          <div className="search-results">
            {results.length === 0 && query.trim() && !isLoading && !error && (
              <div className="search-no-results">
                No messages found for "{query}"
              </div>
            )}
            
            {results.map((result) => (
              <div
                key={result.message_id}
                className="search-result"
                onClick={() => handleResultClick(result)}
              >
                <div className="search-result-header">
                  <span className="search-result-sender">
                    {result.sender_username}
                  </span>
                  <span className="search-result-channel">
                    #{result.channel_name}
                  </span>
                  <span className="search-result-time">
                    {new Date(result.timestamp).toLocaleString()}
                  </span>
                </div>
                <div className="search-result-snippet">
                  Click to view message
                </div>
              </div>
            ))}
          </div>
        </div>
        
        <div className="search-overlay-footer">
          <div className="search-encryption-note">
            🔐 Content search requires client-side decryption
          </div>
        </div>
      </div>
    </div>
  );
};