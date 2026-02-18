import React, { useState, useEffect, useCallback, useRef } from "react";
import { api } from "./api";
import { decryptMessage, getChannelKey } from "./crypto";
import { Channel } from "./types";

interface SearchResult {
  message_id: string;
  channel_id: string;
  channel_name: string;
  sender_id: string;
  sender_public_key_hash: string;
  created_at: number;
  encrypted_payload: string;
  decrypted_content?: string;
}

interface SearchOverlayProps {
  isVisible: boolean;
  onClose: () => void;
  nodeId: string | null;
  channels: Channel[];
  token: string | null;
  onNavigateToMessage: (channelId: string, messageId: string) => void;
  keyPair?: CryptoKeyPair | null;
  encryptionEnabled?: boolean;
}

/** Highlight search terms in text by wrapping matches in <mark> */
function highlightTerms(text: string, query: string): React.ReactNode {
  if (!query.trim()) return text;
  const terms = query.trim().split(/\s+/).filter(Boolean);
  const pattern = terms.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
  if (!pattern) return text;
  const regex = new RegExp(`(${pattern})`, "gi");
  const parts = text.split(regex);
  return parts.map((part, i) =>
    regex.test(part) ? <mark key={i} className="search-highlight">{part}</mark> : part
  );
}

export const SearchOverlay: React.FC<SearchOverlayProps> = ({
  isVisible,
  onClose,
  nodeId,
  channels,
  token,
  onNavigateToMessage,
  keyPair,
  encryptionEnabled,
}) => {
  const [query, setQuery] = useState("");
  const [selectedChannelId, setSelectedChannelId] = useState("");
  const [authorFilter, setAuthorFilter] = useState("");
  const [beforeDate, setBeforeDate] = useState("");
  const [afterDate, setAfterDate] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [showFilters, setShowFilters] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);

  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchTimeoutRef = useRef<number | undefined>(undefined);
  const resultsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isVisible && searchInputRef.current) {
      searchInputRef.current.focus();
      setSelectedIndex(-1);
    }
    if (!isVisible) {
      setQuery("");
      setResults([]);
      setError("");
      setSelectedIndex(-1);
    }
  }, [isVisible]);

  const performSearch = useCallback(async (
    searchQuery: string,
    channelId?: string,
    author?: string,
    before?: string,
    after?: string,
  ) => {
    if (!nodeId || !token || !searchQuery.trim()) {
      setResults([]);
      return;
    }

    setIsLoading(true);
    setError("");

    try {
      const filters: {
        channelId?: string;
        authorId?: string;
        before?: number;
        after?: number;
      } = {};
      if (channelId) filters.channelId = channelId;
      if (author) filters.authorId = author;
      if (before) filters.before = new Date(before).getTime();
      if (after) filters.after = new Date(after).getTime();

      const response = await api.searchMessages(nodeId, searchQuery.trim(), token, filters);

      // Try to decrypt results client-side
      const decryptedResults: SearchResult[] = await Promise.all(
        response.results.map(async (r) => {
          let decrypted_content: string | undefined;
          if (encryptionEnabled && keyPair && r.encrypted_payload) {
            try {
              const channelKey = await getChannelKey(keyPair.privateKey, r.channel_id);
              decrypted_content = await decryptMessage(channelKey, r.encrypted_payload);
            } catch {
              // Decryption failed - leave undefined
            }
          }
          return { ...r, decrypted_content };
        })
      );

      // If we have decrypted content, also filter client-side by content match
      const searchLower = searchQuery.trim().toLowerCase();
      const filtered = decryptedResults.filter(r => {
        // Always include if we couldn't decrypt (metadata match from server)
        if (!r.decrypted_content) return true;
        // Include if content matches the search query
        if (r.decrypted_content.toLowerCase().includes(searchLower)) return true;
        // Include if channel name or sender hash matches (server-side match)
        if (r.channel_name.toLowerCase().includes(searchLower)) return true;
        if (r.sender_public_key_hash.toLowerCase().includes(searchLower)) return true;
        return false;
      });

      setResults(filtered);
      setSelectedIndex(-1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
      setResults([]);
    } finally {
      setIsLoading(false);
    }
  }, [nodeId, token, encryptionEnabled, keyPair]);

  const triggerSearch = useCallback((
    q: string = query,
    ch: string = selectedChannelId,
    au: string = authorFilter,
    be: string = beforeDate,
    af: string = afterDate,
  ) => {
    if (searchTimeoutRef.current) window.clearTimeout(searchTimeoutRef.current);
    searchTimeoutRef.current = window.setTimeout(() => {
      performSearch(q, ch, au, be, af);
    }, 300);
  }, [query, selectedChannelId, authorFilter, beforeDate, afterDate, performSearch]);

  const handleSearchInput = useCallback((value: string) => {
    setQuery(value);
    triggerSearch(value);
  }, [triggerSearch]);

  const handleResultClick = (result: SearchResult) => {
    onNavigateToMessage(result.channel_id, result.message_id);
    onClose();
  };

  // Keyboard navigation
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex(i => Math.min(i + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex(i => Math.max(i - 1, -1));
    } else if (e.key === "Enter" && selectedIndex >= 0 && results[selectedIndex]) {
      e.preventDefault();
      handleResultClick(results[selectedIndex]);
    }
  }, [results, selectedIndex]);

  // Scroll selected result into view
  useEffect(() => {
    if (selectedIndex >= 0 && resultsRef.current) {
      const el = resultsRef.current.children[selectedIndex] as HTMLElement;
      el?.scrollIntoView({ block: "nearest" });
    }
  }, [selectedIndex]);

  useEffect(() => {
    return () => { if (searchTimeoutRef.current) window.clearTimeout(searchTimeoutRef.current); };
  }, []);

  const removeFilter = (type: string) => {
    switch (type) {
      case "channel": setSelectedChannelId(""); triggerSearch(query, "", authorFilter, beforeDate, afterDate); break;
      case "author": setAuthorFilter(""); triggerSearch(query, selectedChannelId, "", beforeDate, afterDate); break;
      case "before": setBeforeDate(""); triggerSearch(query, selectedChannelId, authorFilter, "", afterDate); break;
      case "after": setAfterDate(""); triggerSearch(query, selectedChannelId, authorFilter, beforeDate, ""); break;
    }
  };

  if (!isVisible) return null;

  const activeFilters = [
    selectedChannelId && { type: "channel", label: `In: #${channels.find(c => c.id === selectedChannelId)?.name || "..."}` },
    authorFilter && { type: "author", label: `From: ${authorFilter.slice(0, 8)}...` },
    beforeDate && { type: "before", label: `Before: ${beforeDate}` },
    afterDate && { type: "after", label: `After: ${afterDate}` },
  ].filter(Boolean) as Array<{ type: string; label: string }>;

  return (
    <div className="search-overlay" onKeyDown={handleKeyDown}>
      <div className="search-overlay-backdrop" onClick={onClose} />
      <div className="search-overlay-content">
        <div className="search-overlay-header">
          <h3>🔍 Search Messages</h3>
          <div className="search-header-actions">
            <button
              className={`search-filter-toggle ${showFilters ? "active" : ""}`}
              onClick={() => setShowFilters(!showFilters)}
              title="Toggle filters"
            >
              ⚙️ Filters
            </button>
            <button className="search-overlay-close" onClick={onClose}>×</button>
          </div>
        </div>

        <div className="search-overlay-body">
          <div className="search-controls">
            <div className="search-input-container">
              <input
                ref={searchInputRef}
                type="text"
                placeholder="Search messages... (content is searched after decryption)"
                value={query}
                onChange={(e) => handleSearchInput(e.target.value)}
                className="search-input"
              />
              {isLoading && <div className="search-loading">🔍</div>}
            </div>
          </div>

          {/* Active filter chips */}
          {activeFilters.length > 0 && (
            <div className="search-filter-chips">
              {activeFilters.map(f => (
                <span key={f.type} className="search-chip">
                  {f.label}
                  <button className="search-chip-remove" onClick={() => removeFilter(f.type)}>×</button>
                </span>
              ))}
            </div>
          )}

          {/* Expandable filter panel */}
          {showFilters && (
            <div className="search-filters-panel">
              <div className="search-filter-row">
                <label>Channel:</label>
                <select
                  value={selectedChannelId}
                  onChange={(e) => { setSelectedChannelId(e.target.value); triggerSearch(query, e.target.value, authorFilter, beforeDate, afterDate); }}
                  className="channel-filter-select"
                >
                  <option value="">All channels</option>
                  {channels.map(channel => (
                    <option key={channel.id} value={channel.id}>#{channel.name}</option>
                  ))}
                </select>
              </div>
              <div className="search-filter-row">
                <label>From (user ID):</label>
                <input
                  type="text"
                  placeholder="User ID..."
                  value={authorFilter}
                  onChange={(e) => { setAuthorFilter(e.target.value); triggerSearch(query, selectedChannelId, e.target.value, beforeDate, afterDate); }}
                  className="search-filter-input"
                />
              </div>
              <div className="search-filter-row">
                <label>After:</label>
                <input
                  type="date"
                  value={afterDate}
                  onChange={(e) => { setAfterDate(e.target.value); triggerSearch(query, selectedChannelId, authorFilter, beforeDate, e.target.value); }}
                  className="search-filter-input"
                />
              </div>
              <div className="search-filter-row">
                <label>Before:</label>
                <input
                  type="date"
                  value={beforeDate}
                  onChange={(e) => { setBeforeDate(e.target.value); triggerSearch(query, selectedChannelId, authorFilter, e.target.value, afterDate); }}
                  className="search-filter-input"
                />
              </div>
            </div>
          )}

          {error && <div className="search-error">⚠️ {error}</div>}

          <div className="search-results" ref={resultsRef}>
            {results.length === 0 && query.trim() && !isLoading && !error && (
              <div className="search-no-results">No messages found for &ldquo;{query}&rdquo;</div>
            )}

            {results.map((result, idx) => (
              <div
                key={result.message_id}
                className={`search-result ${idx === selectedIndex ? "search-result-selected" : ""}`}
                onClick={() => handleResultClick(result)}
              >
                <div className="search-result-header">
                  <span className="search-result-sender">
                    {result.sender_public_key_hash?.slice(0, 16) || "Unknown"}
                  </span>
                  <span className="search-result-channel">#{result.channel_name}</span>
                  <span className="search-result-time">
                    {new Date(result.created_at).toLocaleString()}
                  </span>
                </div>
                <div className="search-result-snippet">
                  {result.decrypted_content
                    ? highlightTerms(
                        result.decrypted_content.length > 200
                          ? result.decrypted_content.slice(0, 200) + "…"
                          : result.decrypted_content,
                        query
                      )
                    : <em className="search-encrypted-hint">🔐 Encrypted — click to view</em>
                  }
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="search-overlay-footer">
          <span className="search-footer-hint">
            ↑↓ Navigate · Enter to jump · Esc to close
          </span>
          {results.length > 0 && (
            <span className="search-result-count">{results.length} result{results.length !== 1 ? "s" : ""}</span>
          )}
        </div>
      </div>
    </div>
  );
};
