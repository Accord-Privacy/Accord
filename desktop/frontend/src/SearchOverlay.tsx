import React, { useState, useEffect, useCallback, useRef } from "react";
import { api } from "./api";
import { decryptMessage, getChannelKey } from "./crypto";
import { Channel, Message } from "./types";

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

interface LocalSearchResult {
  message_id: string;
  channel_id: string;
  channel_name: string;
  sender_id: string;
  sender_public_key_hash: string;
  created_at: number;
  decrypted_content: string;
  display_name?: string;
}

type SearchMode = "server" | "local";

interface SearchOverlayProps {
  isVisible: boolean;
  onClose: () => void;
  nodeId: string | null;
  channels: Channel[];
  token: string | null;
  onNavigateToMessage: (channelId: string, messageId: string) => void;
  keyPair?: CryptoKeyPair | null;
  encryptionEnabled?: boolean;
  /** Currently loaded/displayed messages (already decrypted) for local search */
  currentMessages?: Message[];
  /** Current channel ID for local search context */
  currentChannelId?: string;
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

/** Cache of decrypted message content for faster re-search, keyed by message ID */
const decryptedContentCache = new Map<string, string>();
let cachedChannelId: string | undefined;

function clearCacheIfChannelChanged(channelId?: string) {
  if (channelId !== cachedChannelId) {
    decryptedContentCache.clear();
    cachedChannelId = channelId;
  }
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
  currentMessages,
  currentChannelId,
}) => {
  const [query, setQuery] = useState("");
  const [selectedChannelId, setSelectedChannelId] = useState("");
  const [authorFilter, setAuthorFilter] = useState("");
  const [beforeDate, setBeforeDate] = useState("");
  const [afterDate, setAfterDate] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [localResults, setLocalResults] = useState<LocalSearchResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [showFilters, setShowFilters] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [searchMode, setSearchMode] = useState<SearchMode>("local");

  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchTimeoutRef = useRef<number | undefined>(undefined);
  const resultsRef = useRef<HTMLDivElement>(null);

  // Clear cache when channel changes
  useEffect(() => {
    clearCacheIfChannelChanged(currentChannelId);
  }, [currentChannelId]);

  // Build search index from current messages
  useEffect(() => {
    if (currentMessages && currentChannelId) {
      clearCacheIfChannelChanged(currentChannelId);
      for (const msg of currentMessages) {
        if (msg.content && msg.id && !decryptedContentCache.has(msg.id)) {
          decryptedContentCache.set(msg.id, msg.content);
        }
      }
    }
  }, [currentMessages, currentChannelId]);

  useEffect(() => {
    if (isVisible && searchInputRef.current) {
      searchInputRef.current.focus();
      setSelectedIndex(-1);
    }
    if (!isVisible) {
      setQuery("");
      setResults([]);
      setLocalResults([]);
      setError("");
      setSelectedIndex(-1);
    }
  }, [isVisible]);

  // Local search through cached/loaded messages
  const performLocalSearch = useCallback((searchQuery: string) => {
    if (!searchQuery.trim() || !currentMessages) {
      setLocalResults([]);
      return;
    }

    const searchLower = searchQuery.trim().toLowerCase();
    const terms = searchLower.split(/\s+/).filter(Boolean);
    const channelName = channels.find(c => c.id === currentChannelId)?.name || "";

    const matched: LocalSearchResult[] = [];
    for (const msg of currentMessages) {
      const content = decryptedContentCache.get(msg.id) || msg.content || "";
      if (!content) continue;

      const contentLower = content.toLowerCase();
      const authorLower = (msg.display_name || msg.author || "").toLowerCase();

      // All terms must match in content or author
      const allMatch = terms.every(term =>
        contentLower.includes(term) || authorLower.includes(term)
      );

      if (allMatch) {
        matched.push({
          message_id: msg.id,
          channel_id: msg.channel_id || currentChannelId || "",
          channel_name: channelName,
          sender_id: msg.sender_id || msg.author || "",
          sender_public_key_hash: msg.sender_public_key_hash || msg.author || "",
          created_at: msg.timestamp || 0,
          decrypted_content: content,
          display_name: msg.display_name,
        });
      }
    }

    setLocalResults(matched);
    setSelectedIndex(-1);
  }, [currentMessages, currentChannelId, channels]);

  const performServerSearch = useCallback(async (
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
        if (!r.decrypted_content) return true;
        if (r.decrypted_content.toLowerCase().includes(searchLower)) return true;
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
      if (searchMode === "local") {
        performLocalSearch(q);
      } else {
        performServerSearch(q, ch, au, be, af);
      }
    }, 300);
  }, [query, selectedChannelId, authorFilter, beforeDate, afterDate, performServerSearch, performLocalSearch, searchMode]);

  const handleSearchInput = useCallback((value: string) => {
    setQuery(value);
    triggerSearch(value);
  }, [triggerSearch]);

  const handleModeSwitch = useCallback((mode: SearchMode) => {
    setSearchMode(mode);
    setResults([]);
    setLocalResults([]);
    setSelectedIndex(-1);
    // Re-trigger search with new mode after state update
    if (query.trim()) {
      if (searchTimeoutRef.current) window.clearTimeout(searchTimeoutRef.current);
      searchTimeoutRef.current = window.setTimeout(() => {
        if (mode === "local") {
          performLocalSearch(query);
        } else {
          performServerSearch(query, selectedChannelId, authorFilter, beforeDate, afterDate);
        }
      }, 100);
    }
  }, [query, selectedChannelId, authorFilter, beforeDate, afterDate, performLocalSearch, performServerSearch]);

  const handleResultClick = (channelId: string, messageId: string) => {
    onNavigateToMessage(channelId, messageId);
    onClose();
  };

  // Active result list for keyboard nav
  const activeResults = searchMode === "local" ? localResults : results;

  // Keyboard navigation
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex(i => Math.min(i + 1, activeResults.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex(i => Math.max(i - 1, -1));
    } else if (e.key === "Enter" && selectedIndex >= 0 && activeResults[selectedIndex]) {
      e.preventDefault();
      const r = activeResults[selectedIndex];
      handleResultClick(
        "channel_id" in r ? r.channel_id : "",
        "message_id" in r ? r.message_id : "",
      );
    }
  }, [activeResults, selectedIndex]);

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
          <h3>{searchMode === "local" ? "🔒" : "🔍"} Search Messages</h3>
          <div className="search-header-actions">
            <div className="search-mode-tabs">
              <button
                className={`search-mode-tab ${searchMode === "local" ? "active" : ""}`}
                onClick={() => handleModeSwitch("local")}
                title="Search decrypted messages locally"
              >
                🔒 Local
              </button>
              <button
                className={`search-mode-tab ${searchMode === "server" ? "active" : ""}`}
                onClick={() => handleModeSwitch("server")}
                title="Search via server (metadata only)"
              >
                🔍 Server
              </button>
            </div>
            {searchMode === "server" && (
              <button
                className={`search-filter-toggle ${showFilters ? "active" : ""}`}
                onClick={() => setShowFilters(!showFilters)}
                title="Toggle filters"
              >
                ⚙️ Filters
              </button>
            )}
            <button className="search-overlay-close" onClick={onClose}>×</button>
          </div>
        </div>

        <div className="search-overlay-body">
          <div className="search-controls">
            <div className="search-input-container">
              <input
                ref={searchInputRef}
                type="text"
                placeholder={searchMode === "local"
                  ? "Search loaded messages (decrypted locally)..."
                  : "Search messages... (content is searched after decryption)"}
                value={query}
                onChange={(e) => handleSearchInput(e.target.value)}
                className="search-input"
              />
              {isLoading && <div className="search-loading">🔍</div>}
            </div>
            {searchMode === "local" && (
              <div className="search-local-hint">
                Searching {currentMessages?.length || 0} loaded messages in current channel — decrypted locally, never sent to server
              </div>
            )}
          </div>

          {/* Active filter chips (server mode only) */}
          {searchMode === "server" && activeFilters.length > 0 && (
            <div className="search-filter-chips">
              {activeFilters.map(f => (
                <span key={f.type} className="search-chip">
                  {f.label}
                  <button className="search-chip-remove" onClick={() => removeFilter(f.type)}>×</button>
                </span>
              ))}
            </div>
          )}

          {/* Expandable filter panel (server mode only) */}
          {searchMode === "server" && showFilters && (
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
            {/* Local search results */}
            {searchMode === "local" && (
              <>
                {localResults.length === 0 && query.trim() && !isLoading && (
                  <div className="search-no-results">No messages found for &ldquo;{query}&rdquo; in loaded messages</div>
                )}
                {localResults.map((result, idx) => (
                  <div
                    key={result.message_id}
                    className={`search-result ${idx === selectedIndex ? "search-result-selected" : ""}`}
                    onClick={() => handleResultClick(result.channel_id, result.message_id)}
                  >
                    <div className="search-result-header">
                      <span className="search-result-icon" title="Searched locally (decrypted)">🔒</span>
                      <span className="search-result-sender">
                        {result.display_name || result.sender_public_key_hash?.slice(0, 16) || "Unknown"}
                      </span>
                      <span className="search-result-channel">#{result.channel_name}</span>
                      <span className="search-result-time">
                        {result.created_at ? new Date(result.created_at).toLocaleString() : ""}
                      </span>
                    </div>
                    <div className="search-result-snippet">
                      {highlightTerms(
                        result.decrypted_content.length > 200
                          ? result.decrypted_content.slice(0, 200) + "…"
                          : result.decrypted_content,
                        query
                      )}
                    </div>
                  </div>
                ))}
              </>
            )}

            {/* Server search results */}
            {searchMode === "server" && (
              <>
                {results.length === 0 && query.trim() && !isLoading && !error && (
                  <div className="search-no-results">No messages found for &ldquo;{query}&rdquo;</div>
                )}
                {results.map((result, idx) => (
                  <div
                    key={result.message_id}
                    className={`search-result ${idx === selectedIndex ? "search-result-selected" : ""}`}
                    onClick={() => handleResultClick(result.channel_id, result.message_id)}
                  >
                    <div className="search-result-header">
                      <span className="search-result-icon" title="Server search">🔍</span>
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
              </>
            )}
          </div>
        </div>

        <div className="search-overlay-footer">
          <span className="search-footer-hint">
            ↑↓ Navigate · Enter to jump · Esc to close
          </span>
          {activeResults.length > 0 && (
            <span className="search-result-count">{activeResults.length} result{activeResults.length !== 1 ? "s" : ""}</span>
          )}
        </div>
      </div>
    </div>
  );
};
