import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { api } from "./api";
import { decryptMessage, getChannelKey } from "./crypto";
import { Channel, Message } from "./types";
import { Icon } from "./components/Icon";

const PAGE_SIZE = 25;

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
  context_before?: string;
  context_after?: string;
}

type SearchMode = "server" | "local";

interface ParsedQuery {
  text: string;
  from?: string;
  in?: string;
  before?: string;
  after?: string;
  has?: string[];
}

/** Parse Discord-style filter syntax from a query string */
export function parseSearchQuery(raw: string): ParsedQuery {
  const has: string[] = [];
  let from: string | undefined;
  let inChannel: string | undefined;
  let before: string | undefined;
  let after: string | undefined;

  // Match filter tokens: key:value or key:"value with spaces"
  const filterRegex = /(?:^|\s)(from|in|before|after|has):(?:"([^"]+)"|(\S+))/gi;
  let remaining = raw;
  let match: RegExpExecArray | null;

  while ((match = filterRegex.exec(raw)) !== null) {
    const key = match[1].toLowerCase();
    const value = match[2] || match[3];
    switch (key) {
      case "from": from = value; break;
      case "in": inChannel = value; break;
      case "before": before = value; break;
      case "after": after = value; break;
      case "has": has.push(value.toLowerCase()); break;
    }
    remaining = remaining.replace(match[0], " ");
  }

  return {
    text: remaining.trim().replace(/\s+/g, " "),
    from,
    in: inChannel,
    before,
    after,
    has: has.length > 0 ? has : undefined,
  };
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

/** Check if a message has a certain attachment type */
function messageHasType(msg: Message, type: string): boolean {
  switch (type) {
    case "file": return !!(msg.files && msg.files.length > 0);
    case "image": return !!(msg.files && msg.files.some(f =>
      /\.(png|jpg|jpeg|gif|webp|svg)$/i.test(f.encrypted_filename || "")
    ));
    case "link": return /https?:\/\/\S+/.test(msg.content || "");
    default: return false;
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
  const [results, setResults] = useState<SearchResult[]>([]);
  const [localResults, setLocalResults] = useState<LocalSearchResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [showFilters, setShowFilters] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [searchMode, setSearchMode] = useState<SearchMode>("local");
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);

  // Server-mode manual filter state (used when showFilters panel is open)
  const [serverChannelId, setServerChannelId] = useState("");
  const [serverAuthor, setServerAuthor] = useState("");
  const [serverBefore, setServerBefore] = useState("");
  const [serverAfter, setServerAfter] = useState("");

  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchTimeoutRef = useRef<number | undefined>(undefined);
  const resultsRef = useRef<HTMLDivElement>(null);

  const parsed = useMemo(() => parseSearchQuery(query), [query]);

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
      setVisibleCount(PAGE_SIZE);
    }
  }, [isVisible]);

  // Local search through cached/loaded messages
  const performLocalSearch = useCallback((searchQuery: string) => {
    if (!currentMessages) {
      setLocalResults([]);
      return;
    }

    const p = parseSearchQuery(searchQuery);

    // If no text and no filters, clear results
    if (!p.text && !p.from && !p.in && !p.before && !p.after && !p.has) {
      setLocalResults([]);
      return;
    }

    const textLower = p.text.toLowerCase();
    const terms = textLower ? textLower.split(/\s+/).filter(Boolean) : [];
    const channelName = channels.find(c => c.id === currentChannelId)?.name || "";

    const matched: LocalSearchResult[] = [];
    for (let i = 0; i < currentMessages.length; i++) {
      const msg = currentMessages[i];
      const content = decryptedContentCache.get(msg.id) || msg.content || "";
      if (!content) continue;

      const contentLower = content.toLowerCase();
      const authorName = (msg.display_name || msg.author || "").toLowerCase();
      const senderId = (msg.sender_id || "").toLowerCase();

      // Text match: all terms must match in content or author
      if (terms.length > 0) {
        const allMatch = terms.every(term =>
          contentLower.includes(term) || authorName.includes(term)
        );
        if (!allMatch) continue;
      }

      // from: filter
      if (p.from) {
        const fromLower = p.from.toLowerCase();
        if (!authorName.includes(fromLower) && !senderId.includes(fromLower)) continue;
      }

      // in: filter (channel name)
      if (p.in) {
        const inLower = p.in.toLowerCase();
        if (!channelName.toLowerCase().includes(inLower)) continue;
      }

      // before: filter
      if (p.before) {
        const beforeTs = new Date(p.before).getTime();
        if (!isNaN(beforeTs) && msg.timestamp > beforeTs) continue;
      }

      // after: filter
      if (p.after) {
        const afterTs = new Date(p.after).getTime();
        if (!isNaN(afterTs) && msg.timestamp < afterTs) continue;
      }

      // has: filter
      if (p.has) {
        const allHas = p.has.every(h => messageHasType(msg, h));
        if (!allHas) continue;
      }

      // Context: grab 1 message before/after
      const prevMsg = i > 0 ? currentMessages[i - 1] : undefined;
      const nextMsg = i < currentMessages.length - 1 ? currentMessages[i + 1] : undefined;
      const contextBefore = prevMsg
        ? (decryptedContentCache.get(prevMsg.id) || prevMsg.content || "")
        : undefined;
      const contextAfter = nextMsg
        ? (decryptedContentCache.get(nextMsg.id) || nextMsg.content || "")
        : undefined;

      matched.push({
        message_id: msg.id,
        channel_id: msg.channel_id || currentChannelId || "",
        channel_name: channelName,
        sender_id: msg.sender_id || msg.author || "",
        sender_public_key_hash: msg.sender_public_key_hash || msg.author || "",
        created_at: msg.timestamp || 0,
        decrypted_content: content,
        display_name: msg.display_name,
        context_before: contextBefore ? (contextBefore.length > 120 ? contextBefore.slice(0, 120) + "…" : contextBefore) : undefined,
        context_after: contextAfter ? (contextAfter.length > 120 ? contextAfter.slice(0, 120) + "…" : contextAfter) : undefined,
      });
    }

    setLocalResults(matched);
    setSelectedIndex(-1);
    setVisibleCount(PAGE_SIZE);
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
      setVisibleCount(PAGE_SIZE);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
      setResults([]);
    } finally {
      setIsLoading(false);
    }
  }, [nodeId, token, encryptionEnabled, keyPair]);

  const triggerSearch = useCallback((
    q: string = query,
    ch: string = serverChannelId,
    au: string = serverAuthor,
    be: string = serverBefore,
    af: string = serverAfter,
  ) => {
    if (searchTimeoutRef.current) window.clearTimeout(searchTimeoutRef.current);
    searchTimeoutRef.current = window.setTimeout(() => {
      if (searchMode === "local") {
        performLocalSearch(q);
      } else {
        // For server mode, merge parsed inline filters with panel filters
        const p = parseSearchQuery(q);
        performServerSearch(
          p.text || q,
          p.in ? channels.find(c => c.name.toLowerCase() === p.in!.toLowerCase())?.id || ch : ch,
          p.from || au,
          p.before || be,
          p.after || af,
        );
      }
    }, 300);
  }, [query, serverChannelId, serverAuthor, serverBefore, serverAfter, performServerSearch, performLocalSearch, searchMode, channels]);

  const handleSearchInput = useCallback((value: string) => {
    setQuery(value);
    triggerSearch(value);
  }, [triggerSearch]);

  const handleModeSwitch = useCallback((mode: SearchMode) => {
    setSearchMode(mode);
    setResults([]);
    setLocalResults([]);
    setSelectedIndex(-1);
    setVisibleCount(PAGE_SIZE);
    if (query.trim()) {
      if (searchTimeoutRef.current) window.clearTimeout(searchTimeoutRef.current);
      searchTimeoutRef.current = window.setTimeout(() => {
        if (mode === "local") {
          performLocalSearch(query);
        } else {
          performServerSearch(query, serverChannelId, serverAuthor, serverBefore, serverAfter);
        }
      }, 100);
    }
  }, [query, serverChannelId, serverAuthor, serverBefore, serverAfter, performLocalSearch, performServerSearch]);

  const handleResultClick = (channelId: string, messageId: string) => {
    onNavigateToMessage(channelId, messageId);
    onClose();
  };

  // Active result list for keyboard nav
  const activeResults = searchMode === "local" ? localResults : results;
  const paginatedResults = activeResults.slice(0, visibleCount);
  const hasMore = activeResults.length > visibleCount;

  // Keyboard navigation
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex(i => Math.min(i + 1, paginatedResults.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex(i => Math.max(i - 1, -1));
    } else if (e.key === "Enter" && selectedIndex >= 0 && paginatedResults[selectedIndex]) {
      e.preventDefault();
      const r = paginatedResults[selectedIndex];
      handleResultClick(
        "channel_id" in r ? r.channel_id : "",
        "message_id" in r ? r.message_id : "",
      );
    }
  }, [paginatedResults, selectedIndex]);

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

  /** Remove an inline filter from the query string */
  const removeInlineFilter = useCallback((key: string, value?: string) => {
    let newQuery = query;
    if (value) {
      // Remove specific has:value
      newQuery = newQuery.replace(new RegExp(`\\s*${key}:(?:"${value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"|${value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi"), "");
    } else {
      newQuery = newQuery.replace(new RegExp(`\\s*${key}:(?:"[^"]+"|\\S+)`, "gi"), "");
    }
    newQuery = newQuery.trim();
    setQuery(newQuery);
    triggerSearch(newQuery);
  }, [query, triggerSearch]);

  const removeServerFilter = (type: string) => {
    switch (type) {
      case "channel": setServerChannelId(""); triggerSearch(query, "", serverAuthor, serverBefore, serverAfter); break;
      case "author": setServerAuthor(""); triggerSearch(query, serverChannelId, "", serverBefore, serverAfter); break;
      case "before": setServerBefore(""); triggerSearch(query, serverChannelId, serverAuthor, "", serverAfter); break;
      case "after": setServerAfter(""); triggerSearch(query, serverChannelId, serverAuthor, serverBefore, ""); break;
    }
  };

  if (!isVisible) return null;

  // Build filter chips from parsed query (local mode) or manual filters (server mode)
  const inlineFilterChips: Array<{ key: string; value?: string; label: string }> = [];
  if (parsed.from) inlineFilterChips.push({ key: "from", label: `from:${parsed.from}` });
  if (parsed.in) inlineFilterChips.push({ key: "in", label: `in:${parsed.in}` });
  if (parsed.before) inlineFilterChips.push({ key: "before", label: `before:${parsed.before}` });
  if (parsed.after) inlineFilterChips.push({ key: "after", label: `after:${parsed.after}` });
  if (parsed.has) {
    for (const h of parsed.has) {
      inlineFilterChips.push({ key: "has", value: h, label: `has:${h}` });
    }
  }

  const serverFilterChips = searchMode === "server" ? [
    serverChannelId && { type: "channel", label: `In: #${channels.find(c => c.id === serverChannelId)?.name || "..."}` },
    serverAuthor && { type: "author", label: `From: ${serverAuthor.slice(0, 8)}...` },
    serverBefore && { type: "before", label: `Before: ${serverBefore}` },
    serverAfter && { type: "after", label: `After: ${serverAfter}` },
  ].filter(Boolean) as Array<{ type: string; label: string }> : [];

  const searchText = parsed.text;

  return (
    <div className="search-overlay" onKeyDown={handleKeyDown}>
      <div className="search-overlay-backdrop" onClick={onClose} />
      <div className="search-overlay-content">
        <div className="search-overlay-header">
          <h3>Search Messages</h3>
          <div className="search-header-actions">
            <div className="search-mode-tabs">
              <button
                className={`search-mode-tab ${searchMode === "local" ? "active" : ""}`}
                onClick={() => handleModeSwitch("local")}
                title="Search decrypted messages locally"
              >
                Local
              </button>
              <button
                className={`search-mode-tab ${searchMode === "server" ? "active" : ""}`}
                onClick={() => handleModeSwitch("server")}
                title="Search via server (metadata only)"
              >
                Server
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
              <span className="search-input-icon"><Icon name="search" size={16} /></span>
              <input
                ref={searchInputRef}
                type="text"
                placeholder={searchMode === "local"
                  ? "Search loaded messages... (try from:name has:link)"
                  : "Search messages... (try from:name before:2026-01-01)"}
                value={query}
                onChange={(e) => handleSearchInput(e.target.value)}
                className="search-input"
              />
              {isLoading && <div className="search-loading">Searching...</div>}
            </div>
            {searchMode === "local" && (
              <div className="search-local-hint">
                Searching {currentMessages?.length || 0} loaded messages in current channel — decrypted locally, never sent to server
              </div>
            )}
          </div>

          {/* Inline filter chips (parsed from query) */}
          {inlineFilterChips.length > 0 && (
            <div className="search-filter-chips">
              {inlineFilterChips.map((f, i) => (
                <span key={`${f.key}-${f.value || i}`} className="search-chip">
                  {f.label}
                  <button className="search-chip-remove" onClick={() => removeInlineFilter(f.key, f.value)}>×</button>
                </span>
              ))}
            </div>
          )}

          {/* Server-mode manual filter chips */}
          {searchMode === "server" && serverFilterChips.length > 0 && (
            <div className="search-filter-chips">
              {serverFilterChips.map(f => (
                <span key={f.type} className="search-chip">
                  {f.label}
                  <button className="search-chip-remove" onClick={() => removeServerFilter(f.type)}>×</button>
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
                  value={serverChannelId}
                  onChange={(e) => { setServerChannelId(e.target.value); triggerSearch(query, e.target.value, serverAuthor, serverBefore, serverAfter); }}
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
                  value={serverAuthor}
                  onChange={(e) => { setServerAuthor(e.target.value); triggerSearch(query, serverChannelId, e.target.value, serverBefore, serverAfter); }}
                  className="search-filter-input"
                />
              </div>
              <div className="search-filter-row">
                <label>After:</label>
                <input
                  type="date"
                  value={serverAfter}
                  onChange={(e) => { setServerAfter(e.target.value); triggerSearch(query, serverChannelId, serverAuthor, serverBefore, e.target.value); }}
                  className="search-filter-input"
                />
              </div>
              <div className="search-filter-row">
                <label>Before:</label>
                <input
                  type="date"
                  value={serverBefore}
                  onChange={(e) => { setServerBefore(e.target.value); triggerSearch(query, serverChannelId, serverAuthor, e.target.value, serverAfter); }}
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
                {(paginatedResults as LocalSearchResult[]).map((result, idx) => (
                  <div
                    key={result.message_id}
                    className={`search-result ${idx === selectedIndex ? "search-result-selected" : ""}`}
                    onClick={() => handleResultClick(result.channel_id, result.message_id)}
                  >
                    {result.context_before && (
                      <div className="search-result-context search-result-context-before">
                        {result.context_before}
                      </div>
                    )}
                    <div className="search-result-header">
                      <span className="search-result-icon" title="Searched locally (decrypted)">⚿</span>
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
                        searchText
                      )}
                    </div>
                    {result.context_after && (
                      <div className="search-result-context search-result-context-after">
                        {result.context_after}
                      </div>
                    )}
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
                {(paginatedResults as SearchResult[]).map((result, idx) => (
                  <div
                    key={result.message_id}
                    className={`search-result ${idx === selectedIndex ? "search-result-selected" : ""}`}
                    onClick={() => handleResultClick(result.channel_id, result.message_id)}
                  >
                    <div className="search-result-header">
                      <span className="search-result-icon" title="Server search">⚿</span>
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
                            searchText
                          )
                        : <em className="search-encrypted-hint">Encrypted — click to view</em>
                      }
                    </div>
                  </div>
                ))}
              </>
            )}

            {/* Load more button */}
            {hasMore && (
              <button
                className="search-load-more"
                onClick={() => setVisibleCount(c => c + PAGE_SIZE)}
              >
                Load more ({activeResults.length - visibleCount} remaining)
              </button>
            )}
          </div>
        </div>

        <div className="search-overlay-footer">
          <span className="search-footer-hint">
            ↑↓ Navigate · Enter to jump · Esc to close
          </span>
          {activeResults.length > 0 && (
            <span className="search-result-count">
              {activeResults.length} result{activeResults.length !== 1 ? "s" : ""}
              {hasMore && ` (showing ${visibleCount})`}
            </span>
          )}
        </div>
      </div>
    </div>
  );
};
