import React, { useCallback, useEffect, useRef, useState } from "react";

const TENOR_API_BASE = "https://tenor.googleapis.com/v2";
const GIF_KEY_STORAGE = "accord-tenor-api-key";
const SEARCH_DEBOUNCE_MS = 400;

interface TenorGif {
  id: string;
  title: string;
  media_formats: {
    tinygif?: { url: string; dims: [number, number] };
    gif?: { url: string; dims: [number, number] };
    nanogif?: { url: string; dims: [number, number] };
  };
}

interface TenorResponse {
  results: TenorGif[];
  next: string;
}

function getTenorApiKey(): string {
  try {
    return localStorage.getItem(GIF_KEY_STORAGE) || "";
  } catch {
    return "";
  }
}

function setTenorApiKey(key: string): void {
  localStorage.setItem(GIF_KEY_STORAGE, key);
}

async function fetchTenorGifs(
  apiKey: string,
  query: string,
  pos?: string
): Promise<TenorResponse | null> {
  const endpoint = query.trim() ? "search" : "featured";
  const params = new URLSearchParams({
    key: apiKey,
    client_key: "accord_chat",
    limit: "20",
    media_filter: "tinygif,gif",
  });
  if (query.trim()) params.set("q", query.trim());
  if (pos) params.set("pos", pos);

  try {
    const res = await fetch(`${TENOR_API_BASE}/${endpoint}?${params}`);
    if (!res.ok) return null;
    return (await res.json()) as TenorResponse;
  } catch {
    return null;
  }
}

function getGifUrl(gif: TenorGif, size: "thumb" | "full"): string {
  if (size === "thumb") {
    return gif.media_formats.tinygif?.url || gif.media_formats.nanogif?.url || gif.media_formats.gif?.url || "";
  }
  return gif.media_formats.gif?.url || gif.media_formats.tinygif?.url || "";
}

interface GifPickerProps {
  isOpen: boolean;
  onToggle: () => void;
  onSelect: (gifUrl: string) => void;
  onClose: () => void;
}

export const GifPickerButton: React.FC<GifPickerProps> = ({
  isOpen,
  onToggle,
  onSelect,
  onClose,
}) => {
  const pickerRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [gifs, setGifs] = useState<TenorGif[]>([]);
  const [nextPos, setNextPos] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [apiKey, setApiKeyState] = useState(getTenorApiKey);
  const [keyInput, setKeyInput] = useState("");

  // Debounce search
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [search]);

  // Fetch gifs when debounced search changes
  useEffect(() => {
    if (!isOpen || !apiKey) return;
    let cancelled = false;
    setLoading(true);
    setGifs([]);
    setNextPos(undefined);
    fetchTenorGifs(apiKey, debouncedSearch).then((res) => {
      if (cancelled) return;
      setLoading(false);
      if (res) {
        setGifs(res.results);
        setNextPos(res.next || undefined);
      }
    });
    return () => { cancelled = true; };
  }, [isOpen, apiKey, debouncedSearch]);

  // Click outside to close
  useEffect(() => {
    if (!isOpen) return;
    const handler = (e: MouseEvent) => {
      if (pickerRef.current && !pickerRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [isOpen, onClose]);

  // Escape to close
  useEffect(() => {
    if (!isOpen) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [isOpen, onClose]);

  // Focus search when opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => searchRef.current?.focus(), 50);
      setSearch("");
      setDebouncedSearch("");
    }
  }, [isOpen]);

  // Load more on scroll
  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el || loading || !nextPos || !apiKey) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 100) {
      setLoading(true);
      fetchTenorGifs(apiKey, debouncedSearch, nextPos).then((res) => {
        setLoading(false);
        if (res) {
          setGifs((prev) => [...prev, ...res.results]);
          setNextPos(res.next || undefined);
        }
      });
    }
  }, [loading, nextPos, apiKey, debouncedSearch]);

  const handleGifClick = useCallback(
    (gif: TenorGif) => {
      const url = getGifUrl(gif, "full");
      if (url) {
        onSelect(url);
        onClose();
      }
    },
    [onSelect, onClose]
  );

  const handleSaveKey = useCallback(() => {
    const trimmed = keyInput.trim();
    if (trimmed) {
      setTenorApiKey(trimmed);
      setApiKeyState(trimmed);
      setKeyInput("");
    }
  }, [keyInput]);

  return (
    <div className="gif-picker-wrapper" ref={pickerRef}>
      <button
        className="gif-picker-toggle"
        onClick={onToggle}
        title="GIF picker"
        type="button"
      >
        <span style={{ fontSize: "13px", fontWeight: 700, lineHeight: "24px" }}>GIF</span>
      </button>
      {isOpen && (
        <div className="gif-picker-popup">
          {!apiKey ? (
            <div className="gif-picker-no-key">
              <p style={{ margin: "0 0 8px", fontWeight: 600 }}>Tenor API Key Required</p>
              <p style={{ margin: "0 0 12px", fontSize: "13px", opacity: 0.8 }}>
                To use GIF search, you need a free Tenor API key.
                Visit{" "}
                <a
                  href="https://developers.google.com/tenor/guides/quickstart"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: "var(--accent)" }}
                >
                  Google Cloud Console
                </a>{" "}
                and enable the Tenor API to get your key.
              </p>
              <div style={{ display: "flex", gap: "6px" }}>
                <input
                  type="text"
                  placeholder="Paste your API key..."
                  value={keyInput}
                  onChange={(e) => setKeyInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleSaveKey();
                  }}
                  style={{
                    flex: 1,
                    padding: "6px 8px",
                    borderRadius: "4px",
                    border: "1px solid var(--border)",
                    background: "var(--bg-secondary)",
                    color: "var(--text-primary)",
                    fontSize: "13px",
                  }}
                />
                <button
                  onClick={handleSaveKey}
                  type="button"
                  style={{
                    padding: "6px 12px",
                    borderRadius: "4px",
                    border: "none",
                    background: "var(--accent)",
                    color: "#fff",
                    cursor: "pointer",
                    fontSize: "13px",
                    fontWeight: 600,
                  }}
                >
                  Save
                </button>
              </div>
            </div>
          ) : (
            <>
              <div className="gif-picker-search-row">
                <input
                  ref={searchRef}
                  className="gif-picker-search"
                  type="text"
                  placeholder="Search Tenor..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
              <div
                className="gif-picker-scroll"
                ref={scrollRef}
                onScroll={handleScroll}
              >
                {gifs.length === 0 && !loading && (
                  <div className="gif-picker-empty">
                    {debouncedSearch ? "No GIFs found" : "Loading trending GIFs..."}
                  </div>
                )}
                <div className="gif-picker-grid">
                  {gifs.map((gif) => (
                    <button
                      key={gif.id}
                      className="gif-picker-item"
                      onClick={() => handleGifClick(gif)}
                      type="button"
                      title={gif.title || "GIF"}
                    >
                      <img
                        src={getGifUrl(gif, "thumb")}
                        alt={gif.title || "GIF"}
                        loading="lazy"
                      />
                    </button>
                  ))}
                </div>
                {loading && (
                  <div className="gif-picker-loading">Loading...</div>
                )}
              </div>
              <div className="gif-picker-attribution">
                <img
                  src="https://www.gstatic.com/tenor/web/attribution/PB_tenor_logo_blue_horizontal.svg"
                  alt="Powered by Tenor"
                  height="16"
                />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};
