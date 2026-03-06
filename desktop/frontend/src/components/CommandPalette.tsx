import React, { useState, useEffect, useRef, useMemo } from "react";
import { useAppContext } from "./AppContext";
import { getSavedTheme, applyTheme, themes } from "../themes";
import "../styles/command-palette.css";

interface PaletteItem {
  id: string;
  name: string;
  icon: string;
  category: "Channel" | "User" | "Action";
  action: () => void;
}

/** Simple fuzzy match: all query chars appear in order in target (case-insensitive). */
function fuzzyMatch(query: string, target: string): boolean {
  const q = query.toLowerCase();
  const t = target.toLowerCase();
  let qi = 0;
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) qi++;
  }
  return qi === q.length;
}

export const CommandPalette: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const ctx = useAppContext();
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  // Focus input on open
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // Build items list from context
  const items = useMemo<PaletteItem[]>(() => {
    const list: PaletteItem[] = [];

    // Channels
    for (const ch of ctx.channels) {
      if (typeof ch.channel_type === "string" && ch.channel_type === "category") continue;
      if (typeof ch.channel_type === "number" && ch.channel_type === 4) continue;
      list.push({
        id: `ch-${ch.id}`,
        name: ch.name,
        icon: typeof ch.channel_type === "string" && ch.channel_type === "voice" ? "🔊" : "#",
        category: "Channel",
        action: () => { ctx.handleChannelSelect(ch.id, ch.name); onClose(); },
      });
    }

    // Users (members of current node)
    for (const m of ctx.sortedMembers) {
      const name = m.user?.display_name || m.profile?.display_name || m.user_id.substring(0, 8);
      list.push({
        id: `user-${m.user_id}`,
        name,
        icon: "👤",
        category: "User",
        action: () => { if (m.user) ctx.openDmWithUser(m.user); onClose(); },
      });
    }

    // Actions
    list.push(
      { id: "act-settings", name: "Open Settings", icon: "⚙️", category: "Action", action: () => { ctx.setShowSettings(true); onClose(); } },
      { id: "act-create-node", name: "Create Node", icon: "➕", category: "Action", action: () => { ctx.setShowCreateNodeModal(true); onClose(); } },
      { id: "act-join-node", name: "Join Node", icon: "📥", category: "Action", action: () => { ctx.setShowJoinNodeModal(true); onClose(); } },
      { id: "act-toggle-theme", name: "Toggle Theme", icon: "🎨", category: "Action", action: () => {
        const current = getSavedTheme();
        const names = Object.keys(themes);
        const idx = names.indexOf(current);
        const next = names[(idx + 1) % names.length];
        applyTheme(next);
        onClose();
      }},
    );

    return list;
  }, [ctx.channels, ctx.sortedMembers, onClose]);

  const filtered = useMemo(() => {
    if (!query) return items;
    return items.filter(it => fuzzyMatch(query, it.name));
  }, [items, query]);

  // Reset active index when results change
  useEffect(() => { setActiveIndex(0); }, [filtered.length]);

  // Scroll active item into view
  useEffect(() => {
    const el = resultsRef.current?.querySelector(".cp-active");
    el?.scrollIntoView({ block: "nearest" });
  }, [activeIndex]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIndex(i => (i + 1) % Math.max(filtered.length, 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIndex(i => (i - 1 + filtered.length) % Math.max(filtered.length, 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (filtered[activeIndex]) filtered[activeIndex].action();
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  // Group filtered by category for display
  const grouped = useMemo(() => {
    const map = new Map<string, PaletteItem[]>();
    for (const item of filtered) {
      const arr = map.get(item.category) || [];
      arr.push(item);
      map.set(item.category, arr);
    }
    return map;
  }, [filtered]);

  let runningIndex = 0;

  return (
    <div className="command-palette-overlay" onClick={onClose}>
      <div className="command-palette" onClick={e => e.stopPropagation()} onKeyDown={handleKeyDown} role="dialog" aria-modal="true" aria-label="Command Palette">
        <div className="command-palette-input-wrap">
          <span className="cp-search-icon">🔍</span>
          <input
            ref={inputRef}
            className="command-palette-input"
            placeholder="Type a command or search…"
            value={query}
            onChange={e => setQuery(e.target.value)}
            aria-label="Command palette search"
          />
        </div>
        <div className="command-palette-results" ref={resultsRef}>
          {filtered.length === 0 && (
            <div className="command-palette-empty">No results found</div>
          )}
          {Array.from(grouped.entries()).map(([category, items]) => {
            const section = (
              <React.Fragment key={category}>
                <div className="cp-category-label">{category}</div>
                {items.map(item => {
                  const idx = runningIndex++;
                  return (
                    <div
                      key={item.id}
                      className={`cp-result-item${idx === activeIndex ? " cp-active" : ""}`}
                      onClick={() => item.action()}
                      onMouseEnter={() => setActiveIndex(idx)}
                    >
                      <span className="cp-icon">{item.icon}</span>
                      <span className="cp-name">{item.name}</span>
                      <span className="cp-badge">{item.category}</span>
                    </div>
                  );
                })}
              </React.Fragment>
            );
            return section;
          })}
        </div>
        <div className="command-palette-footer">
          <span><kbd>↑↓</kbd> navigate</span>
          <span><kbd>↵</kbd> select</span>
          <span><kbd>esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
};
