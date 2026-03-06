import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CustomEmoji } from "./types";

// ── Emoji data by category ──────────────────────────────────────────────
const CATEGORIES: { id: string; name: string; icon: string; emojis: string[] }[] = [
  {
    id: "recent", name: "Recently Used", icon: "🕐", emojis: [], // filled at runtime
  },
  {
    id: "smileys", name: "Smileys & Emotion", icon: "😀",
    emojis: [
      "😀","😃","😄","😁","😆","😅","🤣","😂","🙂","🙃","😉","😊","😇","🥰","😍","🤩",
      "😘","😗","😚","😙","🥲","😋","😛","😜","🤪","😝","🤑","🤗","🤭","🫢","🫣","🤫",
      "🤔","🫡","🤐","🤨","😐","😑","😶","🫥","😏","😒","🙄","😬","🤥","😌","😔","😪",
      "🤤","😴","😷","🤒","🤕","🤢","🤮","🥵","🥶","🥴","😵","🤯","🤠","🥳","🥸","😎",
      "🤓","🧐","😕","🫤","😟","🙁","😮","😯","😲","😳","🥺","🥹","😦","😧","😨","😰",
      "😥","😢","😭","😱","😖","😣","😞","😓","😩","😫","🥱","😤","😡","😠","🤬","😈",
      "👿","💀","☠️","💩","🤡","👹","👺","👻","👽","👾","🤖","😺","😸","😹","😻","😼",
      "😽","🙀","😿","😾","❤️","🧡","💛","💚","💙","💜","🖤","🤍","🤎","💔","❤️‍🔥","❤️‍🩹",
      "💖","💗","💓","💞","💕","💟","❣️","💋","💯","💢","💥","💫","💦","💨","🕳️","💣",
    ],
  },
  {
    id: "people", name: "People & Body", icon: "👋",
    emojis: [
      "👋","🤚","🖐️","✋","🖖","🫱","🫲","🫳","🫴","👌","🤌","🤏","✌️","🤞","🫰","🤟",
      "🤘","🤙","👈","👉","👆","🖕","👇","☝️","🫵","👍","👎","✊","👊","🤛","🤜","👏",
      "🙌","🫶","👐","🤲","🤝","🙏","✍️","💅","🤳","💪","🦾","🦿","🦵","🦶","👂","🦻",
      "👃","🧠","🫀","🫁","🦷","🦴","👀","👁️","👅","👄","🫦","👶","🧒","👦","👧","🧑",
      "👱","👨","🧔","👩","🧓","👴","👵","🙍","🙎","🙅","🙆","💁","🙋","🧏","🙇","🤦",
      "🤷","👮","🕵️","💂","🥷","👷","🫅","🤴","👸","👳","👲","🧕","🤵","👰","🤰","🫃",
    ],
  },
  {
    id: "animals", name: "Animals & Nature", icon: "🐻",
    emojis: [
      "🐶","🐱","🐭","🐹","🐰","🦊","🐻","🐼","🐻‍❄️","🐨","🐯","🦁","🐮","🐷","🐸","🐵",
      "🙈","🙉","🙊","🐒","🐔","🐧","🐦","🐤","🐣","🐥","🦆","🦅","🦉","🦇","🐺","🐗",
      "🐴","🦄","🐝","🪱","🐛","🦋","🐌","🐞","🐜","🪰","🪲","🪳","🦟","🦗","🕷️","🦂",
      "🐢","🐍","🦎","🦖","🦕","🐙","🦑","🦐","🦞","🦀","🐡","🐠","🐟","🐬","🐳","🐋",
      "🦈","🐊","🐅","🐆","🦓","🦍","🦧","🐘","🦛","🦏","🐪","🐫","🦒","🦘","🦬","🐃",
      "🐂","🐄","🐎","🐖","🐏","🐑","🦙","🐐","🦌","🐕","🐩","🦮","🐕‍🦺","🐈","🐈‍⬛","🪶",
      "🐓","🦃","🦤","🦚","🦜","🦢","🦩","🕊️","🐇","🦝","🦨","🦡","🦫","🦦","🦥","🐁",
      "🐀","🐿️","🦔","🌵","🎄","🌲","🌳","🌴","🪵","🌱","🌿","☘️","🍀","🎍","🎋","🍃",
      "🍂","🍁","🌾","🪻","🌺","🌻","🌹","🥀","🌷","🌼","🌸","💐","🍄","🌰","🪸","🪨",
    ],
  },
  {
    id: "food", name: "Food & Drink", icon: "🍔",
    emojis: [
      "🍇","🍈","🍉","🍊","🍋","🍌","🍍","🥭","🍎","🍏","🍐","🍑","🍒","🍓","🫐","🥝",
      "🍅","🫒","🥥","🥑","🍆","🥔","🥕","🌽","🌶️","🫑","🥒","🥬","🥦","🧄","🧅","🥜",
      "🫘","🌰","🍞","🥐","🥖","🫓","🥨","🥯","🥞","🧇","🧀","🍖","🍗","🥩","🥓","🍔",
      "🍟","🍕","🌭","🥪","🌮","🌯","🫔","🥙","🧆","🥚","🍳","🥘","🍲","🫕","🥣","🥗",
      "🍿","🧈","🧂","🥫","🍱","🍘","🍙","🍚","🍛","🍜","🍝","🍠","🍢","🍣","🍤","🍥",
      "🥮","🍡","🥟","🥠","🥡","🦀","🦞","🦐","🦑","🦪","🍦","🍧","🍨","🍩","🍪","🎂",
      "🍰","🧁","🥧","🍫","🍬","🍭","🍮","🍯","🍼","🥛","☕","🫖","🍵","🍶","🍾","🍷",
      "🍸","🍹","🍺","🍻","🥂","🥃","🫗","🥤","🧋","🧃","🧉","🧊",
    ],
  },
  {
    id: "travel", name: "Travel & Places", icon: "✈️",
    emojis: [
      "🚗","🚕","🚙","🚌","🚎","🏎️","🚓","🚑","🚒","🚐","🛻","🚚","🚛","🚜","🏍️","🛵",
      "🛺","🚲","🛴","🛹","🛼","🚏","🛣️","🛤️","⛽","🛞","🚨","🚥","🚦","🛑","🚧","⚓",
      "🛟","⛵","🚤","🛳️","⛴️","🛥️","🚢","✈️","🛩️","🛫","🛬","🪂","💺","🚁","🚟","🚠",
      "🚡","🛰️","🚀","🛸","🌍","🌎","🌏","🗺️","🧭","🏔️","⛰️","🌋","🗻","🏕️","🏖️","🏜️",
      "🏝️","🏞️","🏟️","🏛️","🏗️","🧱","🪨","🪵","🛖","🏘️","🏚️","🏠","🏡","🏢","🏣","🏤",
      "🏥","🏦","🏨","🏩","🏪","🏫","🏬","🏭","🏯","🏰","💒","🗼","🗽","⛪","🕌","🛕",
      "🕍","⛩️","🕋","⛲","⛺","🌁","🌃","🏙️","🌄","🌅","🌆","🌇","🌉","♨️","🎠","🛝",
      "🎡","🎢","💈","🎪","🗾","🎑","🎆","🎇","🧨","✨","🎏","🎐","🎀","🎁","🎗️",
    ],
  },
  {
    id: "activities", name: "Activities", icon: "⚽",
    emojis: [
      "⚽","🏀","🏈","⚾","🥎","🎾","🏐","🏉","🥏","🎱","🪀","🏓","🏸","🏒","🏑","🥍",
      "🏏","🪃","🥅","⛳","🪁","🏹","🎣","🤿","🥊","🥋","🎽","🛹","🛼","🛷","⛸️","🥌",
      "🎿","⛷️","🏂","🪂","🏋️","🤼","🤸","🤺","⛹️","🤾","🏌️","🏇","🧘","🏄","🏊","🤽",
      "🚣","🧗","🚵","🚴","🏆","🥇","🥈","🥉","🏅","🎖️","🏵️","🎗️","🎪","🎭","🎨","🎬",
      "🎤","🎧","🎼","🎹","🥁","🪘","🎷","🎺","🪗","🎸","🪕","🎻","🎲","♟️","🎯","🎳",
      "🎮","🕹️","🧩","🪅","🪩","🪆",
    ],
  },
  {
    id: "objects", name: "Objects", icon: "💡",
    emojis: [
      "👓","🕶️","🥽","🥼","🦺","👔","👕","👖","🧣","🧤","🧥","🧦","👗","👘","🥻","🩱",
      "🩲","🩳","👙","👚","👛","👜","👝","🛍️","🎒","🩴","👞","👟","🥾","🥿","👠","👡",
      "🩰","👢","👑","👒","🎩","🎓","🧢","🪖","⛑️","📿","💄","💍","💎","📱","📲","💻",
      "⌨️","🖥️","🖨️","🖱️","🖲️","🕹️","🗜️","💾","💿","📀","📼","📷","📸","📹","🎥","📽️",
      "🎞️","📞","☎️","📟","📠","📺","📻","🎙️","🎚️","🎛️","🧭","⏱️","⏲️","⏰","🕰️","⌛",
      "⏳","📡","🔋","🪫","🔌","💡","🔦","🕯️","🪔","🧯","🛢️","💰","🪙","💴","💵","💶",
      "💷","🪪","💳","💸","✉️","📧","📨","📩","📤","📥","📦","📫","📪","📬","📭","📮",
      "🗳️","✏️","✒️","🖋️","🖊️","🖌️","🖍️","📝","💼","📁","📂","🗂️","📅","📆","📇","📈",
      "📉","📊","📋","📌","📍","📎","🖇️","📏","📐","✂️","🗃️","🗄️","🗑️","🔒","🔓","🔏",
      "🔐","🔑","🗝️","🔨","🪓","⛏️","⚒️","🛠️","🗡️","⚔️","💣","🪃","🏹","🛡️","🪚","🔧",
      "🪛","🔩","⚙️","🗜️","⚖️","🦯","🔗","⛓️","🪝","🧰","🧲","🪜","⚗️","🧪","🧫","🧬",
      "🔬","🔭","📡","💉","🩸","💊","🩹","🩼","🩺","🩻","🚪","🛗","🪞","🪟","🛏️","🛋️",
    ],
  },
  {
    id: "symbols", name: "Symbols", icon: "💠",
    emojis: [
      "❤️","🧡","💛","💚","💙","💜","🖤","🤍","🤎","💔","❤️‍🔥","❤️‍🩹","❣️","💕","💞","💓",
      "💗","💖","💘","💝","⭐","🌟","✨","⚡","🔥","💥","☄️","🌈","☀️","🌤️","⛅","🌥️",
      "🌦️","🌧️","⛈️","🌩️","🌪️","🌫️","🌊","💧","💦","☔","☂️","🔱","⚜️","🔰","♻️","✅",
      "❌","❓","❔","‼️","⁉️","⚠️","🚫","🔞","📵","🔇","🔕","🚷","🚯","🚳","🚱","🔅",
      "🔆","〽️","⚠️","🚸","♿","🅿️","🈳","🈂️","🛂","🛃","🛄","🛅","🚮","🚰","♻️","🔣",
      "ℹ️","🔤","🔡","🔠","🆎","🆑","🆒","🆓","🆔","🆕","🆖","🆗","🆘","🆙","🆚","🈁",
      "🔴","🟠","🟡","🟢","🔵","🟣","⚫","⚪","🟤","🔺","🔻","🔸","🔹","🔶","🔷","💠",
      "🔘","🔳","🔲","▪️","▫️","◾","◽","◼️","◻️","🟥","🟧","🟨","🟩","🟦","🟪","⬛","⬜",
    ],
  },
  {
    id: "flags", name: "Flags", icon: "🏁",
    emojis: [
      "🏁","🚩","🎌","🏴","🏳️","🏳️‍🌈","🏳️‍⚧️","🏴‍☠️","🇺🇸","🇬🇧","🇨🇦","🇦🇺","🇩🇪","🇫🇷","🇪🇸","🇮🇹",
      "🇯🇵","🇰🇷","🇨🇳","🇮🇳","🇧🇷","🇲🇽","🇷🇺","🇳🇱","🇸🇪","🇳🇴","🇩🇰","🇫🇮","🇵🇱","🇹🇷","🇿🇦","🇦🇷",
      "🇨🇴","🇨🇱","🇵🇪","🇪🇬","🇳🇬","🇰🇪","🇮🇱","🇸🇦","🇦🇪","🇹🇭","🇻🇳","🇮🇩","🇵🇭","🇲🇾","🇸🇬","🇳🇿",
      "🇮🇪","🇨🇭","🇦🇹","🇧🇪","🇵🇹","🇬🇷","🇨🇿","🇷🇴","🇭🇺","🇺🇦","🇪🇺",
    ],
  },
];

// Skin tone modifiers
const SKIN_TONES = [
  { label: "Default", modifier: "" },
  { label: "Light", modifier: "\u{1F3FB}" },
  { label: "Medium-Light", modifier: "\u{1F3FC}" },
  { label: "Medium", modifier: "\u{1F3FD}" },
  { label: "Medium-Dark", modifier: "\u{1F3FE}" },
  { label: "Dark", modifier: "\u{1F3FF}" },
];

const SKIN_TONE_BASES = new Set([
  "👋","🤚","🖐️","✋","🖖","🫱","🫲","🫳","🫴","👌","🤌","🤏","✌️","🤞","🫰","🤟",
  "🤘","🤙","👈","👉","👆","🖕","👇","☝️","🫵","👍","👎","✊","👊","🤛","🤜","👏",
  "🙌","🫶","👐","🤲","🤝","🙏","✍️","💅","🤳","💪","👂","👃","👶","🧒","👦","👧",
  "🧑","👱","👨","🧔","👩","🧓","👴","👵","👮","💂","👷","🤴","👸","👳","👲","🤵","👰",
  "🤰","🫃","🎅","🤶","🦸","🦹","🧙","🧚","🧛","🧜","🧝","🧞","🧟","💆","💇","🚶",
  "🧍","🧎","🏃","💃","🕺","🕴️","👯","🧖","🧗","🏇","⛷️","🏂","🏌️","🏄","🚣","🏊",
  "⛹️","🏋️","🚴","🚵","🤸","🤽","🤾","🤺","🤹","🧘","🛀","🛌",
]);

const RECENT_KEY = "accord-emoji-recent";
const MAX_RECENT = 24;
const SKIN_TONE_KEY = "accord-emoji-skin-tone";

function getRecentEmojis(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.slice(0, MAX_RECENT) : [];
  } catch { return []; }
}

function addRecentEmoji(emoji: string): void {
  const recent = getRecentEmojis().filter(e => e !== emoji);
  recent.unshift(emoji);
  localStorage.setItem(RECENT_KEY, JSON.stringify(recent.slice(0, MAX_RECENT)));
}

function getSavedSkinTone(): number {
  try {
    const v = localStorage.getItem(SKIN_TONE_KEY);
    return v ? parseInt(v, 10) || 0 : 0;
  } catch { return 0; }
}

function applySkintone(emoji: string, toneIndex: number): string {
  if (toneIndex === 0 || !SKIN_TONE_BASES.has(emoji)) return emoji;
  return emoji + SKIN_TONES[toneIndex].modifier;
}

interface EmojiPickerProps {
  onSelect: (emoji: string) => void;
  onClose: () => void;
  customEmojis?: CustomEmoji[];
  getEmojiUrl?: (hash: string) => string;
}

export const EmojiPickerButton: React.FC<EmojiPickerProps & { isOpen: boolean; onToggle: () => void }> = ({
  isOpen, onToggle, onSelect, onClose, customEmojis, getEmojiUrl,
}) => {
  const pickerRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const [search, setSearch] = useState("");
  const [activeCategory, setActiveCategory] = useState("smileys");
  const [skinTone, setSkinTone] = useState(getSavedSkinTone);
  const [showSkinTones, setShowSkinTones] = useState(false);
  const categoryRefs = useRef<Record<string, HTMLDivElement | null>>({});

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
      if (e.key === "Escape") { onClose(); }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [isOpen, onClose]);

  // Focus search when opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => searchRef.current?.focus(), 50);
      setSearch("");
    }
  }, [isOpen]);

  const recentEmojis = useMemo(() => isOpen ? getRecentEmojis() : [], [isOpen]);

  const categories = useMemo(() => {
    const cats = CATEGORIES.map(c =>
      c.id === "recent" ? { ...c, emojis: recentEmojis } : c
    );
    // Filter out empty recent
    return cats.filter(c => c.id !== "recent" || c.emojis.length > 0);
  }, [recentEmojis]);

  const filteredCategories = useMemo(() => {
    if (!search.trim()) return categories;
    const q = search.toLowerCase();
    // Simple search: filter emojis that... well, we match category names and just show all matching
    // Since we don't have emoji names, we'll filter categories that match and show all emojis from matching categories
    // Or just search across all emojis - since emojis are unicode, searching by name is hard without a name map.
    // We'll filter by category name match, which is useful enough.
    const results: typeof categories = [];
    for (const cat of categories) {
      if (cat.id === "recent") continue;
      if (cat.name.toLowerCase().includes(q)) {
        results.push(cat);
      }
    }
    // If no category match, show all (no filter possible without names)
    if (results.length === 0) {
      return categories.filter(c => c.id !== "recent");
    }
    return results;
  }, [search, categories]);

  const handleSelect = useCallback((emoji: string) => {
    const withTone = applySkintone(emoji, skinTone);
    addRecentEmoji(withTone);
    onSelect(withTone);
  }, [onSelect, skinTone]);

  const handleSkinToneSelect = useCallback((index: number) => {
    setSkinTone(index);
    localStorage.setItem(SKIN_TONE_KEY, String(index));
    setShowSkinTones(false);
  }, []);

  const handleCategoryClick = useCallback((catId: string) => {
    setActiveCategory(catId);
    setSearch("");
    const el = categoryRefs.current[catId];
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const container = e.currentTarget;
    const scrollTop = container.scrollTop;
    let closest = categories[0]?.id || "smileys";
    for (const cat of categories) {
      const el = categoryRefs.current[cat.id];
      if (el && el.offsetTop <= scrollTop + 40) {
        closest = cat.id;
      }
    }
    setActiveCategory(closest);
  }, [categories]);

  return (
    <div className="emoji-picker-wrapper" ref={pickerRef}>
      <button className="emoji-picker-toggle" onClick={onToggle} title="Emoji picker" type="button">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.47 2 2 6.47 2 12s4.47 10 10 10 10-4.47 10-10S17.53 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm3.5-9c.83 0 1.5-.67 1.5-1.5S16.33 8 15.5 8 14 8.67 14 9.5s.67 1.5 1.5 1.5zm-7 0c.83 0 1.5-.67 1.5-1.5S9.33 8 8.5 8 7 8.67 7 9.5 7.67 11 8.5 11zm3.5 6.5c2.33 0 4.31-1.46 5.11-3.5H6.89c.8 2.04 2.78 3.5 5.11 3.5z"/>
        </svg>
      </button>
      {isOpen && (
        <div className="emoji-picker-popup">
          {/* Search bar */}
          <div className="emoji-picker-search-row">
            <input
              ref={searchRef}
              className="emoji-picker-search"
              type="text"
              placeholder="Search categories..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
            {/* Skin tone selector */}
            <div className="emoji-skin-tone-wrapper">
              <button
                className="emoji-skin-tone-btn"
                onClick={() => setShowSkinTones(v => !v)}
                title="Skin tone"
                type="button"
              >
                {skinTone === 0 ? "👋" : "👋" + SKIN_TONES[skinTone].modifier}
              </button>
              {showSkinTones && (
                <div className="emoji-skin-tone-dropdown">
                  {SKIN_TONES.map((tone, i) => (
                    <button
                      key={i}
                      className={`emoji-skin-tone-option${i === skinTone ? " active" : ""}`}
                      onClick={() => handleSkinToneSelect(i)}
                      type="button"
                      title={tone.label}
                    >
                      {i === 0 ? "👋" : "👋" + tone.modifier}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Category tabs */}
          <div className="emoji-picker-tabs">
            {categories.map(cat => (
              <button
                key={cat.id}
                className={`emoji-picker-tab${activeCategory === cat.id ? " active" : ""}`}
                onClick={() => handleCategoryClick(cat.id)}
                title={cat.name}
                type="button"
              >
                {cat.icon}
              </button>
            ))}
            {customEmojis && customEmojis.length > 0 && (
              <button
                className={`emoji-picker-tab${activeCategory === "custom" ? " active" : ""}`}
                onClick={() => handleCategoryClick("custom")}
                title="Custom"
                type="button"
              >
                ⭐
              </button>
            )}
          </div>

          {/* Emoji grid */}
          <div className="emoji-picker-scroll" onScroll={handleScroll}>
            {filteredCategories.map(cat => (
              <div key={cat.id} ref={el => { categoryRefs.current[cat.id] = el; }}>
                <div className="emoji-picker-category-label">{cat.name}</div>
                <div className="emoji-picker-grid">
                  {cat.emojis.map((emoji, i) => (
                    <button
                      key={`${emoji}-${i}`}
                      className="emoji-picker-item"
                      onClick={() => handleSelect(emoji)}
                      type="button"
                      title={emoji}
                    >
                      {applySkintone(emoji, skinTone)}
                    </button>
                  ))}
                </div>
              </div>
            ))}

            {/* Custom emojis */}
            {customEmojis && customEmojis.length > 0 && getEmojiUrl && (!search.trim() || "custom".includes(search.toLowerCase())) && (
              <div ref={el => { categoryRefs.current["custom"] = el; }}>
                <div className="emoji-picker-category-label">Custom</div>
                <div className="emoji-picker-grid">
                  {customEmojis.map(emoji => (
                    <button
                      key={emoji.id}
                      className="emoji-picker-item"
                      onClick={() => { addRecentEmoji(`:${emoji.name}:`); onSelect(`:${emoji.name}:`); }}
                      type="button"
                      title={`:${emoji.name}:`}
                    >
                      <img src={getEmojiUrl(emoji.content_hash)} alt={`:${emoji.name}:`} style={{ width: '22px', height: '22px', objectFit: 'contain' }} />
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
