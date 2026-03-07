import { marked } from 'marked';
import DOMPurify from 'dompurify';
import type { CustomEmoji } from './types';

// Configure marked for chat messages
marked.setOptions({
  breaks: true,
  gfm: true,
});

const ALLOWED_TAGS = [
  'b', 'i', 'em', 'strong', 'code', 'pre', 'del', 's',
  'a', 'p', 'br', 'ul', 'ol', 'li', 'blockquote',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'span', 'div', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
  'hr', 'img',
];

const ALLOWED_ATTR = ['href', 'target', 'rel', 'class', 'src', 'alt', 'title', 'width', 'height'];

/** Map of custom emoji name → image URL, set by the app when a node is selected */
let _customEmojiMap: Map<string, string> = new Map();

/** Update the custom emoji map (call when switching nodes or when emojis are loaded) */
export function setCustomEmojis(emojis: CustomEmoji[], getUrl: (hash: string) => string): void {
  _customEmojiMap = new Map();
  for (const e of emojis) {
    _customEmojiMap.set(e.name, getUrl(e.content_hash));
  }
}

/**
 * Render markdown to sanitized HTML, then apply mention highlighting and custom emojis.
 * Replaces the old `highlightMentions(msg.content)` call.
 */
export function renderMessageMarkdown(raw: string, currentUsername?: string): string {
  if (!raw) return '';

  // Parse markdown to HTML
  const html = marked.parse(raw, { async: false }) as string;

  // Sanitize — allow markdown HTML tags but nothing dangerous
  let clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
  });

  // Make links open in new tab
  const div = document.createElement('div');
  div.innerHTML = clean;
  div.querySelectorAll('a').forEach((a) => {
    a.setAttribute('target', '_blank');
    a.setAttribute('rel', 'noopener noreferrer');
  });
  clean = div.innerHTML;

  // Apply mention highlighting on text nodes only (preserve HTML structure)
  {
    // Patterns: @username, @everyone, #channel-name
    const mentionRegex = /@(\w[\w.]*)/g;
    const everyoneRegex = /(@everyone)/gi;
    const channelRegex = /(#[\w-]+)/g;

    const selfEscaped = currentUsername
      ? currentUsername.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      : null;
    const selfRegex = selfEscaped ? new RegExp(`(@${selfEscaped})`, 'gi') : null;

    // Walk text nodes to apply highlighting without breaking HTML
    const walker = document.createTreeWalker(div, NodeFilter.SHOW_TEXT);
    const textNodes: Text[] = [];
    while (walker.nextNode()) {
      textNodes.push(walker.currentNode as Text);
    }

    for (const node of textNodes) {
      // Skip text inside <code> and <pre>
      if (node.parentElement?.closest('code, pre')) continue;

      const text = node.textContent || '';
      const hasAnyMention = mentionRegex.test(text) || everyoneRegex.test(text) || channelRegex.test(text);
      // Reset lastIndex after test
      mentionRegex.lastIndex = 0;
      everyoneRegex.lastIndex = 0;
      channelRegex.lastIndex = 0;

      if (hasAnyMention) {
        const span = document.createElement('span');
        let escaped = text
          .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

        // Order matters: self mentions first (more specific), then @everyone, then generic @mentions, then #channels
        if (selfRegex) {
          escaped = escaped.replace(selfRegex, '<span class="mention mention-self" data-mention-user="$1">$1</span>');
        }
        escaped = escaped.replace(everyoneRegex, '<span class="mention mention-everyone">$1</span>');
        // Generic @mentions (skip already-wrapped ones)
        escaped = escaped.replace(/@(\w[\w.]*)/g, (match, name) => {
          // Don't double-wrap if already inside a mention span
          if (selfRegex && selfRegex.test('@' + name)) {
            selfRegex.lastIndex = 0;
            return match;
          }
          if (name.toLowerCase() === 'everyone') return match;
          return `<span class="mention" data-mention-user="@${name}">@${name}</span>`;
        });
        escaped = escaped.replace(channelRegex, '<span class="mention-channel" data-mention-channel="$1">$1</span>');

        span.innerHTML = escaped;
        node.replaceWith(span);
      }
    }
    clean = div.innerHTML;
  }

  // Replace custom emoji syntax :name: with <img> tags
  if (_customEmojiMap.size > 0) {
    clean = clean.replace(/:([a-zA-Z0-9_]{2,32}):/g, (_match, name) => {
      const url = _customEmojiMap.get(name);
      if (url) {
        return `<img class="custom-emoji" src="${url}" alt=":${name}:" title=":${name}:" width="24" height="24" />`;
      }
      return _match;
    });
  }

  return clean;
}
