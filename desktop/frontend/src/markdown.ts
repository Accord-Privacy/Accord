import { marked } from 'marked';
import DOMPurify from 'dompurify';

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
  'hr',
];

const ALLOWED_ATTR = ['href', 'target', 'rel', 'class'];

/**
 * Render markdown to sanitized HTML, then apply mention highlighting.
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
  if (currentUsername) {
    const escaped = currentUsername.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const usernameRegex = new RegExp(`(@${escaped})`, 'gi');
    const everyoneRegex = /(@everyone)/gi;

    // Walk text nodes to apply highlighting without breaking HTML
    const walker = document.createTreeWalker(div, NodeFilter.SHOW_TEXT);
    const textNodes: Text[] = [];
    while (walker.nextNode()) {
      textNodes.push(walker.currentNode as Text);
    }

    for (const node of textNodes) {
      // Skip text inside <code> and <pre>
      if (node.parentElement?.closest('code, pre')) continue;

      let text = node.textContent || '';
      if (usernameRegex.test(text) || everyoneRegex.test(text)) {
        const span = document.createElement('span');
        span.innerHTML = text
          .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
          .replace(usernameRegex, '<span class="mention">$1</span>')
          .replace(everyoneRegex, '<span class="mention mention-everyone">$1</span>');
        node.replaceWith(span);
      }
    }
    clean = div.innerHTML;
  }

  return clean;
}
