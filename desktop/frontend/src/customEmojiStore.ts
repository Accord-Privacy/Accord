// Simple module-level store for custom emojis (avoids prop-drilling through AppContext)
import type { CustomEmoji } from './types';

let _emojis: CustomEmoji[] = [];
let _getUrl: (hash: string) => string = () => '';
let _listeners: Array<() => void> = [];

export function setNodeCustomEmojis(emojis: CustomEmoji[], getUrl: (hash: string) => string): void {
  _emojis = emojis;
  _getUrl = getUrl;
  _listeners.forEach(fn => fn());
}

export function getNodeCustomEmojis(): CustomEmoji[] {
  return _emojis;
}

export function getCustomEmojiUrl(hash: string): string {
  return _getUrl(hash);
}

export function subscribeCustomEmojis(listener: () => void): () => void {
  _listeners.push(listener);
  return () => {
    _listeners = _listeners.filter(fn => fn !== listener);
  };
}
