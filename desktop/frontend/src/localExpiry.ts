/**
 * Per-recipient, per-device expiry for read-gated messages.
 *
 * When THIS device reads a read-gated message, its client stamps a local expiry
 * of `read time + gate_ttl`. The message then vanishes from this device at that
 * time — even if other required readers haven't opened it yet, so it lingers for
 * them (the relay only purges the shared ciphertext once every required reader
 * has read it).
 *
 * Two persisted structures survive restarts so a refetch from the relay (which
 * still holds the message for the unread) doesn't resurrect a copy this device
 * already expired or is counting down:
 *   - a map  msgId -> unix-seconds expiry  (still counting down)
 *   - a set  msgId                          (already expired / tombstoned)
 */

const EXPIRY_KEY = 'accord_local_expiry';
const TOMB_KEY = 'accord_local_expired';

function loadMap(): Record<string, number> {
  try {
    return JSON.parse(localStorage.getItem(EXPIRY_KEY) || '{}');
  } catch {
    return {};
  }
}

function saveMap(m: Record<string, number>): void {
  localStorage.setItem(EXPIRY_KEY, JSON.stringify(m));
}

function loadTombstones(): Set<string> {
  try {
    return new Set<string>(JSON.parse(localStorage.getItem(TOMB_KEY) || '[]'));
  } catch {
    return new Set();
  }
}

function saveTombstones(s: Set<string>): void {
  localStorage.setItem(TOMB_KEY, JSON.stringify([...s]));
}

/**
 * Record that this device read a gated message; returns the local expiry (unix
 * seconds) it should carry. No-op returns the existing stamp if already set, so
 * re-reading never restarts this device's own countdown.
 */
export function stampLocalExpiry(messageId: string, ttlSecs: number, now = Math.floor(Date.now() / 1000)): number {
  const map = loadMap();
  if (map[messageId] !== undefined) return map[messageId];
  const expiry = now + ttlSecs;
  map[messageId] = expiry;
  saveMap(map);
  return expiry;
}

/** Current local expiry for a message, if this device is counting one down. */
export function getLocalExpiry(messageId: string): number | undefined {
  return loadMap()[messageId];
}

/** True once this device has expired (and tombstoned) its copy. */
export function isLocallyExpired(messageId: string): boolean {
  return loadTombstones().has(messageId);
}

/** Move a set of ids from "counting down" to "tombstoned". */
export function tombstone(ids: string[]): void {
  if (ids.length === 0) return;
  const map = loadMap();
  const tombs = loadTombstones();
  for (const id of ids) {
    delete map[id];
    tombs.add(id);
  }
  saveMap(map);
  saveTombstones(tombs);
}

/** Filter out ids this device has already tombstoned (used on refetch). */
export function filterTombstoned<T extends { id: string }>(messages: T[]): T[] {
  const tombs = loadTombstones();
  return tombs.size === 0 ? messages : messages.filter(m => !tombs.has(m.id));
}

/** Clear everything — used by panic/duress wipe. */
export function clearLocalExpiry(): void {
  localStorage.removeItem(EXPIRY_KEY);
  localStorage.removeItem(TOMB_KEY);
}
