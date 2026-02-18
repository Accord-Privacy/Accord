// Hash list fetcher for build verification
// Fetches HASHES.json from GitHub, caches in localStorage, refreshes every 6 hours.

import type { KnownBuild } from './buildHash';

const HASHES_URL = 'https://raw.githubusercontent.com/Accord-Privacy/Accord/main/HASHES.json';
const CACHE_KEY = 'accord_known_hashes';
const CACHE_TS_KEY = 'accord_known_hashes_ts';
const REFRESH_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6 hours

export type FetchStatus = 'ok' | 'pending' | 'error';

let cachedHashes: KnownBuild[] | null = null;
let fetchStatus: FetchStatus = 'pending';
let refreshTimer: ReturnType<typeof setInterval> | null = null;
const listeners: Array<() => void> = [];

/** Subscribe to hash list updates. Returns unsubscribe fn. */
export function onHashListUpdate(cb: () => void): () => void {
  listeners.push(cb);
  return () => {
    const i = listeners.indexOf(cb);
    if (i >= 0) listeners.splice(i, 1);
  };
}

function notifyListeners() {
  for (const cb of listeners) {
    try { cb(); } catch (_) { /* ignore */ }
  }
}

/** Load cached hashes from localStorage */
function loadFromCache(): { hashes: KnownBuild[]; ts: number } | null {
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    const ts = localStorage.getItem(CACHE_TS_KEY);
    if (raw && ts) {
      return { hashes: JSON.parse(raw), ts: Number(ts) };
    }
  } catch (_) { /* ignore */ }
  return null;
}

function saveToCache(hashes: KnownBuild[]) {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify(hashes));
    localStorage.setItem(CACHE_TS_KEY, String(Date.now()));
  } catch (_) { /* ignore */ }
}

/** Fetch hash list from GitHub */
async function fetchHashes(): Promise<KnownBuild[] | null> {
  try {
    const resp = await fetch(HASHES_URL, { cache: 'no-cache' });
    if (!resp.ok) return null;
    const data: KnownBuild[] = await resp.json();
    if (!Array.isArray(data)) return null;
    return data;
  } catch (_) {
    return null;
  }
}

/** Refresh the hash list (fetch from network, fall back to cache) */
export async function refreshHashList(): Promise<void> {
  const fetched = await fetchHashes();
  if (fetched) {
    cachedHashes = fetched;
    fetchStatus = 'ok';
    saveToCache(fetched);
  } else {
    // Keep existing cache if available
    if (!cachedHashes) {
      const cached = loadFromCache();
      if (cached) {
        cachedHashes = cached.hashes;
        fetchStatus = 'ok'; // We have data, even if stale
      } else {
        fetchStatus = 'error';
      }
    } else {
      // We already have hashes in memory, just note the fetch failed
      fetchStatus = 'ok'; // Still have usable data
    }
  }
  notifyListeners();
}

/** Get current known hashes (may be null if not yet loaded) */
export function getKnownHashes(): KnownBuild[] | null {
  return cachedHashes;
}

/** Get current fetch status */
export function getHashFetchStatus(): FetchStatus {
  return fetchStatus;
}

/** Initialize: load cache, fetch, set up periodic refresh */
export function initHashVerifier(): void {
  // Load from cache immediately
  const cached = loadFromCache();
  if (cached) {
    cachedHashes = cached.hashes;
    fetchStatus = 'ok';

    // If cache is fresh enough, skip immediate fetch
    if (Date.now() - cached.ts < REFRESH_INTERVAL_MS) {
      notifyListeners();
      // Still set up the timer for next refresh
      if (!refreshTimer) {
        refreshTimer = setInterval(refreshHashList, REFRESH_INTERVAL_MS);
      }
      return;
    }
  }

  // Fetch immediately
  refreshHashList();

  // Set up periodic refresh
  if (!refreshTimer) {
    refreshTimer = setInterval(refreshHashList, REFRESH_INTERVAL_MS);
  }
}
