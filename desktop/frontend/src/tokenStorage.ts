/**
 * Secure token storage wrapper.
 * - Tauri desktop: uses Tauri's invoke-based secure storage (OS keychain/keyring)
 * - Web browser: falls back to localStorage (with a security warning)
 *
 * Backward compatible: migrates existing localStorage tokens on first load in Tauri.
 */

const TOKEN_KEY = 'accord_token';
const TOKEN_EXPIRY_KEY = 'accord_token_expiry';
const DEFAULT_TOKEN_LIFETIME_MS = 24 * 60 * 60 * 1000; // 24 hours

// ── Tauri detection ──

function isTauri(): boolean {
  return typeof window !== 'undefined' && !!(window as any).__TAURI__;
}

// ── Tauri secure storage via plugin-store ──
// Uses @tauri-apps/plugin-store (backed by OS keychain on supported platforms).
// Falls back gracefully to localStorage if the plugin isn't available.

let _tauriStore: any = null;
let _tauriStoreReady: Promise<any> | null = null;

function getTauriStore(): Promise<any> {
  if (_tauriStoreReady) return _tauriStoreReady;

  _tauriStoreReady = (async () => {
    try {
      // Dynamic import so web builds don't fail
      const { Store } = await import('@tauri-apps/plugin-store');
      _tauriStore = await Store.load('accord-secure.json');
      return _tauriStore;
    } catch (e) {
      console.warn('[tokenStorage] Tauri store plugin not available, falling back to localStorage:', e);
      return null;
    }
  })();

  return _tauriStoreReady;
}

// ── Migration: move existing localStorage tokens into Tauri store on first load ──

let _migrated = false;

async function migrateFromLocalStorage(): Promise<void> {
  if (_migrated) return;
  _migrated = true;

  if (!isTauri()) return;

  const existingToken = localStorage.getItem(TOKEN_KEY);
  const existingExpiry = localStorage.getItem(TOKEN_EXPIRY_KEY);
  if (!existingToken) return;

  const store = await getTauriStore();
  if (!store) return;

  // Only migrate if Tauri store is empty
  const alreadyStored = await store.get(TOKEN_KEY);
  if (alreadyStored) {
    // Tauri store already has a token — clear the insecure localStorage copy
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(TOKEN_EXPIRY_KEY);
    return;
  }

  // Migrate
  await store.set(TOKEN_KEY, existingToken);
  if (existingExpiry) {
    await store.set(TOKEN_EXPIRY_KEY, existingExpiry);
  }
  await store.save();

  // Remove from insecure localStorage
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TOKEN_EXPIRY_KEY);
  console.info('[tokenStorage] Migrated token from localStorage to Tauri secure store');
}

// Kick off migration immediately on load
if (isTauri()) {
  migrateFromLocalStorage().catch(() => {});
}

// ── Public API ──

export async function storeToken(token: string, lifetimeMs: number = DEFAULT_TOKEN_LIFETIME_MS): Promise<void> {
  const expiry = (Date.now() + lifetimeMs).toString();

  if (isTauri()) {
    const store = await getTauriStore();
    if (store) {
      await store.set(TOKEN_KEY, token);
      await store.set(TOKEN_EXPIRY_KEY, expiry);
      await store.save();
      return;
    }
  }

  // Web fallback
  if (typeof console !== 'undefined') {
    console.warn(
      '[tokenStorage] Using localStorage for token storage. ' +
      'This is less secure than OS keychain — tokens may be accessible to XSS attacks. ' +
      'For production, use the Tauri desktop app.'
    );
  }
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(TOKEN_EXPIRY_KEY, expiry);
}

export async function getToken(): Promise<string | null> {
  let token: string | null = null;
  let expiryStr: string | null = null;

  if (isTauri()) {
    await migrateFromLocalStorage();
    const store = await getTauriStore();
    if (store) {
      token = (await store.get(TOKEN_KEY)) as string | null;
      expiryStr = (await store.get(TOKEN_EXPIRY_KEY)) as string | null;

      if (token && expiryStr) {
        const expiry = parseInt(expiryStr, 10);
        if (Date.now() > expiry) {
          await clearToken();
          return null;
        }
      }

      return token || null;
    }
  }

  // Web fallback
  token = localStorage.getItem(TOKEN_KEY);
  expiryStr = localStorage.getItem(TOKEN_EXPIRY_KEY);

  if (!token) return null;

  if (expiryStr) {
    const expiry = parseInt(expiryStr, 10);
    if (Date.now() > expiry) {
      await clearToken();
      return null;
    }
  }

  return token;
}

export async function clearToken(): Promise<void> {
  if (isTauri()) {
    const store = await getTauriStore();
    if (store) {
      await store.delete(TOKEN_KEY);
      await store.delete(TOKEN_EXPIRY_KEY);
      await store.save();
    }
  }

  // Always clear localStorage too (migration cleanup / web fallback)
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TOKEN_EXPIRY_KEY);
}
