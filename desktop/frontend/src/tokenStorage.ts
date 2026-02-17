/**
 * Secure token storage wrapper.
 * Adds expiry checking and clears expired tokens automatically.
 * TODO: For production, migrate to Tauri's secure storage API or httpOnly cookies.
 */

const TOKEN_KEY = 'accord_token';
const TOKEN_EXPIRY_KEY = 'accord_token_expiry';
const DEFAULT_TOKEN_LIFETIME_MS = 24 * 60 * 60 * 1000; // 24 hours

export function storeToken(token: string, lifetimeMs: number = DEFAULT_TOKEN_LIFETIME_MS): void {
  const expiry = Date.now() + lifetimeMs;
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(TOKEN_EXPIRY_KEY, expiry.toString());
}

export function getToken(): string | null {
  const token = localStorage.getItem(TOKEN_KEY);
  const expiryStr = localStorage.getItem(TOKEN_EXPIRY_KEY);

  if (!token) return null;

  if (expiryStr) {
    const expiry = parseInt(expiryStr, 10);
    if (Date.now() > expiry) {
      clearToken();
      return null;
    }
  }

  return token;
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TOKEN_EXPIRY_KEY);
}
