/**
 * RelayManager — manages connections to multiple Accord relay servers.
 *
 * Each relay the user has joined Nodes on gets its own AccordApi client
 * and auth token, stored in localStorage under 'accord_relays'.
 *
 * Phase 1: storage, multi-API client, migration from single-relay format.
 */

import { AccordApi } from './api';

// ── Types ──────────────────────────────────────────────────────────────────

/** Persisted relay state (localStorage) */
export interface StoredRelay {
  url: string;        // normalized relay URL (https://host:port)
  token: string;      // auth token for this relay
  userId: string;     // user ID assigned by this relay
  nodeIds: string[];  // Node IDs the user has joined on this relay
}

/** Runtime relay connection */
export interface RelayConnection {
  url: string;
  token: string | null;
  userId: string | null;
  api: AccordApi;
  connected: boolean;
}

// ── Constants ──────────────────────────────────────────────────────────────

const STORAGE_KEY = 'accord_relays';
const LEGACY_URL_KEY = 'accord_server_url';
const LEGACY_TOKEN_KEY = 'accord_token';
const LEGACY_USER_ID_KEY = 'accord_user_id';

// ── Helpers ────────────────────────────────────────────────────────────────

/** Normalize a relay URL: lowercase host, strip trailing slashes, ensure scheme. */
export function normalizeRelayUrl(raw: string): string {
  let url = raw.trim().replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(url)) {
    url = `https://${url}`;
  }
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return url;
  }
}

// ── RelayManager ───────────────────────────────────────────────────────────

export class RelayManager {
  private relays: Map<string, StoredRelay> = new Map();
  private connections: Map<string, RelayConnection> = new Map();

  constructor() {
    this.loadFromStorage();
    this.migrateLegacy();
  }

  // ── Storage ────────────────────────────────────────────────────────────

  /** Load stored relays from localStorage. */
  private loadFromStorage(): void {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const list: StoredRelay[] = JSON.parse(raw);
      if (!Array.isArray(list)) return;
      for (const relay of list) {
        if (relay.url && relay.token && relay.userId) {
          const key = normalizeRelayUrl(relay.url);
          this.relays.set(key, { ...relay, url: key });
        }
      }
    } catch {
      // Corrupt storage — start fresh
    }
  }

  /** Persist current relay list to localStorage. */
  private saveToStorage(): void {
    const list = Array.from(this.relays.values());
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  }

  /**
   * Migrate from the legacy single-relay format (accord_server_url / accord_token / accord_user_id)
   * to the new multi-relay storage.  Only runs once — if we already have relays, skip.
   */
  private migrateLegacy(): void {
    if (this.relays.size > 0) return;

    const legacyUrl = localStorage.getItem(LEGACY_URL_KEY);
    const legacyToken = localStorage.getItem(LEGACY_TOKEN_KEY);
    const legacyUserId = localStorage.getItem(LEGACY_USER_ID_KEY);

    if (legacyUrl && legacyToken && legacyUserId) {
      const url = normalizeRelayUrl(legacyUrl);
      this.relays.set(url, {
        url,
        token: legacyToken,
        userId: legacyUserId,
        nodeIds: [], // will be populated when nodes load
      });
      this.saveToStorage();
    }
  }

  // ── Queries ────────────────────────────────────────────────────────────

  /** Return all stored relays. */
  getRelays(): StoredRelay[] {
    return Array.from(this.relays.values());
  }

  /** Get the live connection for a relay, if one exists. */
  getConnection(relayUrl: string): RelayConnection | undefined {
    return this.connections.get(normalizeRelayUrl(relayUrl));
  }

  /** Get all active connections. */
  getConnections(): RelayConnection[] {
    return Array.from(this.connections.values());
  }

  /** Find which relay owns a given Node ID. */
  getRelayForNode(nodeId: string): StoredRelay | undefined {
    for (const relay of this.relays.values()) {
      if (relay.nodeIds.includes(nodeId)) return relay;
    }
    return undefined;
  }

  // ── Connection management ──────────────────────────────────────────────

  /**
   * Connect to a relay.  If we have a stored token, login to verify it.
   * If no stored token, register a new account on this relay.
   * Returns the live RelayConnection.
   */
  async connectRelay(
    relayUrl: string,
    publicKey: string,
    password: string,
  ): Promise<RelayConnection> {
    const url = normalizeRelayUrl(relayUrl);

    // Reuse existing live connection
    const existing = this.connections.get(url);
    if (existing?.connected) return existing;

    // Create a dedicated API client for this relay
    const api = new AccordApi(url);
    const stored = this.relays.get(url);

    let token: string | null = null;
    let userId: string | null = null;

    if (stored?.token) {
      // We have a stored token — try to use it via login to verify
      api.setToken(stored.token);
      try {
        const profile = await api.getUserProfile(stored.userId);
        if (profile) {
          token = stored.token;
          userId = stored.userId;
        }
      } catch {
        // Token expired or invalid — re-authenticate
        token = null;
      }
    }

    if (!token) {
      // Try login first (account may already exist on this relay)
      try {
        const authResp = await api.login(publicKey, password);
        token = authResp.token;
        userId = authResp.user_id;
      } catch {
        // Login failed — register then login
        await api.register(publicKey, password);
        const authResp = await api.login(publicKey, password);
        token = authResp.token;
        userId = authResp.user_id;
      }
      api.setToken(token);
    }

    // Persist
    const nodeIds = stored?.nodeIds ?? [];
    this.relays.set(url, { url, token: token!, userId: userId!, nodeIds });
    this.saveToStorage();

    const conn: RelayConnection = {
      url,
      token,
      userId,
      api,
      connected: true,
    };
    this.connections.set(url, conn);
    return conn;
  }

  /** Disconnect from a relay (drops the runtime connection, keeps stored credentials). */
  disconnect(relayUrl: string): void {
    const url = normalizeRelayUrl(relayUrl);
    const conn = this.connections.get(url);
    if (conn) {
      conn.connected = false;
      this.connections.delete(url);
    }
  }

  /** Forget a relay entirely — remove stored credentials and disconnect. */
  removeRelay(relayUrl: string): void {
    const url = normalizeRelayUrl(relayUrl);
    this.disconnect(url);
    this.relays.delete(url);
    this.saveToStorage();
  }

  // ── Node tracking ─────────────────────────────────────────────────────

  /** Record that the user has joined a Node on a relay. */
  addNodeToRelay(relayUrl: string, nodeId: string): void {
    const url = normalizeRelayUrl(relayUrl);
    const relay = this.relays.get(url);
    if (!relay) return;
    if (!relay.nodeIds.includes(nodeId)) {
      relay.nodeIds.push(nodeId);
      this.saveToStorage();
    }
  }

  /** Remove a Node from a relay's tracking (e.g. user left the Node). */
  removeNodeFromRelay(relayUrl: string, nodeId: string): void {
    const url = normalizeRelayUrl(relayUrl);
    const relay = this.relays.get(url);
    if (!relay) return;
    relay.nodeIds = relay.nodeIds.filter((id) => id !== nodeId);
    this.saveToStorage();
  }
}
