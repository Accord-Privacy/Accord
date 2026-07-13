/**
 * Disappearing messages — retention policy (client-authoritative).
 *
 * A channel's effective time-to-live is its own override if set, otherwise the
 * node default, otherwise "keep forever" (0). The sender stamps each outgoing
 * message with `now + ttl`; the relay enforces that timestamp without ever
 * understanding the policy (see server delete_expired_messages). The policy
 * itself is distributed to other members inside the NMK-encrypted node metadata
 * blob — the relay never sees the duration in cleartext.
 *
 * This module owns the local cache + the pure TTL/expiry math. Persisted under
 * the `accord_*` prefix so panic-wipe/duress clears it with everything else.
 */

const nodeKey = (nodeId: string) => `accord_retention_node_${nodeId}`;
const channelKey = (channelId: string) => `accord_retention_chan_${channelId}`;

/** Retention choices offered in the UI. `secs === 0` means "keep forever". */
export const RETENTION_PRESETS: ReadonlyArray<{ label: string; secs: number }> = [
  { label: "Off (keep forever)", secs: 0 },
  { label: "1 hour", secs: 3600 },
  { label: "8 hours", secs: 28800 },
  { label: "24 hours", secs: 86400 },
  { label: "7 days", secs: 604800 },
  { label: "30 days", secs: 2592000 },
];

function readTtl(key: string): number | null {
  const raw = localStorage.getItem(key);
  if (raw === null) return null;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

/** Node-wide default TTL (seconds). 0 = keep forever. */
export function getNodeRetention(nodeId: string): number {
  return readTtl(nodeKey(nodeId)) ?? 0;
}

export function setNodeRetention(nodeId: string, ttlSecs: number): void {
  if (!Number.isFinite(ttlSecs) || ttlSecs < 0) throw new Error("ttl must be >= 0");
  localStorage.setItem(nodeKey(nodeId), String(Math.floor(ttlSecs)));
}

/**
 * Per-channel override. `null` clears the override so the channel falls back to
 * the node default. Returns `null` when no override is set (distinct from an
 * explicit 0, which is "this channel keeps forever even if the node expires").
 */
export function getChannelRetentionOverride(channelId: string): number | null {
  return readTtl(channelKey(channelId));
}

export function setChannelRetention(channelId: string, ttlSecs: number | null): void {
  if (ttlSecs === null) {
    localStorage.removeItem(channelKey(channelId));
    return;
  }
  if (!Number.isFinite(ttlSecs) || ttlSecs < 0) throw new Error("ttl must be >= 0");
  localStorage.setItem(channelKey(channelId), String(Math.floor(ttlSecs)));
}

/**
 * Effective TTL (seconds) for a channel: channel override wins, else node
 * default, else 0 (keep forever). `nodeId` may be undefined for DM channels,
 * which only ever use their own override.
 */
export function effectiveTtl(nodeId: string | undefined, channelId: string): number {
  const override = getChannelRetentionOverride(channelId);
  if (override !== null) return override;
  return nodeId ? getNodeRetention(nodeId) : 0;
}

/** Expiry timestamp (unix seconds) for a message sent now, or undefined if it never expires. */
export function expiryForNow(
  ttlSecs: number,
  nowSecs: number = Math.floor(Date.now() / 1000)
): number | undefined {
  return ttlSecs > 0 ? nowSecs + Math.floor(ttlSecs) : undefined;
}

/** Whether a message created at `createdAtSecs` has expired under `ttlSecs`. */
export function isExpired(
  ttlSecs: number,
  createdAtSecs: number,
  nowSecs: number = Math.floor(Date.now() / 1000)
): boolean {
  return ttlSecs > 0 && createdAtSecs + ttlSecs <= nowSecs;
}

/**
 * The "wipe-old" cutoff: when retention is first enabled (or shortened) on a
 * channel, every message created before this timestamp is already expired and
 * must be purged immediately (locally + via the relay purge_before endpoint).
 */
export function wipeOldCutoff(
  ttlSecs: number,
  nowSecs: number = Math.floor(Date.now() / 1000)
): number {
  return ttlSecs > 0 ? nowSecs - Math.floor(ttlSecs) : 0;
}

// ---------------------------------------------------------------------------
// Distribution: serialize the whole node policy for the NMK-encrypted metadata
// blob, and apply a received one so every member's client expires messages the
// same way. The relay only ever stores the encrypted form.
// ---------------------------------------------------------------------------

interface SerializedRetention {
  v: 1;
  node: number;
  channels: Record<string, number>;
}

/** Serialize a node's retention policy (node default + the overrides among `channelIds`). */
export function serializeNodeRetention(nodeId: string, channelIds: string[]): string {
  const channels: Record<string, number> = {};
  for (const cid of channelIds) {
    const override = getChannelRetentionOverride(cid);
    if (override !== null) channels[cid] = override;
  }
  const payload: SerializedRetention = { v: 1, node: getNodeRetention(nodeId), channels };
  return JSON.stringify(payload);
}

/**
 * Apply a distributed retention policy into the local store. Returns true if
 * anything changed (so the caller can re-sweep). Malformed/unknown-version
 * input is ignored.
 */
export function applyNodeRetention(nodeId: string, json: string): boolean {
  let payload: SerializedRetention;
  try {
    payload = JSON.parse(json);
  } catch {
    return false;
  }
  if (!payload || payload.v !== 1) return false;
  let changed = false;
  if (typeof payload.node === "number" && payload.node >= 0) {
    if (getNodeRetention(nodeId) !== payload.node) changed = true;
    setNodeRetention(nodeId, payload.node);
  }
  if (payload.channels && typeof payload.channels === "object") {
    for (const [cid, ttl] of Object.entries(payload.channels)) {
      if (typeof ttl === "number" && ttl >= 0) {
        if (getChannelRetentionOverride(cid) !== ttl) changed = true;
        setChannelRetention(cid, ttl);
      }
    }
  }
  return changed;
}
