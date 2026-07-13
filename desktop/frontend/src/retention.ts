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
const ssNodeKey = (nodeId: string) => `accord_ssprotect_node_${nodeId}`;
const ssChannelKey = (channelId: string) => `accord_ssprotect_chan_${channelId}`;

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
// Screenshot protection — a per-node/channel policy that asks the OS to exclude
// the window from screen capture while a protected channel is open. Local by
// nature (each viewer's window), but distributed so a "confidential" node can
// auto-enable it for every member. `true` = protect. Honest scope: reliable on
// Windows/macOS, best-effort on Linux (most Wayland compositors ignore it).
// ---------------------------------------------------------------------------

function readBool(key: string): boolean | null {
  const raw = localStorage.getItem(key);
  if (raw === null) return null;
  return raw === "1" || raw === "true";
}

export function getNodeScreenshotProtect(nodeId: string): boolean {
  return readBool(ssNodeKey(nodeId)) ?? false;
}

export function setNodeScreenshotProtect(nodeId: string, on: boolean): void {
  localStorage.setItem(ssNodeKey(nodeId), on ? "1" : "0");
}

export function getChannelScreenshotOverride(channelId: string): boolean | null {
  return readBool(ssChannelKey(channelId));
}

export function setChannelScreenshotProtect(channelId: string, on: boolean | null): void {
  if (on === null) {
    localStorage.removeItem(ssChannelKey(channelId));
    return;
  }
  localStorage.setItem(ssChannelKey(channelId), on ? "1" : "0");
}

/** Effective screenshot protection for a channel: override wins, else node default. */
export function effectiveScreenshotProtect(
  nodeId: string | undefined,
  channelId: string
): boolean {
  const override = getChannelScreenshotOverride(channelId);
  if (override !== null) return override;
  return nodeId ? getNodeScreenshotProtect(nodeId) : false;
}

// ---------------------------------------------------------------------------
// Distribution: serialize the whole node policy (retention + screenshot) for the
// NMK-encrypted metadata blob, and apply a received one so every member's client
// behaves the same. The relay only ever stores the encrypted form.
// ---------------------------------------------------------------------------

interface SerializedSettings {
  v: 1;
  retention: { node: number; channels: Record<string, number> };
  screenshot: { node: boolean; channels: Record<string, boolean> };
}

/** Serialize a node's disappearing + screenshot policy (defaults + overrides among `channelIds`). */
export function serializeNodeSettings(nodeId: string, channelIds: string[]): string {
  const retChannels: Record<string, number> = {};
  const ssChannels: Record<string, boolean> = {};
  for (const cid of channelIds) {
    const ret = getChannelRetentionOverride(cid);
    if (ret !== null) retChannels[cid] = ret;
    const ss = getChannelScreenshotOverride(cid);
    if (ss !== null) ssChannels[cid] = ss;
  }
  const payload: SerializedSettings = {
    v: 1,
    retention: { node: getNodeRetention(nodeId), channels: retChannels },
    screenshot: { node: getNodeScreenshotProtect(nodeId), channels: ssChannels },
  };
  return JSON.stringify(payload);
}

/**
 * Apply a distributed node settings blob into the local store. Returns true if
 * anything changed. Malformed/unknown-version input is ignored. Also reads the
 * pre-screenshot format (`{v:1, node, channels}` = retention only).
 */
export function applyNodeSettings(nodeId: string, json: string): boolean {
  let payload: any;
  try {
    payload = JSON.parse(json);
  } catch {
    return false;
  }
  if (!payload || payload.v !== 1) return false;
  // Legacy retention-only blob: promote its top-level fields into `retention`.
  const retention = payload.retention ?? { node: payload.node, channels: payload.channels };
  let changed = false;

  if (retention && typeof retention.node === "number" && retention.node >= 0) {
    if (getNodeRetention(nodeId) !== retention.node) changed = true;
    setNodeRetention(nodeId, retention.node);
  }
  if (retention && retention.channels && typeof retention.channels === "object") {
    for (const [cid, ttl] of Object.entries(retention.channels)) {
      if (typeof ttl === "number" && ttl >= 0) {
        if (getChannelRetentionOverride(cid) !== ttl) changed = true;
        setChannelRetention(cid, ttl);
      }
    }
  }

  const ss = payload.screenshot;
  if (ss && typeof ss.node === "boolean") {
    if (getNodeScreenshotProtect(nodeId) !== ss.node) changed = true;
    setNodeScreenshotProtect(nodeId, ss.node);
  }
  if (ss && ss.channels && typeof ss.channels === "object") {
    for (const [cid, on] of Object.entries(ss.channels)) {
      if (typeof on === "boolean") {
        if (getChannelScreenshotOverride(cid) !== on) changed = true;
        setChannelScreenshotProtect(cid, on);
      }
    }
  }
  return changed;
}
