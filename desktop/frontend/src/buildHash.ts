// Build hash verification and trust indicators for Accord frontend
//
// The client build hash is injected at build time by vite.config.ts.
// The server build hash comes from the WebSocket hello message.

/** Known build entry (mirrors server's KnownBuild) */
export interface KnownBuild {
  version: string;
  platform: string;
  hash: string;
  revoked: boolean;
}

/** Trust levels for a build */
export type BuildTrust = 'verified' | 'unknown' | 'revoked';

/** Trust indicator display info */
export interface TrustIndicator {
  level: BuildTrust;
  emoji: string;
  label: string;
  color: string;
}

// Client build hash injected by Vite at build time (see vite.config.ts)
// Falls back to 'dev' for development builds
export const CLIENT_BUILD_HASH: string =
  (import.meta as any).env?.VITE_BUILD_HASH || 'dev';

export const ACCORD_VERSION = '0.1.0';

/**
 * Sample HASHES.json structure — in production this would be fetched from
 * a signed registry or bundled with official releases.
 */
export const KNOWN_HASHES: KnownBuild[] = [
  // Placeholder entries — real hashes would be added during release builds
  // { version: '0.1.0', platform: 'web', hash: 'abc123...', revoked: false },
];

/** Revoked hashes — builds known to be compromised */
const REVOKED_HASHES = new Set<string>(
  KNOWN_HASHES.filter(h => h.revoked).map(h => h.hash)
);

/** Verified hashes — official non-revoked builds */
const VERIFIED_HASHES = new Set<string>(
  KNOWN_HASHES.filter(h => !h.revoked).map(h => h.hash)
);

/** Verify a single build hash against known hashes */
export function verifyBuildHash(hash: string): BuildTrust {
  if (!hash || hash === 'dev') return 'unknown';
  if (REVOKED_HASHES.has(hash)) return 'revoked';
  if (VERIFIED_HASHES.has(hash)) return 'verified';
  return 'unknown';
}

/** Get combined trust level from client and server hashes */
export function getCombinedTrust(clientHash: string, serverHash: string): BuildTrust {
  const clientTrust = verifyBuildHash(clientHash);
  const serverTrust = verifyBuildHash(serverHash);

  // If either is revoked, the whole thing is revoked
  if (clientTrust === 'revoked' || serverTrust === 'revoked') return 'revoked';
  // Both must be verified for combined verified
  if (clientTrust === 'verified' && serverTrust === 'verified') return 'verified';
  return 'unknown';
}

/** Get display info for a trust level */
export function getTrustIndicator(trust: BuildTrust): TrustIndicator {
  switch (trust) {
    case 'verified':
      return { level: 'verified', emoji: '🟢', label: 'Verified', color: '#43b581' };
    case 'revoked':
      return { level: 'revoked', emoji: '🔴', label: 'Modified Build', color: '#f04747' };
    case 'unknown':
    default:
      return { level: 'unknown', emoji: '🟡', label: 'Unknown Build', color: '#faa61a' };
  }
}

/** Format a hash for display (first 8 chars) */
export function shortHash(hash: string): string {
  if (!hash || hash === 'dev') return 'dev';
  return hash.slice(0, 8);
}
