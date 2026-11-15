/**
 * Build-time checks for release builds, run by `vite.config.ts`. No browser or
 * application imports: this module is loaded by Node when Vite starts.
 */

/** The environment variable that ends the legacy-upload read window (SPEC-02 REQ-29). */
export const LEGACY_READ_UNTIL_VAR = 'VITE_ACCORD_LEGACY_READ_UNTIL';

/**
 * Whether this build is a release build: `ACCORD_RELEASE_BUILD=1`, or a CI
 * build of a `v*` tag (the release workflows run on those tags).
 */
export function isReleaseBuild(env: Record<string, string | undefined>): boolean {
  if (env.ACCORD_RELEASE_BUILD === '1') return true;
  return env.GITHUB_REF_TYPE === 'tag' && /^v/.test(env.GITHUB_REF_NAME ?? '');
}

/** A concrete `YYYY-MM-DD` date that exists. */
export function isConcreteDate(value: string | undefined): boolean {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const t = Date.parse(`${value}T00:00:00Z`);
  return Number.isFinite(t) && new Date(t).toISOString().slice(0, 10) === value;
}

/**
 * SPEC-02 REQ-29: every release build sets `LEGACY_READ_UNTIL` to a concrete
 * date (OD-33: C1's release date plus 365 days), and the release build fails
 * while it is unset. Throws for a release build without a valid date.
 */
export function assertReleaseConfig(env: Record<string, string | undefined>): void {
  if (!isReleaseBuild(env)) return;
  if (!isConcreteDate(env[LEGACY_READ_UNTIL_VAR])) {
    throw new Error(
      `${LEGACY_READ_UNTIL_VAR} must be set to a concrete date (YYYY-MM-DD) in release builds (SPEC-02 REQ-29)`,
    );
  }
}
