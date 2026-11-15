/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_ACCORD_SERVER_URL?: string;
  /**
   * End of the legacy-upload read window, `YYYY-MM-DD` (SPEC-02 REQ-29,
   * OD-33: C1's release date plus 365 days). Required in release builds.
   */
  readonly VITE_ACCORD_LEGACY_READ_UNTIL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
