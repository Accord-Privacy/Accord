import { defineConfig } from 'vitest/config';

/**
 * SPEC-02 §10.1 two-client integration tests: the frontend's attachment and
 * E2EE modules under Node against a real relay (`src/__integration__`).
 * Run with `npm run test:integration`; set ACCORD_SERVER_BIN to a built
 * `accord-server`, or have `cargo` on the PATH.
 */
export default defineConfig({
  test: {
    // Node's own fetch, WebSocket and Blob; `setup.ts` adds XMLHttpRequest.
    environment: 'node',
    setupFiles: ['./src/__integration__/setup.ts'],
    globals: true,
    include: ['src/__integration__/**/*.test.ts'],
    testTimeout: 120_000,
    hookTimeout: 900_000,
    fileParallelism: false,
  },
});
