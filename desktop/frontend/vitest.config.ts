import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/__tests__/setup.ts'],
    // The two-client tests need a relay: `npm run test:integration`. The
    // SPEC-03 voice harness needs one too: `npm run test:voice`.
    exclude: ['e2e/**', 'node_modules/**', 'src/__integration__/**', 'tests/voice/**'],
  },
});
