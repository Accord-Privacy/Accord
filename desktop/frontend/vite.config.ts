import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { createHash } from "crypto";
import { execSync } from "child_process";
import path from "path";
import { assertReleaseConfig } from "./src/releaseChecks";

// SPEC-02 REQ-29: a release build fails while LEGACY_READ_UNTIL is unset.
assertReleaseConfig(process.env);

const isTauri = !!process.env.TAURI_ENV_PLATFORM;

/**
 * SPEC-03 REQ-39, T-39: the client builds no peer connection of any kind,
 * and the production bundle contains the identifier `RTCPeerConnection` only
 * inside reviewed third-party modules listed here (none at A1). Any other
 * occurrence fails the build.
 */
export const PEER_CONNECTION_ALLOWLIST: readonly string[] = [];
const PEER_CONNECTION = /RTCPeerConnection/;

function noPeerConnections(): Plugin {
  return {
    name: "accord-no-peer-connections",
    apply: "build",
    generateBundle(_options, bundle) {
      for (const [fileName, output] of Object.entries(bundle)) {
        if (output.type !== "chunk" || !PEER_CONNECTION.test(output.code)) continue;
        const modules = Object.entries(output.modules ?? {});
        const offending = modules
          .filter(([, m]) => typeof m?.code === "string" && PEER_CONNECTION.test(m.code))
          .map(([id]) => id);
        const explained = offending.length > 0 && offending.every(id => PEER_CONNECTION_ALLOWLIST.some(allowed => id.includes(allowed)));
        if (!explained) {
          this.error(
            `SPEC-03 REQ-39: ${fileName} contains RTCPeerConnection` +
              (offending.length > 0 ? ` (from ${offending.join(", ")})` : "") +
              "; no peer connection may be built, and only reviewed third-party modules may mention it.",
          );
        }
      }
    },
  };
}

// Generate a build hash from git commit + timestamp + random salt
function generateBuildHash(): string {
  let commit = "unknown";
  try {
    commit = execSync("git rev-parse --short HEAD", { encoding: "utf-8" }).trim();
  } catch { /* not in a git repo */ }
  const timestamp = new Date().toISOString();
  const hash = createHash("sha256")
    .update(commit)
    .update(timestamp)
    .update(Math.random().toString())
    .digest("hex");
  return hash;
}

export default defineConfig({
  plugins: [react(), noPeerConnections()],
  clearScreen: false,
  resolve: {
    alias: isTauri ? {} : {
      '@tauri-apps/plugin-store': path.resolve(__dirname, 'src/tauri-stubs/plugin-store.ts'),
      '@tauri-apps/plugin-updater': path.resolve(__dirname, 'src/tauri-stubs/plugin-updater.ts'),
      '@tauri-apps/plugin-process': path.resolve(__dirname, 'src/tauri-stubs/plugin-process.ts'),
    },
  },
  define: {
    // Inject build hash at compile time
    "import.meta.env.VITE_BUILD_HASH": JSON.stringify(generateBuildHash()),
  },
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    chunkSizeWarningLimit: 650,
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          if (id.includes('node_modules')) {
            if (id.includes('react') || id.includes('react-dom')) {
              return 'vendor-react';
            }
            if (id.includes('qrcode') || id.includes('jsqr')) {
              return 'vendor-qr';
            }
            if (id.includes('@noble/ciphers') || id.includes('@noble/curves') || id.includes('@noble/hashes')) {
              return 'vendor-crypto';
            }
            if (id.includes('marked') || id.includes('dompurify')) {
              return 'vendor-markdown';
            }
          }
        },
      },
    },
  },
});
