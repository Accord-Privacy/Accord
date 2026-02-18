import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { createHash } from "crypto";
import { execSync } from "child_process";

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
  plugins: [react()],
  clearScreen: false,
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
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor-react': ['react', 'react-dom'],
          'vendor-qr': ['qrcode', 'jsqr'],
          'vendor-crypto': ['@noble/ciphers', '@noble/curves', '@noble/hashes'],
        },
      },
    },
  },
});
