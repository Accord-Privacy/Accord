# Reproducible Builds

Accord supports reproducible builds so you can verify that distributed binaries were built from the published source code.

## Quick Verification

```bash
# 1. Check out the exact version
git checkout v0.1.0

# 2. Run the reproducible build script
./scripts/reproducible-build.sh --server-only

# 3. Compare the hash
cat build-hashes.sha256
# Compare with the hashes published in the GitHub release or CI artifacts
```

If the SHA256 hash matches, the binary is identical to what was built from source.

## Requirements

To reproduce an official build, you need to match the build environment:

| Component | Requirement |
|-----------|-------------|
| **OS** | Same as CI (Ubuntu latest — check workflow run for exact version) |
| **Rust toolchain** | Same version (check CI logs or `rust-toolchain.toml` if present) |
| **Dependencies** | Locked via `Cargo.lock` (committed to repo) |

The build script prints the exact Rust version and OS used — compare these with the CI run you're verifying against.

## What the Script Does

`scripts/reproducible-build.sh` sets these deterministic environment variables:

- **`SOURCE_DATE_EPOCH`** — Fixed timestamp so embedded dates are stable
- **`CARGO_INCREMENTAL=0`** — Disables incremental compilation (non-deterministic)
- **`RUSTFLAGS --remap-path-prefix`** — Strips local filesystem paths from the binary
- **`ZERO_AR_DATE=1`** — Deterministic archive timestamps
- **`--locked`** — Uses exact dependency versions from `Cargo.lock`

The release profile in `Cargo.toml` also helps: `codegen-units = 1` ensures deterministic code generation, and `lto = "thin"` produces consistent link-time optimization.

## Server vs Desktop

### Server (`accord-server`) ✅ Reproducible

The server is pure Rust with no system UI dependencies. Builds are reproducible across identical OS + toolchain combinations.

### Desktop (`accord-desktop`) ⚠️ Limited

The Tauri desktop app links against system libraries (GTK, WebKitGTK, etc.) which makes exact reproducibility harder:

- Different distro versions ship different system library versions
- WebKitGTK in particular is large and version-sensitive
- The Tauri bundler may embed OS-specific metadata

**Current status:** Desktop reproducibility is best-effort. For verification, use the exact same OS version and system package versions as CI.

## CI Workflow

The `reproducible.yml` workflow runs automatically on release tags and can be triggered manually. It:

1. Builds the server binary on Ubuntu
2. Computes SHA256 hashes
3. Uploads both the binary and hashes as artifacts

To verify a release: download the CI artifacts, then run the build locally and compare `build-hashes.sha256`.

## Known Limitations

- **Cross-OS:** Binaries built on different operating systems will differ (different libc, linker, etc.)
- **Rust toolchain version:** Even patch-level Rust updates can change codegen. Pin the exact version for critical verification.
- **Caching:** The build script works with or without Rust caches, but for guaranteed reproducibility, build from a clean state (`cargo clean` first).
- **Strip:** The release profile strips symbols (`strip = true`). This is deterministic but means you can't debug the release binary.
