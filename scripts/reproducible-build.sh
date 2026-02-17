#!/usr/bin/env bash
# reproducible-build.sh — Build Accord binaries deterministically.
# Usage: ./scripts/reproducible-build.sh [--server-only]
#
# Produces SHA256 hashes so anyone building from the same source
# (same toolchain, same OS) gets identical output.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SERVER_ONLY=false
if [[ "${1:-}" == "--server-only" ]]; then
    SERVER_ONLY=true
fi

# ── Deterministic environment ──────────────────────────────────────
# Fixed timestamp (2020-01-01) so embedded dates are stable.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1577836800}"

# No incremental compilation (non-deterministic).
export CARGO_INCREMENTAL=0

# Remap the build directory so absolute paths don't leak into the binary.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${REPO_ROOT}=/build/accord --remap-path-prefix=${HOME}/.cargo=/cargo"

# Ensure deterministic linker behaviour.
export ZERO_AR_DATE=1

# ── Toolchain info (for verification) ─────────────────────────────
echo "═══ Reproducible Build — Accord ═══"
echo "Date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Commit:      $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
echo "Rust:        $(rustc --version)"
echo "Cargo:       $(cargo --version)"
echo "OS:          $(uname -srm)"
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
echo "RUSTFLAGS=$RUSTFLAGS"
echo ""

# ── Build ──────────────────────────────────────────────────────────
CARGO_ARGS=(--release --locked)

if $SERVER_ONLY; then
    echo "Building accord-server only…"
    cargo build "${CARGO_ARGS[@]}" -p accord-server
else
    echo "Building full workspace…"
    cargo build "${CARGO_ARGS[@]}" --workspace
fi

# ── Hash output ────────────────────────────────────────────────────
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release"
HASH_FILE="$REPO_ROOT/build-hashes.sha256"

echo ""
echo "═══ Binary Hashes (SHA256) ═══"

: > "$HASH_FILE"

for bin in accord-server accord-cli accord-desktop standalone-demo; do
    BIN_PATH="$TARGET_DIR/$bin"
    if [[ -f "$BIN_PATH" ]]; then
        HASH=$(sha256sum "$BIN_PATH" | awk '{print $1}')
        echo "$HASH  $bin" | tee -a "$HASH_FILE"
    fi
done

echo ""
echo "Hashes written to: $HASH_FILE"
echo "Done."
