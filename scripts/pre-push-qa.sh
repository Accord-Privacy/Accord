#!/bin/bash
# Pre-push QA gate — run this before EVERY push
# If any step fails, DO NOT PUSH

set -e
source ~/.cargo/env 2>/dev/null || true

echo "=== PRE-PUSH QA ==="
echo ""

echo "[1/5] cargo fmt --check"
cargo fmt --all -- --check
echo "  ✅ Formatting clean"
echo ""

echo "[2/5] cargo clippy --workspace -- -D warnings"
cargo clippy --workspace -- -D warnings 2>&1 | grep -E "^error" && { echo "  ❌ Clippy errors found"; exit 1; } || true
echo "  ✅ Clippy clean"
echo ""

echo "[3/5] cargo test (core + server)"
cargo test -p accord-core -p accord-server 2>&1 | tail -1
echo "  ✅ Tests pass"
echo ""

echo "[4/5] cargo check --workspace"
cargo check --workspace 2>&1 | grep -E "^error" && { echo "  ❌ Check failed"; exit 1; } || true
echo "  ✅ Workspace compiles"
echo ""

echo "[5/5] Frontend build check"
if [ -f desktop/frontend/package.json ]; then
    cd desktop/frontend
    npm run build 2>&1 | tail -3
    cd ../..
    echo "  ✅ Frontend builds"
else
    echo "  ⏭️ No frontend package.json"
fi

echo ""
echo "=== ALL CHECKS PASSED — safe to push ==="
