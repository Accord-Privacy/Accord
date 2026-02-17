#!/bin/bash
# Pre-push QA gate — run this before EVERY push
# If any step fails, DO NOT PUSH

set -euo pipefail
source ~/.cargo/env 2>/dev/null || true

echo "=== PRE-PUSH QA ==="
echo ""

echo "[1/5] cargo fmt --check"
if ! cargo fmt --all -- --check; then
    echo "  ❌ Formatting issues found. Run 'cargo fmt' to fix."
    exit 1
fi
echo "  ✅ Formatting clean"
echo ""

echo "[2/5] cargo clippy --workspace -- -D warnings"
if ! cargo clippy --workspace -- -D warnings 2>&1; then
    echo "  ❌ Clippy errors found"
    exit 1
fi
echo "  ✅ Clippy clean"
echo ""

echo "[3/5] cargo test (core + server)"
if ! cargo test -p accord-core -p accord-server 2>&1; then
    echo "  ❌ Tests failed"
    exit 1
fi
echo "  ✅ Tests pass"
echo ""

echo "[4/5] cargo check --workspace"
if ! cargo check --workspace 2>&1; then
    echo "  ❌ Workspace check failed"
    exit 1
fi
echo "  ✅ Workspace compiles"
echo ""

echo "[5/5] Frontend build check"
if [ -f desktop/frontend/package.json ]; then
    cd desktop/frontend
    if ! npx vite build 2>&1; then
        echo "  ❌ Frontend build failed"
        exit 1
    fi
    # TypeScript type check
    if ! npx tsc --noEmit 2>&1; then
        echo "  ❌ TypeScript type errors found"
        exit 1
    fi
    cd ../..
    echo "  ✅ Frontend builds"
else
    echo "  ⏭️ No frontend package.json"
fi

echo ""
echo "=== ALL CHECKS PASSED — safe to push ==="
