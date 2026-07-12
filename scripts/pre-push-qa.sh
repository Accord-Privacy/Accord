#!/bin/bash
# Pre-push QA gate — run this before EVERY push
# If any step fails, DO NOT PUSH
set -euo pipefail
source ~/.cargo/env 2>/dev/null || true
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && source "$NVM_DIR/nvm.sh" 2>/dev/null || true

echo "=== PRE-PUSH QA ==="
echo ""

echo "[1/6] cargo fmt --check"
if ! cargo fmt --all -- --check; then
    echo "  ❌ Formatting issues found. Run 'cargo fmt' to fix."
    exit 1
fi
echo "  ✅ Formatting clean"
echo ""

echo "[2/6] cargo clippy --workspace --all-targets -- -D warnings"
if ! cargo clippy --workspace --all-targets -- -D warnings 2>&1; then
    echo "  ❌ Clippy errors found"
    exit 1
fi
echo "  ✅ Clippy clean"
echo ""

echo "[3/6] cargo test (core + server)"
if ! cargo test -p accord-core -p accord-server 2>&1; then
    echo "  ❌ Tests failed"
    exit 1
fi
echo "  ✅ Tests pass"
echo ""

echo "[4/6] cargo check --workspace --all-targets"
if ! cargo check --workspace --all-targets 2>&1; then
    echo "  ❌ Workspace check failed (includes benches/examples — keep them compiling)"
    exit 1
fi
echo "  ✅ Workspace compiles (all targets)"
echo ""

echo "[5/6] cargo audit"
# cargo finds subcommands in $CARGO_HOME/bin even when it's not on PATH,
# so probe via cargo itself rather than command -v.
if ! cargo audit --version >/dev/null 2>&1; then
    echo "  ❌ cargo-audit not installed. Install with: cargo install cargo-audit --locked"
    exit 1
fi
if ! cargo audit 2>&1; then
    echo "  ❌ cargo audit found unaddressed advisories (see .cargo/audit.toml for accepted ones)"
    exit 1
fi
echo "  ✅ No unaddressed advisories"
echo ""

echo "[6/6] Frontend build + typecheck + tests"
if [ -f desktop/frontend/package.json ]; then
    if ! command -v npm >/dev/null 2>&1; then
        echo "  ❌ Node.js/npm not found. Frontend checks are mandatory — install Node 20+."
        exit 1
    fi
    cd desktop/frontend
    if ! npx vite build 2>&1; then
        echo "  ❌ Frontend build failed"
        exit 1
    fi
    if ! npx tsc --noEmit 2>&1; then
        echo "  ❌ TypeScript type errors found"
        exit 1
    fi
    if ! npx vitest run 2>&1; then
        echo "  ❌ Frontend unit tests failed"
        exit 1
    fi
    cd ../..
    echo "  ✅ Frontend builds, typechecks, and tests pass"
else
    echo "  ⏭️ No frontend package.json"
fi

echo ""
echo "=== ALL CHECKS PASSED — safe to push ==="
