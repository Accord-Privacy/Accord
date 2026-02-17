#!/usr/bin/env bash
# build-rust.sh — Cross-compile accord-core for Android targets
# Produces .so libraries for inclusion in the Android app.
#
# Prerequisites:
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#   Android NDK installed (set ANDROID_NDK_HOME)
#
# Usage:
#   ./build-rust.sh [release|debug]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CORE_DIR="$REPO_ROOT/core"
OUT_DIR="$SCRIPT_DIR/app/src/main/jniLibs"

PROFILE="${1:-release}"
if [ "$PROFILE" = "release" ]; then
    CARGO_FLAGS="--release"
    TARGET_SUBDIR="release"
else
    CARGO_FLAGS=""
    TARGET_SUBDIR="debug"
fi

# ── NDK detection ─────────────────────────────────────────────────────────────

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    # Try common locations
    if [ -d "$HOME/Android/Sdk/ndk" ]; then
        ANDROID_NDK_HOME="$(ls -d "$HOME/Android/Sdk/ndk/"* 2>/dev/null | sort -V | tail -1)"
    elif [ -d "$HOME/Library/Android/sdk/ndk" ]; then
        ANDROID_NDK_HOME="$(ls -d "$HOME/Library/Android/sdk/ndk/"* 2>/dev/null | sort -V | tail -1)"
    fi
fi

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "ERROR: ANDROID_NDK_HOME not set and NDK not found in default locations."
    echo "Set ANDROID_NDK_HOME to your Android NDK installation directory."
    exit 1
fi

echo "Using NDK: $ANDROID_NDK_HOME"

# ── Toolchain setup ──────────────────────────────────────────────────────────

TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt"
if [ -d "$TOOLCHAIN/linux-x86_64" ]; then
    TOOLCHAIN="$TOOLCHAIN/linux-x86_64"
elif [ -d "$TOOLCHAIN/darwin-x86_64" ]; then
    TOOLCHAIN="$TOOLCHAIN/darwin-x86_64"
elif [ -d "$TOOLCHAIN/darwin-aarch64" ]; then
    TOOLCHAIN="$TOOLCHAIN/darwin-aarch64"
else
    echo "ERROR: Could not find NDK prebuilt toolchain in $TOOLCHAIN"
    exit 1
fi

# Min API level
API_LEVEL=21

declare -A TARGET_MAP=(
    ["aarch64-linux-android"]="arm64-v8a"
    ["armv7-linux-androideabi"]="armeabi-v7a"
    ["x86_64-linux-android"]="x86_64"
)

declare -A CC_MAP=(
    ["aarch64-linux-android"]="aarch64-linux-android${API_LEVEL}-clang"
    ["armv7-linux-androideabi"]="armv7a-linux-androideabi${API_LEVEL}-clang"
    ["x86_64-linux-android"]="x86_64-linux-android${API_LEVEL}-clang"
)

declare -A AR_MAP=(
    ["aarch64-linux-android"]="llvm-ar"
    ["armv7-linux-androideabi"]="llvm-ar"
    ["x86_64-linux-android"]="llvm-ar"
)

# ── Build ─────────────────────────────────────────────────────────────────────

echo "Building accord-core for Android ($PROFILE)..."

for TARGET in "${!TARGET_MAP[@]}"; do
    ABI="${TARGET_MAP[$TARGET]}"
    CC="${CC_MAP[$TARGET]}"
    AR="${AR_MAP[$TARGET]}"

    echo ""
    echo "━━━ Building for $TARGET ($ABI) ━━━"

    # Cargo target-specific env vars (uppercase with underscores)
    TARGET_UPPER="${TARGET//-/_}"
    TARGET_UPPER="${TARGET_UPPER^^}"

    export "CC_${TARGET_UPPER}=$TOOLCHAIN/bin/$CC"
    export "AR_${TARGET_UPPER}=$TOOLCHAIN/bin/$AR"
    export "CARGO_TARGET_${TARGET_UPPER}_LINKER=$TOOLCHAIN/bin/$CC"

    cargo build \
        --manifest-path "$CORE_DIR/Cargo.toml" \
        --target "$TARGET" \
        --features android \
        $CARGO_FLAGS

    # Copy .so to jniLibs
    mkdir -p "$OUT_DIR/$ABI"
    cp "$REPO_ROOT/target/$TARGET/$TARGET_SUBDIR/libaccord_core.so" \
       "$OUT_DIR/$ABI/libaccord_core.so"

    echo "  → $OUT_DIR/$ABI/libaccord_core.so"
done

echo ""
echo "✅ Android build complete!"
echo "   Output: $OUT_DIR/"
