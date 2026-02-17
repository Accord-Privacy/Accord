#!/usr/bin/env bash
# build-rust.sh — Cross-compile accord-core for iOS targets
# Produces a universal static library (XCFramework) for use in Xcode.
#
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#
# Usage:
#   ./build-rust.sh [release|debug]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CORE_DIR="$REPO_ROOT/core"
OUT_DIR="$SCRIPT_DIR/build"

PROFILE="${1:-release}"
if [ "$PROFILE" = "release" ]; then
    CARGO_FLAGS="--release"
    TARGET_SUBDIR="release"
else
    CARGO_FLAGS=""
    TARGET_SUBDIR="debug"
fi

TARGETS=(
    "aarch64-apple-ios"
    "aarch64-apple-ios-sim"
)

LIB_NAME="libaccord_core.a"

echo "=== Building accord-core for iOS ($PROFILE) ==="

# Ensure targets are installed
for target in "${TARGETS[@]}"; do
    if ! rustup target list --installed | grep -q "$target"; then
        echo "Installing target: $target"
        rustup target add "$target"
    fi
done

# Build for each target
for target in "${TARGETS[@]}"; do
    echo "--- Building for $target ---"
    cargo build \
        --manifest-path "$CORE_DIR/Cargo.toml" \
        --target "$target" \
        $CARGO_FLAGS \
        --lib
done

# Create output directory
mkdir -p "$OUT_DIR"

# Copy individual static libraries
for target in "${TARGETS[@]}"; do
    SRC="$REPO_ROOT/target/$target/$TARGET_SUBDIR/$LIB_NAME"
    if [ ! -f "$SRC" ]; then
        echo "ERROR: Expected library not found: $SRC"
        exit 1
    fi
    mkdir -p "$OUT_DIR/$target"
    cp "$SRC" "$OUT_DIR/$target/$LIB_NAME"
    echo "  Copied $target/$LIB_NAME"
done

# Create XCFramework
XCFRAMEWORK_DIR="$OUT_DIR/AccordCore.xcframework"
rm -rf "$XCFRAMEWORK_DIR"

xcodebuild -create-xcframework \
    -library "$OUT_DIR/aarch64-apple-ios/$LIB_NAME" \
    -headers "$SCRIPT_DIR/AccordCore/include" \
    -library "$OUT_DIR/aarch64-apple-ios-sim/$LIB_NAME" \
    -headers "$SCRIPT_DIR/AccordCore/include" \
    -output "$XCFRAMEWORK_DIR"

echo ""
echo "=== Build complete ==="
echo "XCFramework: $XCFRAMEWORK_DIR"
echo "Individual libs: $OUT_DIR/<target>/$LIB_NAME"
echo ""
echo "To use in Xcode:"
echo "  1. Drag AccordCore.xcframework into your project"
echo "  2. Add AccordCore/module.modulemap to Swift import search paths"
echo "  3. import AccordCoreFFI in Swift files"
