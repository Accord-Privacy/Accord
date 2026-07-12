#!/usr/bin/env bash
# release.sh — Build, sign, and publish an Accord desktop release.
#
# Usage:
#   TAURI_SIGNING_PRIVATE_KEY_PATH=~/.tauri/accord-updater.key ./scripts/release.sh [--draft]
#
# Produces (Linux; Windows artifacts come from CI):
#   - .deb + .AppImage bundles, updater-signed (.sig)
#   - latest.json  — tauri-plugin-updater feed (endpoint already set in tauri.conf.json)
#   - HASHES.json  — sha256 of every artifact for reproducible-build verification
# and uploads everything to a GitHub Release tagged v<version>.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

DRAFT_FLAG=""
if [[ "${1:-}" == "--draft" ]]; then
    DRAFT_FLAG="--draft"
fi

# Tauri CLI expects the key CONTENT in TAURI_SIGNING_PRIVATE_KEY.
# Accept a _PATH for convenience and inline it.
if [[ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" && -n "${TAURI_SIGNING_PRIVATE_KEY_PATH:-}" ]]; then
    export TAURI_SIGNING_PRIVATE_KEY="$(cat "${TAURI_SIGNING_PRIVATE_KEY_PATH}")"
fi
if [[ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
    echo "ERROR: set TAURI_SIGNING_PRIVATE_KEY (or _PATH) — updater signing key required." >&2
    exit 1
fi
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}" 

VERSION=$(python3 -c "import json; print(json.load(open('desktop/tauri.conf.json'))['version'])")
TAG="v${VERSION}"
BUNDLE_DIR="target/release/bundle"

echo "═══ Accord release ${TAG} ═══"

# ── 1. QA gate ─────────────────────────────────────────────────────
bash scripts/pre-push-qa.sh

# ── 2. Build signed Linux bundles ──────────────────────────────────
# APPIMAGE_EXTRACT_AND_RUN: linuxdeploy self-extracts instead of requiring FUSE2
# NO_STRIP: linuxdeploy's bundled strip is too old for modern .relr.dyn sections
(cd desktop && NO_STRIP=true APPIMAGE_EXTRACT_AND_RUN=1 frontend/node_modules/.bin/tauri build --bundles deb,appimage)

DEB=$(ls "${BUNDLE_DIR}"/deb/*.deb | head -1)
APPIMAGE=$(ls "${BUNDLE_DIR}"/appimage/*.AppImage | head -1)
APPIMAGE_SIG="${APPIMAGE}.sig"

for f in "$DEB" "$APPIMAGE" "$APPIMAGE_SIG"; do
    [[ -f "$f" ]] || { echo "ERROR: expected artifact missing: $f" >&2; exit 1; }
done

# ── 3. latest.json (tauri-plugin-updater feed) ─────────────────────
RELEASE_BASE="https://github.com/Accord-Privacy/Accord/releases/download/${TAG}"
PUB_DATE=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
SIGNATURE=$(cat "$APPIMAGE_SIG")

python3 - "$VERSION" "$PUB_DATE" "$RELEASE_BASE" "$(basename "$APPIMAGE")" "$SIGNATURE" << 'PYEOF' > latest.json
import json, sys
version, pub_date, base, appimage, sig = sys.argv[1:6]
json.dump({
    "version": version,
    "notes": f"Accord {version} — see the GitHub release for the changelog.",
    "pub_date": pub_date,
    "platforms": {
        "linux-x86_64": {
            "signature": sig,
            "url": f"{base}/{appimage}",
        },
    },
}, sys.stdout, indent=2)
PYEOF

# ── 4. HASHES.json (reproducible-build verification) ──────────────
python3 - "$VERSION" "$DEB" "$APPIMAGE" << 'PYEOF' > HASHES.json
import hashlib, json, os, subprocess, sys
version = sys.argv[1]
files = sys.argv[2:]
def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
json.dump({
    "version": version,
    "commit": commit,
    "artifacts": {os.path.basename(p): {"sha256": sha256(p), "bytes": os.path.getsize(p)} for p in files},
}, sys.stdout, indent=2)
PYEOF

echo ""
echo "── artifacts ──"
ls -la "$DEB" "$APPIMAGE" "$APPIMAGE_SIG" latest.json HASHES.json

# ── 5. GitHub Release ──────────────────────────────────────────────
gh release create "$TAG" $DRAFT_FLAG \
    --title "Accord ${VERSION}" \
    --generate-notes \
    "$DEB" "$APPIMAGE" "$APPIMAGE_SIG" latest.json HASHES.json

rm -f latest.json HASHES.json
echo "═══ Released ${TAG} ═══"
