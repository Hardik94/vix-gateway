#!/usr/bin/env bash
# Fill JuiceFS + Filebrowser sha256 values in in.vistrix.MeshDrive.yaml
# Usage: ./flatpak/update-binary-sources.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${ROOT}/flatpak/in.vistrix.MeshDrive.yaml"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

JFS_URL="https://github.com/juicedata/juicefs/releases/download/v1.4.1/juicefs-1.4.1-linux-amd64.tar.gz"
FB_URL="https://github.com/filebrowser/filebrowser/releases/download/v2.63.23/linux-amd64-filebrowser.tar.gz"

echo "[flatpak] downloading JuiceFS…"
curl -fsSL -o "${TMP}/juicefs.tgz" "${JFS_URL}"
JFS_SHA="$(sha256sum "${TMP}/juicefs.tgz" | awk '{print $1}')"

echo "[flatpak] downloading Filebrowser…"
curl -fsSL -L -o "${TMP}/filebrowser.tgz" "${FB_URL}"
FB_SHA="$(sha256sum "${TMP}/filebrowser.tgz" | awk '{print $1}')"

echo "[flatpak] JuiceFS sha256=${JFS_SHA}"
echo "[flatpak] Filebrowser sha256=${FB_SHA}"

python3 - "${MANIFEST}" "${JFS_SHA}" "${FB_SHA}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
jfs_sha, fb_sha = sys.argv[2], sys.argv[3]
text = path.read_text(encoding="utf-8")
if "REPLACE_WITH_JUICEFS_SHA256" not in text and "REPLACE_WITH_FILEBROWSER_SHA256" not in text:
    # Already filled — replace existing quoted sha256 on those archive blocks by URL context
    import re
    text = re.sub(
        r'(url: https://github.com/juicedata/juicefs/releases/download/v1\.4\.1/juicefs-1\.4\.1-linux-amd64\.tar\.gz\n\s+sha256: ")[^"]+(")',
        rf"\g<1>{jfs_sha}\2",
        text,
        count=1,
    )
    text = re.sub(
        r'(url: https://github.com/filebrowser/filebrowser/releases/download/v2\.63\.23/linux-amd64-filebrowser\.tar\.gz\n\s+sha256: ")[^"]+(")',
        rf"\g<1>{fb_sha}\2",
        text,
        count=1,
    )
else:
    text = text.replace("REPLACE_WITH_JUICEFS_SHA256", jfs_sha, 1)
    text = text.replace("REPLACE_WITH_FILEBROWSER_SHA256", fb_sha, 1)
path.write_text(text, encoding="utf-8")
print(f"[flatpak] updated {path}")
PY
