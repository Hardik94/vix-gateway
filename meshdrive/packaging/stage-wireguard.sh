#!/usr/bin/env bash
# Copy WireGuard hub-spoke templates into the MeshDrive install root.
set -euo pipefail
ROOT="${1:-/opt/meshdrive}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
DEST="${ROOT}/share/wireguard"
mkdir -p "${DEST}"
if [[ -d "${REPO}/infra/wireguard-hub-spoke" ]]; then
  WG="${REPO}/infra/wireguard-hub-spoke"
  cp "${WG}/clients/node.template/wg0.conf.template" "${DEST}/" 2>/dev/null || true
  cp "${WG}/scripts/nft-client.nft" "${DEST}/" 2>/dev/null || true
  cp "${WG}/docs/environment-ip-plan.md" "${DEST}/" 2>/dev/null || true
elif [[ -d "${HERE}/../overlay/opt/meshdrive/share/wireguard" ]]; then
  cp -a "${HERE}/../overlay/opt/meshdrive/share/wireguard/." "${DEST}/"
fi
echo "wireguard templates -> ${DEST}"
