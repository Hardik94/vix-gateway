#!/bin/bash
# Run MeshDrive agent in the foreground (no systemd inside the container).
set -euo pipefail

export MESHDRIVE_ROOT="${MESHDRIVE_ROOT:-/opt/meshdrive}"
export MESHDRIVE_CONTROL_HOST="${MESHDRIVE_CONTROL_HOST:-0.0.0.0}"
export PYTHONUNBUFFERED=1

# FUSE for JuiceFS mounts (compose should pass /dev/fuse + SYS_ADMIN or privileged).
if [[ -e /dev/fuse ]]; then
  chmod 666 /dev/fuse 2>/dev/null || true
fi
modprobe fuse 2>/dev/null || true

mkdir -p \
  "${MESHDRIVE_ROOT}/var/log" \
  "${MESHDRIVE_ROOT}/var/cache" \
  "${MESHDRIVE_ROOT}/mnt"

AGENT=""
for candidate in \
  "${MESHDRIVE_ROOT}/bin/meshdrive-agent" \
  /usr/local/bin/meshdrive-agent \
  "$(command -v meshdrive-agent 2>/dev/null || true)"
do
  if [[ -n "${candidate}" && -x "${candidate}" ]]; then
    AGENT="${candidate}"
    break
  fi
done

if [[ -z "${AGENT}" ]]; then
  echo "meshdrive-agent not found after .deb install" >&2
  exit 1
fi

# Optional free add-on install on first start (downloads MCP deps into the image FS).
if [[ "${MESHDRIVE_INSTALL_MCP:-0}" == "1" ]]; then
  if command -v meshdrive >/dev/null 2>&1; then
    echo "[entrypoint] installing MCP addon…"
    meshdrive addons install mcp || echo "[entrypoint] MCP install failed (non-fatal)" >&2
  fi
fi

if [[ "${MESHDRIVE_INSTALL_OPENFGA:-0}" == "1" ]]; then
  if command -v meshdrive >/dev/null 2>&1; then
    echo "[entrypoint] installing OpenFGA addon…"
    meshdrive addons install openfga || echo "[entrypoint] OpenFGA install failed (non-fatal)" >&2
  fi
fi

echo "[entrypoint] starting ${AGENT} (MESHDRIVE_ROOT=${MESHDRIVE_ROOT} CONTROL_HOST=${MESHDRIVE_CONTROL_HOST})"
exec "${AGENT}"
