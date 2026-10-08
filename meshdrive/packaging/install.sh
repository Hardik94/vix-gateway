#!/usr/bin/env bash
# Install MeshDrive 2.0 from a git checkout or extracted tarball.
#
# Usage:
#   sudo ./packaging/install.sh
#   sudo ./packaging/install.sh mcp openfga otel
#   sudo ./packaging/install.sh addons
#   sudo ./packaging/install.sh --with mcp,openfga,otel
#
# Core always lives under /opt/meshdrive (config, state, binaries).
# Add-on data also stays there. WireGuard is not installed yet.
set -euo pipefail

usage() {
  cat <<'EOF'
MeshDrive 2.0 installer (isolated under /opt/meshdrive)

  sudo ./packaging/install.sh                 # core: agent, TUI, JuiceFS, Filebrowser
  sudo ./packaging/install.sh addons          # mcp + openfga + otel
  sudo ./packaging/install.sh mcp             # one module
  sudo ./packaging/install.sh openfga
  sudo ./packaging/install.sh otel
  sudo ./packaging/install.sh --with mcp,openfga,otel

  After core is installed you can also run:
  sudo meshdrive-addons install mcp openfga otel
  sudo meshdrive-addons list

WireGuard is not available in this release.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "${HERE}/.." && pwd)"
ROOT="${MESHDRIVE_ROOT:-/opt/meshdrive}"

log() { echo "[meshdrive install] $*"; }

CORE=0
ADDONS=()
parse_with() {
  local spec="$1"
  local part
  IFS=',' read -ra parts <<< "${spec}"
  for part in "${parts[@]}"; do
    part="$(echo "${part}" | tr -d ' ')"
    [[ -z "${part}" ]] && continue
    ADDONS+=("${part}")
  done
}

if [[ $# -eq 0 ]]; then
  CORE=1
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      core) CORE=1 ;;
      addons|all) ADDONS+=(mcp openfga otel) ;;
      mcp|openfga|otel) ADDONS+=("$1") ;;
      --with)
        shift
        parse_with "${1:-}"
        ;;
      --with=*) parse_with "${1#--with=}" ;;
      wireguard)
        echo "WireGuard is not available yet" >&2
        exit 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        usage
        exit 1
        ;;
    esac
    shift
  done
fi

if [[ ${#ADDONS[@]} -gt 0 && ! -x "${ROOT}/bin/meshdrive-agent" ]]; then
  log "core not present; installing core first"
  CORE=1
fi
if [[ ${#ADDONS[@]} -eq 0 ]]; then
  CORE=1
fi

if [[ "${CORE}" -eq 1 ]]; then
  log "installing MeshDrive 2.0 core into ${ROOT} from ${SRC}"
  mkdir -p "${ROOT}"
  if [[ -d "${SRC}/overlay/opt/meshdrive" ]]; then
    if [[ -f "${ROOT}/etc/config.yaml" ]]; then
      while IFS= read -r -d '' item; do
        rel="${item#${SRC}/overlay/opt/meshdrive/}"
        case "${rel}" in
          etc/config.yaml|etc/auth.yaml|etc/filebrowser.json|etc/otel-collector.yaml) continue ;;
        esac
        if [[ -d "${item}" ]]; then
          mkdir -p "${ROOT}/${rel}"
        else
          mkdir -p "$(dirname "${ROOT}/${rel}")"
          cp -a "${item}" "${ROOT}/${rel}"
        fi
      done < <(find "${SRC}/overlay/opt/meshdrive" -print0)
      log "kept existing isolated config under ${ROOT}/etc"
    else
      cp -a "${SRC}/overlay/opt/meshdrive/." "${ROOT}/"
    fi
  fi

  rm -rf "${ROOT}/pkg"
  mkdir -p "${ROOT}/pkg" "${ROOT}/packaging"
  cp -a "${SRC}/src" "${SRC}/pyproject.toml" "${SRC}/README.md" "${ROOT}/pkg/"
  install -m 0755 "${HERE}/fetch-binaries.sh" "${ROOT}/packaging/fetch-binaries.sh"
  install -m 0755 "${HERE}/setup-runtime.sh" "${ROOT}/packaging/setup-runtime.sh"

  if [[ -d "${SRC}/overlay/usr/share/applications" ]]; then
    install -D -m 0644 "${SRC}/overlay/usr/share/applications/meshdrive-tui.desktop" \
      /usr/share/applications/meshdrive-tui.desktop
  fi

  export MESHDRIVE_ROOT="${ROOT}"
  bash "${HERE}/setup-runtime.sh"
fi

if [[ ${#ADDONS[@]} -gt 0 ]]; then
  log "installing add-ons: ${ADDONS[*]}"
  export MESHDRIVE_ROOT="${ROOT}"
  if [[ -x "${ROOT}/bin/meshdrive-addons" ]]; then
    "${ROOT}/bin/meshdrive-addons" install "${ADDONS[@]}"
  elif [[ -x "${ROOT}/venv/bin/meshdrive-addons" ]]; then
    "${ROOT}/venv/bin/meshdrive-addons" install "${ADDONS[@]}"
  else
    echo "meshdrive-addons not found; re-run core install" >&2
    exit 1
  fi
fi

log "done. Config stays in ${ROOT}/etc (not in your home directory)."
log "Next: meshdrive-tui   or   sudo meshdrive-addons list"
