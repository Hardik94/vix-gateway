#!/bin/sh
# Flatpak entrypoint: keep all MeshDrive state under the app data dir.
set -eu

APP_ID="${FLATPAK_ID:-in.vistrix.MeshDrive}"
DATA_HOME="${XDG_DATA_HOME:-${HOME}/.var/app/${APP_ID}/data}"
ROOT="${MESHDRIVE_ROOT:-${DATA_HOME}/meshdrive}"
export MESHDRIVE_ROOT="${ROOT}"

# Bundled install tree (read-only) lives under /app
SHARE="/app/share/meshdrive"
BIN_DIR="/app/libexec/meshdrive/bin"
VENV_BIN="/app/libexec/meshdrive/venv/bin"

mkdir -p \
  "${ROOT}/etc" \
  "${ROOT}/var/log" \
  "${ROOT}/var/cache" \
  "${ROOT}/var/meta" \
  "${ROOT}/var/data" \
  "${ROOT}/var/tmp" \
  "${ROOT}/mnt" \
  "${ROOT}/bin"

# Seed default configs once (never overwrite user edits)
if [ -d "${SHARE}/etc" ]; then
  for f in "${SHARE}/etc/"*; do
    [ -e "$f" ] || continue
    base="$(basename "$f")"
    if [ ! -e "${ROOT}/etc/${base}" ]; then
      cp -a "$f" "${ROOT}/etc/${base}"
    fi
  done
fi

# Expose JuiceFS / Filebrowser on PATH for the Python package
if [ -d "${BIN_DIR}" ]; then
  # Symlink into writable ROOT/bin so juicefs candidates resolve
  for b in juicefs filebrowser; do
    if [ -x "${BIN_DIR}/${b}" ] && [ ! -e "${ROOT}/bin/${b}" ]; then
      ln -sf "${BIN_DIR}/${b}" "${ROOT}/bin/${b}"
    fi
  done
  export PATH="${BIN_DIR}:${PATH}"
fi

CMD="${1:-meshdrive-tui}"
shift || true

case "${CMD}" in
  meshdrive|meshdrive-tui|meshdrive-agent|meshdrive-addons|meshdrive-mount|meshdrive-mcp)
    exec "${VENV_BIN}/${CMD}" "$@"
    ;;
  doctor)
    exec "${VENV_BIN}/meshdrive" doctor "$@"
    ;;
  *)
    # Allow `flatpak run … --command=meshdrive-wrapper meshdrive status`
    if [ -x "${VENV_BIN}/${CMD}" ]; then
      exec "${VENV_BIN}/${CMD}" "$@"
    fi
    exec "${VENV_BIN}/meshdrive" "${CMD}" "$@"
    ;;
esac
