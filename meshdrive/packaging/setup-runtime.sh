#!/usr/bin/env bash
# Shared post-copy setup: user, venv, wrappers, binaries, fuse, systemd.
# Expects overlay + Python sources already under /opt/meshdrive.
set -euo pipefail

ROOT="${MESHDRIVE_ROOT:-/opt/meshdrive}"
PKG="${ROOT}/pkg"
VENV="${ROOT}/venv"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "[meshdrive setup] $*"; }

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[meshdrive setup] must run as root" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[meshdrive setup] python3 is required" >&2
  exit 1
fi

# --- user and directories ---
if ! id meshdrive >/dev/null 2>&1; then
  useradd --system --home "${ROOT}" --shell /usr/sbin/nologin --user-group meshdrive
  log "created system user meshdrive"
fi
getent group meshdrive >/dev/null 2>&1 || groupadd --system meshdrive

mkdir -p \
  "${ROOT}/bin" \
  "${ROOT}/etc" \
  "${ROOT}/var/log" \
  "${ROOT}/var/cache" \
  "${ROOT}/var/meta" \
  "${ROOT}/var/data" \
  "${ROOT}/var/telemetry" \
  "${ROOT}/var/openfga" \
  "${ROOT}/var/tmp" \
  "${ROOT}/mnt"

chmod 750 "${ROOT}/etc" "${ROOT}/var"
chmod 600 "${ROOT}/etc/auth.yaml" 2>/dev/null || true
chmod 644 "${ROOT}/etc/config.yaml" 2>/dev/null || true

# --- Python venv ---
if [[ ! -x "${VENV}/bin/python" ]]; then
  python3 -m venv "${VENV}"
fi
"${VENV}/bin/pip" install --upgrade pip wheel >/dev/null
if [[ -f "${PKG}/pyproject.toml" ]]; then
  log "installing meshdrive Python package"
  "${VENV}/bin/pip" install "${PKG}"
else
  echo "[meshdrive setup] missing ${PKG}/pyproject.toml" >&2
  exit 1
fi

cat > "${ROOT}/bin/meshdrive" <<EOF
#!/bin/sh
exec ${VENV}/bin/meshdrive "\$@"
EOF
cat > "${ROOT}/bin/meshdrive-agent" <<EOF
#!/bin/sh
exec ${VENV}/bin/meshdrive-agent "\$@"
EOF
cat > "${ROOT}/bin/meshdrive-tui" <<EOF
#!/bin/sh
exec ${VENV}/bin/meshdrive-tui "\$@"
EOF
cat > "${ROOT}/bin/meshdrive-mount" <<EOF
#!/bin/sh
exec ${VENV}/bin/meshdrive-mount "\$@"
EOF
cat > "${ROOT}/bin/meshdrive-addons" <<EOF
#!/bin/sh
exec ${VENV}/bin/meshdrive-addons "\$@"
EOF
cat > "${ROOT}/bin/meshdrive-mcp" <<EOF
#!/bin/sh
exec ${VENV}/bin/python -m meshdrive.mcp "\$@"
EOF
chmod 0755 "${ROOT}/bin/meshdrive" "${ROOT}/bin/meshdrive-agent" "${ROOT}/bin/meshdrive-tui" "${ROOT}/bin/meshdrive-mount" \
  "${ROOT}/bin/meshdrive-addons" "${ROOT}/bin/meshdrive-mcp"

ln -sfn "${ROOT}/bin/meshdrive" /usr/local/bin/meshdrive
ln -sfn "${ROOT}/bin/meshdrive-tui" /usr/local/bin/meshdrive-tui
ln -sfn "${ROOT}/bin/meshdrive-agent" /usr/local/bin/meshdrive-agent
ln -sfn "${ROOT}/bin/meshdrive-addons" /usr/local/bin/meshdrive-addons

# --- pinned binaries ---
if [[ -x "${HERE}/fetch-binaries.sh" ]]; then
  bash "${HERE}/fetch-binaries.sh" "${ROOT}" || log "WARNING: binary fetch failed (JuiceFS/Filebrowser). Install later or re-run fetch-binaries.sh"
elif [[ -x "${ROOT}/packaging/fetch-binaries.sh" ]]; then
  bash "${ROOT}/packaging/fetch-binaries.sh" "${ROOT}" || log "WARNING: binary fetch failed"
else
  log "fetch-binaries.sh not found; skip JuiceFS/Filebrowser download"
fi

if [[ -x "${HERE}/stage-wireguard.sh" ]]; then
  bash "${HERE}/stage-wireguard.sh" "${ROOT}" || true
elif [[ -x "${ROOT}/packaging/stage-wireguard.sh" ]]; then
  bash "${ROOT}/packaging/stage-wireguard.sh" "${ROOT}" || true
fi

# --- Filebrowser database ---
if [[ -x "${ROOT}/bin/filebrowser" && ! -f "${ROOT}/var/filebrowser.db" ]]; then
  log "initializing Filebrowser database"
  "${ROOT}/bin/filebrowser" config init -d "${ROOT}/var/filebrowser.db" >/dev/null 2>&1 || true
  "${ROOT}/bin/filebrowser" config set \
    -d "${ROOT}/var/filebrowser.db" \
    --address 127.0.0.1 \
    --port 8080 \
    --root "${ROOT}/mnt" \
    --minimumPasswordLength 12 >/dev/null 2>&1 || true
fi

if [[ ! -f "${ROOT}/var/bootstrap-password.txt" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 18 | tr -d '\n' > "${ROOT}/var/bootstrap-password.txt"
  else
    head -c 18 /dev/urandom | base64 | tr -d '\n' > "${ROOT}/var/bootstrap-password.txt"
  fi
  echo >> "${ROOT}/var/bootstrap-password.txt"
  chmod 600 "${ROOT}/var/bootstrap-password.txt"
  log "wrote one-time admin password to ${ROOT}/var/bootstrap-password.txt"
fi

# --- FUSE ---
if [[ -f /etc/fuse.conf ]] && grep -q '^#user_allow_other' /etc/fuse.conf; then
  sed -i 's/^#user_allow_other/user_allow_other/' /etc/fuse.conf || true
  log "enabled user_allow_other in /etc/fuse.conf"
fi
if command -v modprobe >/dev/null 2>&1; then
  modprobe fuse 2>/dev/null || true
fi

# --- systemd units ---
if [[ -d "${ROOT}/systemd" ]]; then
  install -m 0644 "${ROOT}/systemd/meshdrive-agent.service" /etc/systemd/system/meshdrive-agent.service
  install -m 0644 "${ROOT}/systemd/meshdrive-mount@.service" /etc/systemd/system/meshdrive-mount@.service
  install -m 0644 "${ROOT}/systemd/meshdrive-filebrowser.service" /etc/systemd/system/meshdrive-filebrowser.service
fi
if [[ -f "${ROOT}/systemd/sudoers" ]]; then
  install -m 0440 "${ROOT}/systemd/sudoers" /etc/sudoers.d/meshdrive
fi
if [[ -f "${ROOT}/../usr/share/applications/meshdrive-tui.desktop" ]]; then
  install -D -m 0644 "${ROOT}/../usr/share/applications/meshdrive-tui.desktop" \
    /usr/share/applications/meshdrive-tui.desktop
fi
# desktop file may live next to overlay
SCRIPT_ROOT="$(cd "${HERE}/.." && pwd)"
if [[ -f "${SCRIPT_ROOT}/overlay/usr/share/applications/meshdrive-tui.desktop" ]]; then
  install -D -m 0644 "${SCRIPT_ROOT}/overlay/usr/share/applications/meshdrive-tui.desktop" \
    /usr/share/applications/meshdrive-tui.desktop
fi

chown -R meshdrive:meshdrive "${ROOT}/etc" "${ROOT}/var" "${ROOT}/mnt"
# agent/mount need to write state and mount as root; keep bin owned by root
chown root:root "${ROOT}/bin" "${ROOT}/bin/"* 2>/dev/null || true

if [[ -n "${SUDO_USER:-}" ]]; then
  usermod -aG meshdrive "${SUDO_USER}" 2>/dev/null || true
  log "added ${SUDO_USER} to group meshdrive (re-login required)"
fi

if [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
  systemctl enable meshdrive-agent.service
  # Do not start mount or filebrowser; configure via TUI first.
  # Start the agent so the TUI can talk to it immediately.
  systemctl restart meshdrive-agent.service || systemctl start meshdrive-agent.service || true
  log "meshdrive-agent.service enabled and started"
  log "run: meshdrive-tui"
else
  log "systemd not running; skip systemctl"
fi

log "setup complete"
