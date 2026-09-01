#!/usr/bin/env bash
# Ensure meshdrive.local resolves on this host (IPv4 + IPv6 when present).
#
# Recommendation:
#   - /etc/hosts  → this machine only (offline-safe)
#   - Avahi/mDNS  → other devices on the LAN (preferred for phones/laptops)
#     sudo apt-get install -y avahi-daemon
#     sudo hostnamectl set-hostname meshdrive   # → meshdrive.local via mDNS
#
# Usage:
#   sudo ./packaging/ensure-local-hostname.sh
#   MESHDRIVE_LOCAL_FQDN=files.local sudo ./packaging/ensure-local-hostname.sh
set -euo pipefail

FQDN="${MESHDRIVE_LOCAL_FQDN:-meshdrive.local}"
MARKER_BEGIN="# BEGIN meshdrive-local-hostname"
MARKER_END="# END meshdrive-local-hostname"
HOSTS_FILE="${MESHDRIVE_HOSTS_FILE:-/etc/hosts}"

primary_ipv4() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{
    for (i = 1; i <= NF; i++) if ($i == "src") { print $(i+1); exit }
  }' || true
}

primary_ipv6() {
  ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{
    for (i = 1; i <= NF; i++) if ($i == "src") { print $(i+1); exit }
  }' || true
}

IPV4="$(primary_ipv4)"
IPV6="$(primary_ipv6)"

LINES=()
LINES+=("127.0.0.1 ${FQDN}")
LINES+=("::1 ${FQDN}")
if [[ -n "${IPV4}" && "${IPV4}" != "127.0.0.1" ]]; then
  LINES+=("${IPV4} ${FQDN}")
fi
if [[ -n "${IPV6}" && "${IPV6}" != "::1" && "${IPV6}" != fe80* ]]; then
  LINES+=("${IPV6} ${FQDN}")
fi

BLOCK="${MARKER_BEGIN}"$'\n'
for line in "${LINES[@]}"; do
  BLOCK+="${line}"$'\n'
done
BLOCK+="${MARKER_END}"

if [[ ! -w "${HOSTS_FILE}" ]]; then
  echo "[meshdrive] cannot write ${HOSTS_FILE} (need root)" >&2
  echo "[meshdrive] would install:"
  printf '%s\n' "${BLOCK}"
  exit 1
fi

TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

if grep -qF "${MARKER_BEGIN}" "${HOSTS_FILE}" 2>/dev/null; then
  awk -v begin="${MARKER_BEGIN}" -v end="${MARKER_END}" '
    $0 == begin {skip=1; next}
    $0 == end {skip=0; next}
    !skip {print}
  ' "${HOSTS_FILE}" > "${TMP}"
else
  cp "${HOSTS_FILE}" "${TMP}"
fi

printf '\n%s\n' "${BLOCK}" >> "${TMP}"
cp "${TMP}" "${HOSTS_FILE}"

echo "[meshdrive] ${FQDN} entries:"
printf '  %s\n' "${LINES[@]}"

AVAHI_DIR="/etc/avahi/services"
if [[ -d "${AVAHI_DIR}" ]]; then
  cat > "${AVAHI_DIR}/meshdrive.service" <<EOF
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">MeshDrive on %h</name>
  <service>
    <type>_http._tcp</type>
    <port>8080</port>
    <txt-record>path=/</txt-record>
  </service>
</service-group>
EOF
  systemctl try-reload-or-restart avahi-daemon 2>/dev/null || true
  echo "[meshdrive] Avahi HTTP service published"
  echo "[meshdrive] For meshdrive.local via mDNS: sudo hostnamectl set-hostname meshdrive"
fi
