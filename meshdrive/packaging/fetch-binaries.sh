#!/usr/bin/env bash
# Download pinned binaries into DEST/bin.
# Usage:
#   fetch-binaries.sh [DEST] [juicefs|filebrowser|openfga|otel ...]
# Default modules: juicefs filebrowser
set -euo pipefail

ROOT="${MESHDRIVE_ROOT:-/opt/meshdrive}"
MODULES=()

for arg in "$@"; do
  case "${arg}" in
    juicefs|filebrowser|openfga|otel|mcp) MODULES+=("${arg}") ;;
    *)
      ROOT="${arg}"
      ;;
  esac
done

if [[ ${#MODULES[@]} -eq 0 ]]; then
  MODULES=(juicefs filebrowser)
fi

BIN="${ROOT}/bin"
TMP="${ROOT}/var/tmp/downloads"
ARCH_RAW="$(uname -m)"

JFS_VERSION="${MESHDRIVE_JUICEFS_VERSION:-1.4.1}"
FB_VERSION="${MESHDRIVE_FILEBROWSER_VERSION:-2.63.23}"
OPENFGA_VERSION="${MESHDRIVE_OPENFGA_VERSION:-1.8.12}"
OTEL_VERSION="${MESHDRIVE_OTEL_VERSION:-0.119.1}"

case "${ARCH_RAW}" in
  x86_64|amd64)
    JFS_ARCH="amd64"
    FB_ARCH="amd64"
    OG_ARCH="amd64"
    OT_ARCH="amd64"
    ;;
  aarch64|arm64)
    JFS_ARCH="arm64"
    FB_ARCH="arm64"
    OG_ARCH="arm64"
    OT_ARCH="arm64"
    ;;
  *)
    echo "[meshdrive] fetch-binaries: unsupported arch (got ${ARCH_RAW}; need amd64 or arm64)" >&2
    exit 1
    ;;
esac

mkdir -p "${BIN}" "${TMP}"

need_cmd() { command -v "$1" >/dev/null 2>&1; }

if ! need_cmd curl; then
  echo "[meshdrive] curl is required to fetch binaries" >&2
  exit 1
fi
if ! need_cmd tar; then
  echo "[meshdrive] tar is required to fetch binaries" >&2
  exit 1
fi

want() {
  local name="$1"
  local m
  for m in "${MODULES[@]}"; do
    [[ "${m}" == "${name}" ]] && return 0
  done
  return 1
}

# Extract a single executable member from a tarball (avoid unpacking full trees).
# OpenFGA release archives include assets/*.sql that hit EPERM under some snap/AppArmor setups.
extract_binary_member() {
  local tarball="$1"
  local dest_dir="$2"
  local bin_name="$3"
  local member
  member="$(
    tar -tzf "${tarball}" 2>/dev/null | awk -v n="${bin_name}" '
      $0 == n || $0 == "./" n { print; exit }
      $0 ~ ("/" n "$") && $0 !~ /\/assets\// { print; exit }
    '
  )"
  if [[ -z "${member}" ]]; then
    echo "[meshdrive] ${bin_name} not found inside $(basename "${tarball}")" >&2
    return 1
  fi
  # Do not unpack migrations/assets; skip xattrs/ACLs (common EPERM under snap).
  local tar_opts=(--no-same-owner --no-same-permissions)
  if tar --help 2>/dev/null | grep -q -- '--no-acls'; then
    tar_opts+=(--no-acls)
  fi
  if tar --help 2>/dev/null | grep -q -- '--no-xattrs'; then
    tar_opts+=(--no-xattrs)
  fi
  if tar --help 2>/dev/null | grep -q -- '--no-selinux'; then
    tar_opts+=(--no-selinux)
  fi
  tar -xzf "${tarball}" -C "${dest_dir}" "${tar_opts[@]}" "${member}"
}


if want juicefs; then
  if [[ ! -x "${BIN}/juicefs" ]]; then
    echo "[meshdrive] downloading JuiceFS v${JFS_VERSION} (${JFS_ARCH})"
    jfs_tarball="${TMP}/juicefs-${JFS_VERSION}-linux-${JFS_ARCH}.tar.gz"
    curl -fsSL -o "${jfs_tarball}" \
      "https://github.com/juicedata/juicefs/releases/download/v${JFS_VERSION}/juicefs-${JFS_VERSION}-linux-${JFS_ARCH}.tar.gz"
    tar -xzf "${jfs_tarball}" -C "${TMP}"
    if [[ -f "${TMP}/juicefs" ]]; then
      install -m 0755 "${TMP}/juicefs" "${BIN}/juicefs"
    else
      echo "[meshdrive] juicefs binary missing from tarball" >&2
      exit 1
    fi
  else
    echo "[meshdrive] juicefs already present at ${BIN}/juicefs"
  fi
fi

if want filebrowser; then
  if [[ ! -x "${BIN}/filebrowser" ]]; then
    echo "[meshdrive] downloading Filebrowser v${FB_VERSION} (${FB_ARCH})"
    fb_tarball="${TMP}/filebrowser-${FB_VERSION}-linux-${FB_ARCH}.tar.gz"
    curl -fsSL -L -o "${fb_tarball}" \
      "https://github.com/filebrowser/filebrowser/releases/download/v${FB_VERSION}/linux-${FB_ARCH}-filebrowser.tar.gz"
    mkdir -p "${TMP}/filebrowser"
    tar -xzf "${fb_tarball}" -C "${TMP}/filebrowser"
    if [[ -f "${TMP}/filebrowser/filebrowser" ]]; then
      install -m 0755 "${TMP}/filebrowser/filebrowser" "${BIN}/filebrowser"
    elif [[ -f "${TMP}/filebrowser" && ! -d "${TMP}/filebrowser" ]]; then
      install -m 0755 "${TMP}/filebrowser" "${BIN}/filebrowser"
    else
      found="$(find "${TMP}/filebrowser" -maxdepth 2 -type f -name filebrowser | head -n 1 || true)"
      if [[ -n "${found}" ]]; then
        install -m 0755 "${found}" "${BIN}/filebrowser"
      else
        echo "[meshdrive] filebrowser binary missing from tarball" >&2
        exit 1
      fi
    fi
  else
    echo "[meshdrive] filebrowser already present at ${BIN}/filebrowser"
  fi
fi

if want openfga; then
  if [[ ! -x "${BIN}/openfga" ]]; then
    echo "[meshdrive] downloading OpenFGA v${OPENFGA_VERSION} (${OG_ARCH})"
    og_dir="${TMP}/openfga"
    rm -rf "${og_dir}"
    mkdir -p "${og_dir}"
    og_tarball="${TMP}/openfga_${OPENFGA_VERSION}_linux_${OG_ARCH}.tar.gz"
    curl -fsSL -L -o "${og_tarball}" \
      "https://github.com/openfga/openfga/releases/download/v${OPENFGA_VERSION}/openfga_${OPENFGA_VERSION}_linux_${OG_ARCH}.tar.gz"
    # Full extract fails under snap with EPERM on assets/migrations/*.sql — binary only.
    extract_binary_member "${og_tarball}" "${og_dir}" openfga
    found="$(find "${og_dir}" -maxdepth 3 -type f -name openfga | head -n 1 || true)"
    if [[ -z "${found}" ]]; then
      echo "[meshdrive] openfga binary missing after extract" >&2
      exit 1
    fi
    install -m 0755 "${found}" "${BIN}/openfga"
  else
    echo "[meshdrive] openfga already present at ${BIN}/openfga"
  fi
fi

if want otel; then
  if [[ ! -x "${BIN}/otelcol-contrib" ]]; then
    echo "[meshdrive] downloading otelcol-contrib v${OTEL_VERSION} (${OT_ARCH})"
    ot_dir="${TMP}/otelcol"
    rm -rf "${ot_dir}"
    mkdir -p "${ot_dir}"
    ot_tarball="${TMP}/otelcol-contrib_${OTEL_VERSION}_linux_${OT_ARCH}.tar.gz"
    curl -fsSL -L -o "${ot_tarball}" \
      "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v${OTEL_VERSION}/otelcol-contrib_${OTEL_VERSION}_linux_${OT_ARCH}.tar.gz"
    if ! extract_binary_member "${ot_tarball}" "${ot_dir}" otelcol-contrib; then
      tar -xzf "${ot_tarball}" -C "${ot_dir}" --no-same-owner --no-same-permissions
    fi
    found="$(find "${ot_dir}" -maxdepth 3 -type f -name otelcol-contrib | head -n 1 || true)"
    if [[ -z "${found}" ]]; then
      echo "[meshdrive] otelcol-contrib binary missing from tarball" >&2
      exit 1
    fi
    install -m 0755 "${found}" "${BIN}/otelcol-contrib"
  else
    echo "[meshdrive] otelcol-contrib already present at ${BIN}/otelcol-contrib"
  fi
fi

if want mcp; then
  echo "[meshdrive] mcp is a Python extra; install with: meshdrive-addons install mcp"
fi

echo "[meshdrive] binaries ready in ${BIN} (arch=${JFS_ARCH})"
