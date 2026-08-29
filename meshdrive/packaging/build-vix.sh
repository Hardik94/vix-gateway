#!/usr/bin/env bash
# Build vix_cpp_gateway and/or vix_cpp_fuse from vix_package (Linux amd64, requires Rust + cmake).
set -euo pipefail

ROOT="${1:-/opt/meshdrive}"
TARGET="${2:-all}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VIX_ROOT="${REPO_ROOT}/vix_package"
OUT_BIN="${ROOT}/bin"
mkdir -p "${OUT_BIN}"

build_gateway() {
  if [[ ! -d "${VIX_ROOT}/cpp_gateway" ]]; then
    echo "missing ${VIX_ROOT}/cpp_gateway" >&2
    return 1
  fi
  cmake -S "${VIX_ROOT}/cpp_gateway" -B /tmp/vix-gateway-build -DCMAKE_BUILD_TYPE=Release
  cmake --build /tmp/vix-gateway-build -j"$(nproc)"
  install -m 0755 /tmp/vix-gateway-build/vix_cpp_gateway "${OUT_BIN}/vix_cpp_gateway"
  echo "built ${OUT_BIN}/vix_cpp_gateway"
}

build_fuse() {
  if [[ ! -d "${VIX_ROOT}/cpp_fuse" ]]; then
    echo "missing ${VIX_ROOT}/cpp_fuse" >&2
    return 1
  fi
  cmake -S "${VIX_ROOT}/cpp_fuse" -B /tmp/vix-fuse-build -DCMAKE_BUILD_TYPE=Release
  cmake --build /tmp/vix-fuse-build -j"$(nproc)"
  install -m 0755 /tmp/vix-fuse-build/vix_cpp_fuse "${OUT_BIN}/vix_cpp_fuse"
  echo "built ${OUT_BIN}/vix_cpp_fuse"
}

case "${TARGET}" in
  gateway) build_gateway ;;
  fuse) build_fuse ;;
  all)
    build_gateway || echo "gateway build skipped"
    build_fuse || echo "fuse build skipped"
    ;;
  *)
    echo "usage: $0 [ROOT] [gateway|fuse|all]" >&2
    exit 1
    ;;
esac
