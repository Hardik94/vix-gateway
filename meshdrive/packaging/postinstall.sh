#!/usr/bin/env bash
# dpkg postinst for meshdrive 2.0.0
set -euo pipefail

ROOT="/opt/meshdrive"
export MESHDRIVE_ROOT="${ROOT}"

if [[ -x "${ROOT}/packaging/setup-runtime.sh" ]]; then
  bash "${ROOT}/packaging/setup-runtime.sh"
elif [[ -x /usr/share/meshdrive/setup-runtime.sh ]]; then
  bash /usr/share/meshdrive/setup-runtime.sh
else
  echo "[meshdrive postinst] setup-runtime.sh not found" >&2
  exit 1
fi

exit 0
