"""Shared paths and version for MeshDrive 2.0."""

from __future__ import annotations

import os
from pathlib import Path

from meshdrive import __version__

VERSION = __version__

# Pinned binary versions (keep in sync with packaging/fetch-binaries.sh defaults)
PINNED_JUICEFS_VERSION = "1.4.1"
PINNED_FILEBROWSER_VERSION = "2.63.23"


def _resolve_root() -> Path:
    if os.environ.get("MESHDRIVE_ROOT"):
        return Path(os.environ["MESHDRIVE_ROOT"])
    # Snap: always prefer $SNAP_COMMON (real writable dir). Do not rely on the
    # /opt/meshdrive layout bind — a host /opt/meshdrive from a prior .deb can
    # break the agent. Never use $SNAP (read-only) or $SNAP_DATA (per-rev).
    snap_common = os.environ.get("SNAP_COMMON")
    if snap_common:
        return Path(snap_common)
    if os.environ.get("SNAP"):
        return Path("/var/snap/meshdrive/common")
    # Flatpak: XDG_DATA_HOME is ~/.var/app/<app-id>/data when FLATPAK_ID is set
    if os.environ.get("FLATPAK_ID"):
        xdg_data = os.environ.get("XDG_DATA_HOME")
        if xdg_data:
            return Path(xdg_data) / "meshdrive"
    return Path("/opt/meshdrive")


ROOT = _resolve_root()
SNAP = os.environ.get("SNAP")
SNAP_DATA = os.environ.get("SNAP_DATA")

ETC = ROOT / "etc"
VAR = ROOT / "var"
BIN = ROOT / "bin"
MNT = ROOT / "mnt"
SHARE = Path(SNAP) / "share" / "meshdrive" if SNAP else ROOT / "share"

# Read-only binaries shipped in the package. Under snap, ROOT is SNAP_COMMON
# (writable data via layout bind), while juicefs/filebrowser live under $SNAP.
def _shipped_bin_dirs() -> tuple[Path, ...]:
    dirs: list[Path] = []
    if SNAP:
        dirs.append(Path(SNAP) / "opt" / "meshdrive" / "bin")
        dirs.append(Path(SNAP) / "bin")
    dirs.append(BIN)
    # de-dupe while preserving order
    seen: set[Path] = set()
    out: list[Path] = []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return tuple(out)


SHIPPED_BIN_DIRS = _shipped_bin_dirs()
PACKAGE_BIN = SHIPPED_BIN_DIRS[0]

CONFIG_PATH = ETC / "config.yaml"
AUTH_PATH = ETC / "auth.yaml"
LICENSE_PATH = ETC / "license.yaml"
CLUSTER_PATH = ETC / "cluster.yaml"
STATE_PATH = VAR / "state.json"
FILEBROWSER_JSON = ETC / "filebrowser.json"
FILEBROWSER_DB = VAR / "filebrowser.db"
BOOTSTRAP_PASSWORD = VAR / "bootstrap-password.txt"
CONTROL_LOG = VAR / "log" / "agent.log"
WG_STATE = VAR / "wireguard" / "state.json"

CONTROL_HOST = os.environ.get("MESHDRIVE_CONTROL_HOST", "127.0.0.1")
CONTROL_PORT = int(os.environ.get("MESHDRIVE_CONTROL_PORT", "12700"))


def control_bind_host(host: str | None = None) -> str:
    """Normalize agent bind address to IPv4 loopback (snap-safe).

    ``localhost`` can resolve to IPv6 (::1) and fail with EACCES under some
    snap/AppArmor setups. Keep the control API on ``127.0.0.1`` unless an
    explicit non-loopback host is configured.
    """
    raw = (host if host is not None else CONTROL_HOST) or "127.0.0.1"
    h = str(raw).strip().lower()
    if h in {"", "localhost", "::1", "[::1]", "*"}:
        return "127.0.0.1"
    return str(raw).strip()

# Filebrowser default --minimumPasswordLength (v2.32+)
FILEBROWSER_MIN_PASSWORD_LENGTH = 12

ADDON_KEYS = ("mcp", "openfga", "wireguard", "telemetry", "vix_gateway", "vix_fuse", "sssd", "remote_cluster")

FREE_ADDONS = frozenset({"mcp", "openfga", "otel", "telemetry"})
PAID_ADDONS = frozenset(
    {"wireguard", "vix-gateway", "vix-fuse", "sssd-ldap", "remote-cluster", "vix_gateway", "vix_fuse", "sssd", "remote_cluster"}
)

JUICEFS_BIN_CANDIDATES = tuple(d / "juicefs" for d in SHIPPED_BIN_DIRS) + (
    Path("/usr/local/bin/juicefs"),
    Path("/usr/bin/juicefs"),
)
FILEBROWSER_BIN_CANDIDATES = tuple(d / "filebrowser" for d in SHIPPED_BIN_DIRS) + (
    Path("/usr/local/bin/filebrowser"),
)
OPENFGA_BIN_CANDIDATES = tuple(d / "openfga" for d in SHIPPED_BIN_DIRS)
OTEL_BIN_CANDIDATES = tuple(d / "otelcol-contrib" for d in SHIPPED_BIN_DIRS)
# Paid/runtime binaries land in ROOT/bin (SNAP_COMMON under snap).
VIX_GATEWAY_BIN = BIN / "vix_cpp_gateway"
VIX_FUSE_BIN = BIN / "vix_cpp_fuse"


def ensure_runtime_dirs() -> None:
    for path in (
        ETC,
        VAR,
        VAR / "log",
        VAR / "cache",
        VAR / "meta",
        VAR / "data",
        VAR / "telemetry",
        VAR / "openfga",
        VAR / "wireguard",
        VAR / "tmp",
        MNT,
        BIN,
    ):
        path.mkdir(parents=True, exist_ok=True)
