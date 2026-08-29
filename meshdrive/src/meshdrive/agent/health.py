"""Build /opt/meshdrive/var/state.json from config, mounts, and binaries."""

from __future__ import annotations

from typing import Any

from meshdrive.auth import list_users
from meshdrive.config import addon_status, backends, load_config, root
from meshdrive.constants import BIN, BOOTSTRAP_PASSWORD, CONTROL_HOST, CONTROL_PORT, VIX_FUSE_BIN, VIX_GATEWAY_BIN
from meshdrive.state import default_state
from meshdrive.storage.filebrowser import filebrowser_version, which_filebrowser
from meshdrive.storage.juicefs import (
    disk_stats,
    fuse_available,
    is_mounted,
    juicefs_version,
    parse_capacity_gb,
    which_juicefs,
)


def _component_status(ok: bool, missing: bool = False) -> str:
    if missing:
        return "missing"
    return "ready" if ok else "error"


def collect_state(*, agent_status: str = "running") -> dict[str, Any]:
    cfg = load_config()
    md = root(cfg)
    fb = md.get("filebrowser") or {}
    juice = which_juicefs()
    fb_bin = which_filebrowser()
    users = list_users()

    storage_rows = []
    for backend in backends(cfg):
        mount = backend.get("mount_point") or ""
        stats = disk_stats(
            mount if mount else (backend.get("data_path") or "."),
            capacity_gb=parse_capacity_gb(backend.get("capacity_gb")),
        )
        row = {
            "name": backend.get("name"),
            "type": backend.get("type", "juicefs"),
            "mount_point": mount,
            "data_path": backend.get("data_path"),
            "capacity_gb": backend.get("capacity_gb"),
            "formatted": bool(backend.get("formatted")),
            **stats,
            "mounted": is_mounted(mount) if mount else False,
        }
        storage_rows.append(row)

    mounted_any = any(row.get("mounted") for row in storage_rows)
    fb_url = f"http://{fb.get('address', '127.0.0.1')}:{fb.get('port', 8080)}"

    state = default_state()
    state["agent"] = {
        "status": agent_status,
        "listen": f"{CONTROL_HOST}:{CONTROL_PORT}",
    }
    state["components"] = {
        "fuse": {"status": _component_status(fuse_available(), missing=not fuse_available())},
        "juicefs": {
            "status": "ready" if juice else "missing",
            "version": juicefs_version(juice),
            "path": str(juice) if juice else "",
        },
        "filebrowser": {
            "status": "ready" if fb_bin else "missing",
            "version": filebrowser_version(fb_bin),
            "path": str(fb_bin) if fb_bin else "",
            "url": fb_url if fb_bin else "",
            "listening": _port_open(str(fb.get("address") or "127.0.0.1"), int(fb.get("port") or 8080)),
        },
    }
    state["storage"] = storage_rows
    state["users"] = {"count": len(users), "items": users}
    state["addons"] = addon_status(cfg)
    _overlay_addon_binaries(state["addons"])
    state["bootstrap_password_present"] = BOOTSTRAP_PASSWORD.is_file()
    state["filebrowser_url"] = fb_url
    state["mounted"] = mounted_any
    return state


def _overlay_addon_binaries(addons: dict[str, Any]) -> None:
    if (BIN / "openfga").is_file() and addons.get("openfga", {}).get("status") == "not_installed":
        addons["openfga"]["status"] = "installed"
        addons["openfga"]["message"] = "binary present; start meshdrive-openfga"
    if (BIN / "otelcol-contrib").is_file() and addons.get("telemetry", {}).get("status") == "not_installed":
        addons["telemetry"]["status"] = "installed"
        addons["telemetry"]["message"] = "binary present; start meshdrive-otel"
    if (BIN / "meshdrive-mcp").is_file() and addons.get("mcp", {}).get("status") == "not_installed":
        addons["mcp"]["status"] = "installed"
        addons["mcp"]["message"] = "wrapper present; run meshdrive addons install mcp if MCP extra is missing"
    if VIX_GATEWAY_BIN.is_file() and addons.get("vix_gateway", {}).get("status") == "not_installed":
        addons["vix_gateway"]["status"] = "installed"
        addons["vix_gateway"]["message"] = "binary present; run meshdrive addons install vix-gateway"
    if VIX_FUSE_BIN.is_file() and addons.get("vix_fuse", {}).get("status") == "not_installed":
        addons["vix_fuse"]["status"] = "installed"
        addons["vix_fuse"]["message"] = "binary present; run meshdrive addons install vix-fuse"


def _port_open(host: str, port: int) -> bool:
    import socket

    try:
        with socket.create_connection((host, port), timeout=0.3):
            return True
    except OSError:
        return False
