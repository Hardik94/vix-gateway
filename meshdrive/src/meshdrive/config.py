"""Load and save MeshDrive YAML configuration."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from meshdrive.constants import AUTH_PATH, CONFIG_PATH, MNT, ROOT, VAR

_EMPTY = {
    "meshdrive": {
        "version": "2.0.0",
        "mode": "local",
        "storage": {"backends": []},
        "filebrowser": {
            "enabled": True,
            # Empty → all interfaces (IPv4 + IPv6). Use "127.0.0.1" for loopback-only.
            "address": "",
            "hostname": "meshdrive.local",
            "port": 8080,
            "root": str(MNT),
            "database": str(VAR / "filebrowser.db"),
        },
        "auth": {"backend": "local", "path": str(AUTH_PATH), "session_timeout": 3600},
        "mcp": {
            "enabled": False,
            "status": "not_installed",
            "host": "127.0.0.1",
            "port": 9000,
            "progress": 0,
        },
        "openfga": {
            "enabled": False,
            "status": "not_installed",
            "http": "127.0.0.1:8081",
            "progress": 0,
        },
        "telemetry": {
            "enabled": False,
            "status": "not_installed",
            "privacy_level": "anonymized",
            "send_interval": 86400,
            "progress": 0,
            "mode": "local_file",
        },
        "wireguard": {"enabled": False, "status": "not_installed", "progress": 0, "message": "Paid — meshdrive license activate"},
        "vix_gateway": {"enabled": False, "status": "not_installed", "progress": 0, "message": "Paid — requires license"},
        "vix_fuse": {"enabled": False, "status": "not_installed", "progress": 0, "message": "Paid — requires license + WG"},
        "sssd": {"enabled": False, "status": "not_installed", "progress": 0, "message": "Paid — LDAP over WireGuard"},
        "remote_cluster": {"enabled": False, "status": "not_installed", "progress": 0, "message": "Paid — remote JuiceFS over WG"},
        "isolation": {
            "root_dir": str(ROOT),
            "user": "meshdrive",
            "group": "meshdrive",
            "allowed_paths": [str(ROOT)],
        },
    }
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or CONFIG_PATH
    if not cfg_path.is_file():
        return deepcopy(_EMPTY)
    with cfg_path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        return deepcopy(_EMPTY)
    return _deep_merge(_EMPTY, raw)


def save_config(data: dict[str, Any], path: Path | None = None) -> None:
    cfg_path = path or CONFIG_PATH
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    with cfg_path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, default_flow_style=False, sort_keys=False)


def root(data: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = data if data is not None else load_config()
    return cfg.setdefault("meshdrive", {})


def backends(data: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    storage = root(data).setdefault("storage", {})
    items = storage.setdefault("backends", [])
    if not isinstance(items, list):
        storage["backends"] = []
        return storage["backends"]
    return items


def get_backend(name: str, data: dict[str, Any] | None = None) -> dict[str, Any] | None:
    for item in backends(data):
        if item.get("name") == name:
            return item
    return None


def upsert_backend(backend: dict[str, Any], data: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = data if data is not None else load_config()
    items = backends(cfg)
    name = backend["name"]
    for idx, item in enumerate(items):
        if item.get("name") == name:
            items[idx] = {**item, **backend}
            save_config(cfg)
            return cfg
    items.append(backend)
    save_config(cfg)
    return cfg


def delete_backend(name: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = data if data is not None else load_config()
    items = backends(cfg)
    kept = [item for item in items if item.get("name") != name]
    if len(kept) == len(items):
        raise KeyError(f"unknown backend {name!r}")
    root(cfg).setdefault("storage", {})["backends"] = kept
    save_config(cfg)
    return cfg


def addon_status(data: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    from meshdrive.license import is_paid

    md = root(data)
    out: dict[str, dict[str, Any]] = {}
    paid_keys = {
        "wireguard": "wireguard",
        "vix_gateway": "vix-gateway",
        "vix_fuse": "vix-fuse",
        "sssd": "sssd-ldap",
        "remote_cluster": "remote-cluster",
    }
    free_keys = ("mcp", "openfga", "telemetry")
    for key in (*free_keys, *paid_keys):
        block = md.get(key) or {}
        status = block.get("status", "not_installed")
        progress = int(block.get("progress") or 0)
        locked = key in paid_keys and not is_paid()
        if status == "ready":
            progress = 100
            message = block.get("message") or "ready"
        elif status == "installing":
            message = block.get("message") or "installing"
        elif locked:
            message = "🔒 Paid — meshdrive license activate --token …"
        elif status == "not_installed":
            install_name = paid_keys.get(key) or ("otel" if key == "telemetry" else key)
            message = block.get("message") or f"Install: meshdrive addons install {install_name}"
        else:
            message = block.get("message") or status
        out[key] = {
            "status": status,
            "enabled": bool(block.get("enabled", False)),
            "progress": progress,
            "message": message,
            "tier": "paid" if key in paid_keys else "free",
            "locked": locked,
        }
    return out
