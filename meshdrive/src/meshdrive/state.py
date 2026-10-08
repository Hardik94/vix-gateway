"""Health snapshot written to var/state.json and served by the agent API."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from meshdrive.constants import STATE_PATH, VERSION, ensure_runtime_dirs


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_state() -> dict[str, Any]:
    return {
        "version": VERSION,
        "updated_at": _now(),
        "agent": {"status": "starting", "listen": ""},
        "components": {
            "fuse": {"status": "unknown"},
            "juicefs": {"status": "missing"},
            "filebrowser": {"status": "missing", "url": ""},
        },
        "storage": [],
        "users": {"count": 0},
        "addons": {
            "mcp": {"status": "not_installed", "progress": 0, "message": "Install later"},
            "openfga": {"status": "not_installed", "progress": 0, "message": "Install later"},
            "wireguard": {"status": "not_installed", "progress": 0, "message": "Install later"},
            "telemetry": {"status": "not_installed", "progress": 0, "message": "Install later"},
        },
        "bootstrap_password_present": False,
        "errors": [],
    }


def load_state(path: Path | None = None) -> dict[str, Any]:
    state_path = path or STATE_PATH
    if not state_path.is_file():
        return default_state()
    try:
        with state_path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            base = default_state()
            base.update(data)
            return base
    except (OSError, json.JSONDecodeError):
        pass
    return default_state()


def save_state(data: dict[str, Any], path: Path | None = None) -> None:
    ensure_runtime_dirs()
    state_path = path or STATE_PATH
    data = dict(data)
    data["updated_at"] = _now()
    tmp = state_path.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    tmp.replace(state_path)
