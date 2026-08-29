"""Filebrowser binary helpers and local user sync."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from meshdrive.constants import FILEBROWSER_BIN_CANDIDATES, FILEBROWSER_DB, FILEBROWSER_JSON


def which_filebrowser() -> Path | None:
    for candidate in FILEBROWSER_BIN_CANDIDATES:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("filebrowser")
    return Path(found) if found else None


def filebrowser_version(binary: Path | None = None) -> str | None:
    bin_path = binary or which_filebrowser()
    if not bin_path:
        return None
    try:
        proc = subprocess.run(
            [str(bin_path), "version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or proc.stderr or "").strip()
    return text.splitlines()[0] if text else None


def write_filebrowser_json(
    *,
    address: str,
    port: int,
    root: str,
    database: str | None = None,
    path: Path | None = None,
) -> None:
    """Write Filebrowser config compatible with v2.32+ / v2.63.x."""
    cfg_path = path or FILEBROWSER_JSON
    Path(root).mkdir(parents=True, exist_ok=True)
    db = database or str(FILEBROWSER_DB)
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "port": int(port),
        "baseURL": "",
        "address": address or "127.0.0.1",
        "log": "stdout",
        "database": db,
        "root": root,
        # Stable defaults for newer Filebrowser releases
        "disableThumbnails": False,
        "disablePreviewResize": False,
        "disableExec": True,
        "disableShell": True,
    }
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        cfg_path.chmod(0o644)
    except OSError:
        pass


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)


def add_filebrowser_user(username: str, password: str, *, admin: bool = False) -> None:
    binary = which_filebrowser()
    if not binary:
        return
    db = FILEBROWSER_DB
    db.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(binary), "users", "add", username, password, "-d", str(db)]
    if admin:
        cmd.extend(["--perm.admin"])
    proc = _run(cmd)
    if proc.returncode != 0:
        combined = (proc.stderr or "") + (proc.stdout or "")
        if "already exists" in combined.lower():
            return
        raise RuntimeError(combined.strip() or "filebrowser users add failed")


def delete_filebrowser_user(username: str) -> None:
    binary = which_filebrowser()
    if not binary or not FILEBROWSER_DB.is_file():
        return
    _run([str(binary), "users", "rm", username, "-d", str(FILEBROWSER_DB)])
