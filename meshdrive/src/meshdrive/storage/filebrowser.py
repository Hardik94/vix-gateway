"""Filebrowser binary helpers and local user sync."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from meshdrive.constants import (
    FILEBROWSER_BIN_CANDIDATES,
    FILEBROWSER_DB,
    FILEBROWSER_JSON,
    FILEBROWSER_MIN_PASSWORD_LENGTH,
)

MIN_PASSWORD_LENGTH = FILEBROWSER_MIN_PASSWORD_LENGTH


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
    """Write Filebrowser config compatible with v2.32+ / v2.63.x.

    Empty ``address`` makes Filebrowser listen on ``:port`` (dual-stack
    IPv4+IPv6 on Linux). ``127.0.0.1`` / ``::1`` keep loopback-only.
    """
    cfg_path = path or FILEBROWSER_JSON
    Path(root).mkdir(parents=True, exist_ok=True)
    db = database or str(FILEBROWSER_DB)
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    # Preserve empty string (all interfaces); do not coerce to 127.0.0.1.
    bind = "" if address is None else str(address)
    payload = {
        "port": int(port),
        "baseURL": "",
        "address": bind,
        "log": "stdout",
        "database": db,
        "root": root,
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


def _run(cmd: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    # Prefer running as meshdrive so filebrowser.db ownership stays correct
    # (agent often runs as root; the Filebrowser unit runs as meshdrive).
    final = list(cmd)
    if os.geteuid() == 0:
        try:
            import pwd

            pwd.getpwnam("meshdrive")
            if shutil.which("runuser"):
                final = ["runuser", "-u", "meshdrive", "--", *cmd]
            elif shutil.which("sudo"):
                final = ["sudo", "-n", "-u", "meshdrive", "--", *cmd]
        except KeyError:
            pass
    return subprocess.run(final, capture_output=True, text=True, timeout=timeout, check=False)


def _combined(proc: subprocess.CompletedProcess[str]) -> str:
    return ((proc.stderr or "") + (proc.stdout or "")).strip()


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters "
            "(Filebrowser requirement)"
        )


def list_filebrowser_usernames(binary: Path | None = None) -> list[str]:
    bin_path = binary or which_filebrowser()
    if not bin_path or not FILEBROWSER_DB.is_file():
        return []
    proc = _run([str(bin_path), "users", "ls", "-d", str(FILEBROWSER_DB)])
    if proc.returncode != 0:
        return []
    names: list[str] = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0].lower() in {"id", "---"}:
            continue
        # Table: ID Username Scope Admin ...
        if parts[0].isdigit():
            names.append(parts[1])
    return names


def add_filebrowser_user(
    username: str,
    password: str,
    *,
    admin: bool = False,
    scope: str | None = None,
) -> None:
    """Create or update a Filebrowser account (password always applied).

    ``scope`` limits the UI to a subdirectory (private home). Admins usually
    keep the global root; non-admins should receive their private path.
    """
    validate_password(password)
    binary = which_filebrowser()
    if not binary:
        raise RuntimeError("filebrowser binary not found")
    db = FILEBROWSER_DB
    db.parent.mkdir(parents=True, exist_ok=True)

    # Prefer update when the user already exists so password stays in sync.
    existing = list_filebrowser_usernames(binary)
    if username in existing:
        cmd = [str(binary), "users", "update", username, "-p", password, "-d", str(db)]
        if scope:
            cmd.extend(["--scope", scope])
        proc = _run(cmd)
        if proc.returncode != 0:
            raise RuntimeError(_combined(proc) or "filebrowser users update failed")
        if admin:
            _run(
                [
                    str(binary),
                    "users",
                    "update",
                    username,
                    "--perm.admin",
                    "-d",
                    str(db),
                ]
            )
        return

    cmd = [str(binary), "users", "add", username, password, "-d", str(db)]
    if admin:
        cmd.append("--perm.admin")
    if scope:
        cmd.extend(["--scope", scope])
    proc = _run(cmd)
    if proc.returncode == 0:
        return
    combined = _combined(proc).lower()
    if "already exists" in combined:
        cmd2 = [
            str(binary),
            "users",
            "update",
            username,
            "-p",
            password,
            "-d",
            str(db),
        ]
        if scope:
            cmd2.extend(["--scope", scope])
        proc2 = _run(cmd2)
        if proc2.returncode != 0:
            raise RuntimeError(_combined(proc2) or "filebrowser users update failed")
        return
    raise RuntimeError(_combined(proc) or "filebrowser users add failed")


def set_filebrowser_scope(username: str, scope: str) -> None:
    """Set Filebrowser --scope for an existing user (private home)."""
    binary = which_filebrowser()
    if not binary:
        raise RuntimeError("filebrowser binary not found")
    proc = _run(
        [
            str(binary),
            "users",
            "update",
            username,
            "--scope",
            scope,
            "-d",
            str(FILEBROWSER_DB),
        ]
    )
    if proc.returncode != 0:
        raise RuntimeError(_combined(proc) or "filebrowser scope update failed")


def delete_filebrowser_user(username: str) -> None:
    binary = which_filebrowser()
    if not binary or not FILEBROWSER_DB.is_file():
        return
    _run([str(binary), "users", "rm", username, "-d", str(FILEBROWSER_DB)])
