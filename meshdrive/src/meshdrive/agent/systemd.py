"""Thin wrappers around systemctl; no-op-friendly when systemd is missing."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def systemd_available() -> bool:
    return Path("/run/systemd/system").exists() and shutil.which("systemctl") is not None


def systemctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def unit_is_active(unit: str) -> bool:
    if not systemd_available():
        return False
    proc = systemctl("is-active", "--quiet", unit)
    return proc.returncode == 0


def start_unit(unit: str) -> None:
    if not systemd_available():
        raise RuntimeError("systemd is not available on this host")
    proc = systemctl("start", unit)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or f"systemctl start {unit} failed").strip())


def stop_unit(unit: str) -> None:
    if not systemd_available():
        return
    systemctl("stop", unit)


def disable_unit(unit: str) -> None:
    if not systemd_available():
        return
    systemctl("disable", "--now", unit)


def enable_now(unit: str) -> None:
    if not systemd_available():
        raise RuntimeError("systemd is not available on this host")
    proc = systemctl("enable", "--now", unit)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or f"systemctl enable {unit} failed").strip())


def mount_unit(name: str) -> str:
    return f"meshdrive-mount@{name}.service"


def filebrowser_unit() -> str:
    return "meshdrive-filebrowser.service"
