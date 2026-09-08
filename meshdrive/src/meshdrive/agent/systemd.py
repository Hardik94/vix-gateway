"""Thin wrappers around systemctl; snap uses in-process mount/Filebrowser instead."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def snap_installed() -> bool:
    """True when the meshdrive snap is present (even outside snap-run env)."""
    if os.environ.get("SNAP"):
        return True
    return Path("/snap/meshdrive/current").exists()


def systemd_available() -> bool:
    return Path("/run/systemd/system").exists() and shutil.which("systemctl") is not None


def use_host_units() -> bool:
    """Host meshdrive-*.service units are for .deb / install.sh, not snap.

    Classic snap still has systemd, but the package units are not installed under
    /etc/systemd/system. Prefer direct juicefs/filebrowser process management.
    """
    if snap_installed():
        return False
    return systemd_available()


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


def snap_agent_unit() -> str:
    return "snap.meshdrive.agent.service"


def agent_unit() -> str:
    """Snap: snap.meshdrive.agent.service — never meshdrive-agent.service."""
    if snap_installed():
        return snap_agent_unit()
    return "meshdrive-agent.service"


def agent_start_hint() -> str:
    if snap_installed():
        return "sudo snap start meshdrive.agent"
    return "sudo systemctl start meshdrive-agent.service"
