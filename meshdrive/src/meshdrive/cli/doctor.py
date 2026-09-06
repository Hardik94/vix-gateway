"""meshdrive doctor — verify install, PATH, binaries, license, addons."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from meshdrive.constants import (
    AUTH_PATH,
    BIN,
    CONFIG_PATH,
    FILEBROWSER_BIN_CANDIDATES,
    JUICEFS_BIN_CANDIDATES,
    LICENSE_PATH,
    PACKAGE_BIN,
    ROOT,
    SHARE,
    SNAP,
    VAR,
    VIX_FUSE_BIN,
    VIX_GATEWAY_BIN,
    ensure_runtime_dirs,
)
from meshdrive.license import status_dict

# Host /usr/local names vs snap app names exposed under /snap/bin
_CLI_ALIASES: dict[str, tuple[str, ...]] = {
    "meshdrive": ("meshdrive",),
    "meshdrive-tui": ("meshdrive-tui", "meshdrive.tui"),
    "meshdrive-agent": ("meshdrive-agent", "meshdrive.agent"),
    "meshdrive-addons": ("meshdrive-addons", "meshdrive.addons"),
}


def _which(name: str) -> str | None:
    return shutil.which(name)


def _find_bin(candidates: tuple[Path, ...]) -> Path | None:
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return path
    return None


def _resolve_cli(name: str) -> str | None:
    for alias in _CLI_ALIASES.get(name, (name,)):
        found = _which(alias)
        if found:
            return found
    # Already running inside the snap: wrappers exist even if aliases are unset.
    if SNAP:
        snap_root = Path(SNAP)
        wrapper_map = {
            "meshdrive": "meshdrive-wrapper",
            "meshdrive-tui": "meshdrive-tui-wrapper",
            "meshdrive-agent": "meshdrive-agent-wrapper",
            "meshdrive-addons": "meshdrive-addons-wrapper",
        }
        wrapper = snap_root / "bin" / wrapper_map.get(name, "")
        if wrapper.is_file() and os.access(wrapper, os.X_OK):
            return str(wrapper)
    return None


def _check_python_env() -> dict[str, Any]:
    """Deb/source installs use a venv; snap uses relocatable python-packages."""
    if SNAP:
        site = Path(SNAP) / "opt" / "meshdrive" / "python-packages"
        pkg = site / "meshdrive"
        py = Path(SNAP) / "usr" / "bin" / "python3"
        if not py.is_file():
            found = shutil.which("python3")
            py_s = found
        else:
            py_s = str(py)
        return {
            "mode": "snap-target",
            "path": str(site),
            "exists": site.is_dir(),
            "python": py_s,
            "ok": pkg.is_dir() and bool(py_s),
        }

    venv = ROOT / "venv"
    py = venv / "bin" / "python"
    return {
        "mode": "venv",
        "path": str(venv),
        "exists": venv.is_dir(),
        "python": str(py) if py.is_file() else None,
        "ok": py.is_file(),
    }


def _check_systemd_unit(name: str) -> dict[str, Any]:
    if not shutil.which("systemctl"):
        return {"available": False}
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return {"available": True, "active": proc.stdout.strip(), "ok": proc.returncode == 0}
    except (OSError, subprocess.TimeoutExpired):
        return {"available": True, "ok": False, "error": "systemctl failed"}


def run(verbose: bool = False) -> dict[str, Any]:
    ensure_runtime_dirs()
    issues: list[str] = []

    cli_names = ("meshdrive", "meshdrive-tui", "meshdrive-agent", "meshdrive-addons")
    cli_on_path = {n: _resolve_cli(n) for n in cli_names}

    for name, loc in cli_on_path.items():
        if not loc:
            issues.append(f"{name} not on PATH")

    juicefs = _find_bin(JUICEFS_BIN_CANDIDATES)
    filebrowser = _find_bin(FILEBROWSER_BIN_CANDIDATES)
    if not juicefs:
        issues.append("juicefs binary missing")
    if not filebrowser:
        issues.append("filebrowser binary missing")

    py_env = _check_python_env()
    if not py_env["ok"]:
        if py_env.get("mode") == "snap-target":
            issues.append("python packages missing or broken (snap python-packages)")
        else:
            issues.append("python venv missing or broken")

    lic = status_dict()
    agent = _check_systemd_unit("meshdrive-agent.service")
    if SNAP:
        # Classic snap runs agent as snap daemon, not host systemd unit.
        snap_agent = _check_systemd_unit("snap.meshdrive.agent.service")
        if snap_agent.get("available"):
            agent = {**snap_agent, "unit": "snap.meshdrive.agent.service"}

    snap = {
        "SNAP": os.environ.get("SNAP"),
        "SNAP_COMMON": os.environ.get("SNAP_COMMON"),
        "SNAP_DATA": os.environ.get("SNAP_DATA"),
        "package_bin": str(PACKAGE_BIN),
    }

    report: dict[str, Any] = {
        "ok": len(issues) == 0,
        "version_module": __import__("meshdrive").__version__,
        "root": str(ROOT),
        "python": sys.executable,
        "path": os.environ.get("PATH"),
        "cli_on_path": cli_on_path,
        "config": {"path": str(CONFIG_PATH), "exists": CONFIG_PATH.is_file()},
        "auth": {"path": str(AUTH_PATH), "exists": AUTH_PATH.is_file()},
        "license": lic,
        "binaries": {
            "juicefs": str(juicefs) if juicefs else None,
            "filebrowser": str(filebrowser) if filebrowser else None,
            "vix_gateway": str(VIX_GATEWAY_BIN) if VIX_GATEWAY_BIN.is_file() else None,
            "vix_fuse": str(VIX_FUSE_BIN) if VIX_FUSE_BIN.is_file() else None,
            "package_bin": str(PACKAGE_BIN),
            "data_bin": str(BIN),
        },
        "venv": py_env,  # keep key for older tooling; mode distinguishes snap
        "python_env": py_env,
        "agent_service": agent,
        "snap": snap,
        "share": str(SHARE),
        "issues": issues,
    }

    if verbose:
        report["var"] = {"path": str(VAR), "writable": os.access(VAR, os.W_OK)}
        try:
            from meshdrive.config import addon_status, load_config

            report["addons"] = addon_status(load_config())
        except Exception as exc:
            report["addons_error"] = str(exc)

    return report


def print_report(report: dict[str, Any]) -> None:
    ok = report.get("ok", False)
    print(f"MeshDrive doctor — {'OK' if ok else 'ISSUES FOUND'}")
    print(f"  version: {report.get('version_module')}")
    print(f"  root:    {report.get('root')}")
    print(f"  tier:    {report.get('license', {}).get('tier', 'unknown')}")
    print("  CLI on PATH:")
    for name, loc in (report.get("cli_on_path") or {}).items():
        mark = "✓" if loc else "✗"
        print(f"    {mark} {name}: {loc or 'missing'}")
    bins = report.get("binaries") or {}
    print("  binaries:")
    for key in ("juicefs", "filebrowser", "vix_gateway", "vix_fuse"):
        val = bins.get(key)
        mark = "✓" if val else "·"
        print(f"    {mark} {key}: {val or 'not installed'}")
    py_env = report.get("python_env") or report.get("venv") or {}
    mode = py_env.get("mode", "venv")
    label = "python-packages" if mode == "snap-target" else "venv"
    print(f"  {label}: {'ok' if py_env.get('ok') else 'missing'} ({py_env.get('path')})")
    agent = report.get("agent_service") or {}
    if agent.get("available"):
        print(f"  agent service: {agent.get('active', 'unknown')}")
    snap = report.get("snap") or {}
    if snap.get("SNAP"):
        print(f"  snap: {snap.get('SNAP')} common={snap.get('SNAP_COMMON')}")
        print(f"  package_bin: {snap.get('package_bin')}")
    for issue in report.get("issues") or []:
        print(f"  ! {issue}")
