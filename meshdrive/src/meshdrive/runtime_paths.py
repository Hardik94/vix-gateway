"""Normalize MeshDrive data paths (especially under classic snap layout)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from meshdrive.constants import (
    AUTH_PATH,
    FILEBROWSER_DB,
    FILEBROWSER_JSON,
    MNT,
    ROOT,
    SNAP,
    VAR,
    ensure_runtime_dirs,
)


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.expanduser().resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except (ValueError, OSError):
        return False


def is_readonly_snap_path(path: Path | str) -> bool:
    """True if path sits under $SNAP (squashfs) — never use for writable state."""
    if not SNAP:
        return False
    return _is_under(Path(path), Path(SNAP))


def is_revision_data_path(path: Path | str) -> bool:
    """True if path sits under $SNAP_DATA (per-revision) instead of $SNAP_COMMON."""
    snap_data = os.environ.get("SNAP_DATA")
    if not snap_data:
        return False
    p = Path(path)
    if not _is_under(p, Path(snap_data)):
        return False
    # SNAP_COMMON can be unrelated; anything under SNAP_DATA is revision-scoped.
    return True


def canonicalize_data_path(path: Path | str, *, default: Path) -> Path:
    """Map mistaken snap readonly / empty paths onto the writable data root."""
    raw = str(path or "").strip()
    if not raw:
        return default
    p = map_legacy_root_path(raw)
    if is_readonly_snap_path(p) or is_revision_data_path(p):
        return default
    return p


def map_legacy_root_path(path: Path | str) -> Path:
    """Rewrite ``/opt/meshdrive/...`` onto ``ROOT`` (snap: ``$SNAP_COMMON``).

    The TUI placeholder historically suggested ``/opt/meshdrive/var/data/...``.
    After ``sudo`` addon installs, a host leftover ``/opt/meshdrive`` can exist
    **without** the snap layout bind, so creates fail with PermissionError while
    the real writable tree is ``/var/snap/meshdrive/common``.
    """
    raw = str(path or "").strip()
    if not raw:
        return ROOT
    p = Path(raw).expanduser()
    text = p.as_posix() if p.is_absolute() else p.as_posix()
    # Normalize common prefixes (with or without trailing slash).
    for prefix in ("/opt/meshdrive", "/var/snap/meshdrive/common"):
        if text == prefix:
            return ROOT
        if text.startswith(prefix + "/"):
            rel = text[len(prefix) + 1 :]
            return ROOT / rel if rel else ROOT
    return p


def ensure_writable_data_tree() -> None:
    """Best-effort mkdir/chmod so storage create works after sudo addon installs."""
    ensure_runtime_dirs()
    for path in (
        ROOT,
        ROOT / "etc",
        ROOT / "bin",
        ROOT / "mnt",
        VAR,
        VAR / "data",
        VAR / "meta",
        VAR / "cache",
        VAR / "log",
        VAR / "tmp",
        VAR / "openfga",
    ):
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        try:
            # Keep dirs traversable; do not loosen file secrets (credentials stay 0600).
            if path.is_dir():
                mode = path.stat().st_mode & 0o777
                if mode & 0o100 == 0 or mode & 0o200 == 0:
                    path.chmod(0o755)
        except OSError:
            pass


def rewrite_runtime_config_paths() -> dict[str, Any]:
    """Force config + filebrowser.json onto ROOT (layout /opt/meshdrive under snap)."""
    from meshdrive.config import load_config, root, save_config
    from meshdrive.storage.filebrowser import apply_filebrowser_server_config, write_filebrowser_json
    from meshdrive.storage.juicefs import preferred_filebrowser_root

    ensure_runtime_dirs()
    cfg = load_config()
    md = root(cfg)
    fb = md.setdefault("filebrowser", {})
    auth = md.setdefault("auth", {})
    isolation = md.setdefault("isolation", {})

    fb_root = preferred_filebrowser_root()
    fb["database"] = str(FILEBROWSER_DB)
    fb["root"] = fb_root
    if "address" not in fb:
        fb["address"] = ""
    fb.setdefault("hostname", "meshdrive.local")
    fb.setdefault("port", 8080)

    auth["path"] = str(AUTH_PATH)
    isolation["root_dir"] = str(ROOT)
    isolation["allowed_paths"] = [str(ROOT)]

    save_config(cfg)
    write_filebrowser_json(
        address=str(fb.get("address") if fb.get("address") is not None else ""),
        port=int(fb.get("port") or 8080),
        root=fb_root,
        database=str(FILEBROWSER_DB),
        path=FILEBROWSER_JSON,
    )
    # Bolt DB is authoritative while the service is stopped; apply when possible.
    try:
        apply_filebrowser_server_config(
            address=str(fb.get("address") if fb.get("address") is not None else ""),
            port=int(fb.get("port") or 8080),
            root=fb_root,
            database=str(FILEBROWSER_DB),
        )
    except Exception:
        pass
    return cfg


def ensure_filebrowser_db() -> Path:
    """Create Filebrowser DB under ROOT/var if missing."""
    from meshdrive.storage.filebrowser import which_filebrowser

    ensure_runtime_dirs()
    if FILEBROWSER_DB.is_file():
        return FILEBROWSER_DB
    binary = which_filebrowser()
    if not binary:
        raise RuntimeError("filebrowser binary not found; cannot init database")
    FILEBROWSER_DB.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [str(binary), "config", "init", "-d", str(FILEBROWSER_DB)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0 and not FILEBROWSER_DB.is_file():
        err = ((proc.stderr or "") + (proc.stdout or "")).strip()
        raise RuntimeError(err or f"filebrowser config init failed ({FILEBROWSER_DB})")
    # Align listening / root with MeshDrive defaults (best-effort).
    subprocess.run(
        [
            str(binary),
            "config",
            "set",
            "-d",
            str(FILEBROWSER_DB),
            "--address",
            "",
            "--port",
            "8080",
            "--root",
            str(MNT),
            "--minimumPasswordLength",
            "12",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return FILEBROWSER_DB


def prepare_runtime() -> None:
    """Dirs + canonical paths + Filebrowser DB — call on agent start."""
    ensure_runtime_dirs()
    ensure_writable_data_tree()
    (VAR / "log").mkdir(parents=True, exist_ok=True)
    rewrite_runtime_config_paths()
    try:
        from meshdrive.storage.juicefs import ensure_user_allow_other

        ensure_user_allow_other()
    except Exception:
        pass
    try:
        ensure_filebrowser_db()
    except RuntimeError:
        # Binary may be temporarily missing; doctor will surface it.
        pass
