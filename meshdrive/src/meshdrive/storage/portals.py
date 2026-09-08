"""Per-user Filebrowser portals — symlinks to allowed JuiceFS buckets.

Each non-admin user gets::

  $ROOT/var/portals/<username>/
      <bucket> -> $ROOT/mnt/<bucket>

Filebrowser ``--scope`` points at that portal so one instance can serve
many-to-many user↔bucket ACLs without exposing the whole ``mnt/`` tree.
Admins keep the global Filebrowser root (``mnt/``).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from meshdrive.config import backends, get_backend
from meshdrive.constants import MNT, VAR
from meshdrive.storage.homes import ensure_user_private

PORTALS = VAR / "portals"


def portal_dir(username: str) -> Path:
    return PORTALS / username


def rebuild_user_portal(
    username: str,
    bucket_names: list[str],
    *,
    ensure_private: bool = True,
) -> Path:
    """Rebuild portal symlinks for ``username``. Returns portal path."""
    portal = portal_dir(username)
    portal.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(portal, 0o755)
    except OSError:
        pass

    # Drop existing bucket symlinks (keep any non-link files)
    for child in list(portal.iterdir()):
        if child.is_symlink():
            try:
                child.unlink()
            except OSError:
                pass

    known = {str(item.get("name") or "") for item in backends()}
    for name in bucket_names:
        name = str(name).strip()
        if not name or name not in known:
            continue
        item = get_backend(name) or {}
        mount = item.get("mount_point") or item.get("mountpoint") or str(MNT / name)
        target = Path(mount)
        try:
            target.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        if ensure_private:
            try:
                ensure_user_private(target, username)
            except OSError:
                pass
        link = portal / name
        try:
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(target)
        except OSError:
            continue
    return portal


def remove_user_portal(username: str) -> None:
    portal = portal_dir(username)
    if not portal.is_dir():
        return
    for child in list(portal.iterdir()):
        try:
            if child.is_symlink() or child.is_file():
                child.unlink()
        except OSError:
            pass
    try:
        portal.rmdir()
    except OSError:
        pass


def rebuild_all_portals(users: list[dict[str, Any]]) -> dict[str, str]:
    """Rebuild portals for every user; return username → portal path."""
    out: dict[str, str] = {}
    for user in users:
        name = str(user.get("username") or "")
        if not name:
            continue
        access = list(user.get("storage_access") or [])
        portal = rebuild_user_portal(name, access)
        out[name] = str(portal)
    return out


def filebrowser_scope_for_user(
    username: str,
    *,
    admin: bool,
    storage_access: list[str] | None,
) -> str | None:
    """Return Filebrowser ``--scope`` path, or None for unrestricted (admin)."""
    if admin:
        return None
    portal = rebuild_user_portal(username, list(storage_access or []))
    return str(portal.resolve())
