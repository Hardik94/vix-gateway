"""Per-user private homes and posix-group shared folders on JuiceFS buckets.

Layout (under each storage bucket mount)::

  <mount>/
    .meshdrive/
      users/<username>/private/     # Filebrowser --scope for that user
      shares/<share_name>/          # group-writable shared folder
    users/<username> -> .meshdrive/users/<username>/private   (optional convenience link)
    shared/<share_name> -> .meshdrive/shares/<share_name>

Sharing model
-------------
* Each share has a posix group (e.g. FAM-101-EDITOR) and directory mode 2770.
* Members of that group can create/delete files according to directory ACLs.
* Cross-bucket copy is a normal file copy (or JuiceFS clone) between mounts —
  not a symlink across filesystems unless both sides are on the same volume.

Filebrowser
-----------
Set each non-admin user's scope to their private directory. Shared folders are
reachable by placing a symlink **inside** the private scope, or by using a
parent scope that includes both private and shared (less isolation).

Recommended (strong isolation)::

  scope = <mount>/.meshdrive/users/<user>/private
  and create: private/shared-<name> → ../../shares/<name>
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def user_private_dir(mount: Path | str, username: str) -> Path:
    return Path(mount) / ".meshdrive" / "users" / username / "private"


def share_dir(mount: Path | str, share_name: str) -> Path:
    return Path(mount) / ".meshdrive" / "shares" / share_name


def ensure_user_private(mount: Path | str, username: str, *, mode: int = 0o700) -> Path:
    target = user_private_dir(mount, username)
    target.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target, mode)
    except OSError:
        pass
    return target


def ensure_share(
    mount: Path | str,
    share_name: str,
    *,
    mode: int = 0o2770,
) -> Path:
    """Create a setgid shared directory (group sticky for collaboration)."""
    target = share_dir(mount, share_name)
    target.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target, mode)
    except OSError:
        pass
    return target


def link_share_into_private(
    mount: Path | str,
    username: str,
    share_name: str,
    *,
    link_name: str | None = None,
) -> Path:
    """Put a symlink to a share inside the user's private Filebrowser scope."""
    private = ensure_user_private(mount, username)
    shared = ensure_share(mount, share_name)
    name = link_name or f"shared-{share_name}"
    link = private / name
    if link.is_symlink() or link.exists():
        return link
    # Relative symlink so moving the mount still works.
    rel = os.path.relpath(shared, start=private)
    link.symlink_to(rel)
    return link


def ensure_bucket_layout(
    mount: Path | str,
    *,
    usernames: list[str],
    shares: list[str] | None = None,
    share_members: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Idempotent layout for one JuiceFS bucket."""
    mount_p = Path(mount)
    mount_p.mkdir(parents=True, exist_ok=True)
    created_users = []
    for user in usernames:
        ensure_user_private(mount_p, user)
        created_users.append(user)
    created_shares = []
    for share in shares or []:
        ensure_share(mount_p, share)
        created_shares.append(share)
        for member in (share_members or {}).get(share, []):
            if member in usernames:
                link_share_into_private(mount_p, member, share)
    return {
        "mount": str(mount_p),
        "users": created_users,
        "shares": created_shares,
    }


def filebrowser_scope_for(mount: Path | str, username: str) -> str:
    """Absolute path to pass as Filebrowser user scope."""
    return str(user_private_dir(mount, username).resolve())
