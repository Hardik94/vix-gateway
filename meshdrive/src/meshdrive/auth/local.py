"""Local user store (argon2id) in auth.yaml."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from meshdrive.constants import AUTH_PATH

_hasher = PasswordHasher()


def load_auth(path: Path | None = None) -> dict[str, Any]:
    auth_path = path or AUTH_PATH
    if not auth_path.is_file():
        return {"users": {}}
    with auth_path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        return {"users": {}}
    data.setdefault("users", {})
    if not isinstance(data["users"], dict):
        data["users"] = {}
    return data


def save_auth(data: dict[str, Any], path: Path | None = None) -> None:
    auth_path = path or AUTH_PATH
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    with auth_path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, default_flow_style=False, sort_keys=False)
    try:
        auth_path.chmod(0o600)
    except OSError:
        pass


def list_users(path: Path | None = None) -> list[dict[str, Any]]:
    users = load_auth(path).get("users") or {}
    out = []
    for name, rec in users.items():
        item = {"username": name, **(rec if isinstance(rec, dict) else {})}
        item.pop("password_hash", None)
        out.append(item)
    return sorted(out, key=lambda u: u["username"])


def add_user(
    username: str,
    password: str,
    *,
    admin: bool = False,
    storage_access: list[str] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    from meshdrive.constants import FILEBROWSER_MIN_PASSWORD_LENGTH

    username = username.strip()
    if not username or not password:
        raise ValueError("username and password are required")
    if any(ch.isspace() for ch in username) or "/" in username:
        raise ValueError("username must not contain spaces or slashes")
    if len(password) < FILEBROWSER_MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"password must be at least {FILEBROWSER_MIN_PASSWORD_LENGTH} characters "
            "(required for Filebrowser login)"
        )
    data = load_auth(path)
    if username in data["users"]:
        raise ValueError(f"user {username!r} already exists")
    data["users"][username] = {
        "password_hash": _hasher.hash(password),
        "groups": ["admin"] if admin else ["user"],
        "storage_access": list(storage_access or []),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    save_auth(data, path)
    rec = dict(data["users"][username])
    rec.pop("password_hash", None)
    rec["username"] = username
    return rec


def delete_user(username: str, path: Path | None = None) -> None:
    data = load_auth(path)
    if username not in data["users"]:
        raise KeyError(username)
    del data["users"][username]
    save_auth(data, path)


def remove_storage_access(backend_name: str, path: Path | None = None) -> None:
    """Drop a backend name from every user's storage_access list."""
    data = load_auth(path)
    changed = False
    for rec in (data.get("users") or {}).values():
        if not isinstance(rec, dict):
            continue
        access = list(rec.get("storage_access") or [])
        if backend_name not in access:
            continue
        rec["storage_access"] = [item for item in access if item != backend_name]
        changed = True
    if changed:
        save_auth(data, path)


def set_storage_access(
    username: str,
    storage_access: list[str],
    path: Path | None = None,
) -> dict[str, Any]:
    """Replace a user's bucket ACL (many-to-many user ↔ storage backend)."""
    username = username.strip()
    data = load_auth(path)
    if username not in data["users"]:
        raise KeyError(username)
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in storage_access:
        name = str(item).strip()
        if not name or name in seen:
            continue
        seen.add(name)
        cleaned.append(name)
    rec = data["users"][username]
    if not isinstance(rec, dict):
        raise KeyError(username)
    rec["storage_access"] = cleaned
    save_auth(data, path)
    out = dict(rec)
    out.pop("password_hash", None)
    out["username"] = username
    return out


def grant_storage_access(
    username: str,
    backend_name: str,
    path: Path | None = None,
) -> dict[str, Any]:
    data = load_auth(path)
    rec = (data.get("users") or {}).get(username)
    if not isinstance(rec, dict):
        raise KeyError(username)
    access = list(rec.get("storage_access") or [])
    if backend_name not in access:
        access.append(backend_name)
    return set_storage_access(username, access, path=path)


def revoke_user_storage_access(
    username: str,
    backend_name: str,
    path: Path | None = None,
) -> dict[str, Any]:
    data = load_auth(path)
    rec = (data.get("users") or {}).get(username)
    if not isinstance(rec, dict):
        raise KeyError(username)
    access = [b for b in (rec.get("storage_access") or []) if b != backend_name]
    return set_storage_access(username, access, path=path)


def set_backend_users(
    backend_name: str,
    usernames: list[str],
    path: Path | None = None,
) -> list[dict[str, Any]]:
    """Set which users may access ``backend_name`` (rewrites each user's ACL)."""
    backend_name = backend_name.strip()
    if not backend_name:
        raise ValueError("backend name required")
    wanted = {u.strip() for u in usernames if str(u).strip()}
    data = load_auth(path)
    users = data.get("users") or {}
    updated: list[dict[str, Any]] = []
    for name, rec in users.items():
        if not isinstance(rec, dict):
            continue
        access = list(rec.get("storage_access") or [])
        has = backend_name in access
        if name in wanted and not has:
            access.append(backend_name)
            rec["storage_access"] = access
            updated.append(name)
        elif name not in wanted and has:
            rec["storage_access"] = [b for b in access if b != backend_name]
            updated.append(name)
    if updated:
        save_auth(data, path)
    return list_users(path)


def users_for_backend(backend_name: str, path: Path | None = None) -> list[str]:
    names: list[str] = []
    for user in list_users(path):
        if backend_name in (user.get("storage_access") or []):
            names.append(str(user["username"]))
    return names


def verify_password(username: str, password: str, path: Path | None = None) -> bool:
    rec = (load_auth(path).get("users") or {}).get(username)
    if not rec or "password_hash" not in rec:
        return False
    try:
        return _hasher.verify(rec["password_hash"], password)
    except VerifyMismatchError:
        return False
