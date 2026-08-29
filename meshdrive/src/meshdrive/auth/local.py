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


def verify_password(username: str, password: str, path: Path | None = None) -> bool:
    rec = (load_auth(path).get("users") or {}).get(username)
    if not rec or "password_hash" not in rec:
        return False
    try:
        return _hasher.verify(rec["password_hash"], password)
    except VerifyMismatchError:
        return False
