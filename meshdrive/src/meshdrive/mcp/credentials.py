"""MCP API tokens — install-time, rotatable, not Filebrowser/LDAP users.

Plaintext is shown once (install/rotate) via ``mcp-token-once.txt`` (0600).
Only argon2id hashes are stored under ``etc/mcp_credentials.yaml``.

Ownership: the SSE unit runs as ``meshdrive``. Tokens created via ``sudo``
must still be readable/writable by that user (see ``_fix_secret_perms``).
"""

from __future__ import annotations

import logging
import os
import pwd
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from meshdrive.constants import MCP_CREDENTIALS_PATH, MCP_TOKEN_ONCE_PATH, ensure_runtime_dirs

DEFAULT_TOKEN_ID = "default"
_hasher = PasswordHasher()
_TOKEN_BYTES = 32
log = logging.getLogger("meshdrive.mcp.credentials")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _generate_plaintext() -> str:
    # Prefix helps operators recognize MeshDrive MCP tokens in configs.
    return "md_" + secrets.token_urlsafe(_TOKEN_BYTES)


def _meshdrive_ids() -> tuple[int, int] | None:
    try:
        pw = pwd.getpwnam("meshdrive")
        return int(pw.pw_uid), int(pw.pw_gid)
    except KeyError:
        return None


def _fix_secret_perms(path: Path) -> None:
    """Ensure meshdrive can read/write secrets created under sudo."""
    try:
        path.chmod(0o600)
    except OSError:
        pass
    if os.geteuid() != 0:
        return
    ids = _meshdrive_ids()
    if not ids:
        return
    try:
        os.chown(path, ids[0], ids[1])
    except OSError as exc:
        log.warning("chown %s to meshdrive failed: %s", path, exc)


def _perm_hint(path: Path) -> str:
    return (
        f"Permission denied for {path}. "
        "MCP SSE runs as user meshdrive. Fix with: "
        f"sudo chown meshdrive:meshdrive {path} "
        f"{path.parent} && sudo chmod 600 {path} && "
        "sudo systemctl restart meshdrive-mcp"
    )


def _load() -> dict[str, Any]:
    path = MCP_CREDENTIALS_PATH
    if not path.is_file():
        return {"version": 1, "tokens": {}}
    try:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except PermissionError as exc:
        raise PermissionError(_perm_hint(path)) from exc
    if not isinstance(data, dict):
        return {"version": 1, "tokens": {}}
    data.setdefault("version", 1)
    tokens = data.get("tokens")
    if not isinstance(tokens, dict):
        data["tokens"] = {}
    return data


def _save(data: dict[str, Any]) -> None:
    ensure_runtime_dirs()
    path = MCP_CREDENTIALS_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".yaml.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(data, fh, default_flow_style=False, sort_keys=False)
        os.chmod(tmp, 0o600)
        tmp.replace(path)
    except PermissionError as exc:
        try:
            tmp.unlink(missing_ok=True)  # type: ignore[call-arg]
        except (TypeError, OSError):
            if tmp.is_file():
                try:
                    tmp.unlink()
                except OSError:
                    pass
        raise PermissionError(_perm_hint(path)) from exc
    _fix_secret_perms(path)


def _write_once_file(plaintext: str) -> Path:
    ensure_runtime_dirs()
    path = MCP_TOKEN_ONCE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(plaintext.rstrip() + "\n", encoding="utf-8")
    _fix_secret_perms(path)
    return path


def _clear_once_file() -> None:
    try:
        MCP_TOKEN_ONCE_PATH.unlink(missing_ok=True)  # type: ignore[call-arg]
    except TypeError:
        # Python < 3.8 style (we require 3.10+, but be safe)
        if MCP_TOKEN_ONCE_PATH.is_file():
            MCP_TOKEN_ONCE_PATH.unlink()
    except OSError:
        pass


def configured() -> bool:
    data = _load()
    tokens = data.get("tokens") or {}
    return any(isinstance(v, dict) and v.get("hash") for v in tokens.values())


def status() -> dict[str, Any]:
    try:
        data = _load()
    except PermissionError as exc:
        return {
            "configured": False,
            "path": str(MCP_CREDENTIALS_PATH),
            "once_file_present": False,
            "tokens": [],
            "error": str(exc),
            "note": str(exc),
        }
    tokens = data.get("tokens") or {}
    rows = []
    for tid, rec in tokens.items():
        if not isinstance(rec, dict):
            continue
        rows.append(
            {
                "id": tid,
                "label": rec.get("label") or tid,
                "prefix": rec.get("prefix") or "",
                "created_at": rec.get("created_at"),
                "rotated_at": rec.get("rotated_at"),
                "openfga_subject": rec.get("openfga_subject") or "agent:mcp",
            }
        )
    return {
        "configured": bool(rows),
        "path": str(MCP_CREDENTIALS_PATH),
        "once_file_present": MCP_TOKEN_ONCE_PATH.is_file(),
        "tokens": rows,
        "note": (
            "stdio MCP trusts the local process (no token). "
            "SSE/HTTP MCP requires Authorization: Bearer <token>."
        ),
    }


def ensure_secret_ownership() -> None:
    """Best-effort chown of credentials + once-file to meshdrive (call after sudo install)."""
    if MCP_CREDENTIALS_PATH.is_file():
        _fix_secret_perms(MCP_CREDENTIALS_PATH)
    if MCP_TOKEN_ONCE_PATH.is_file():
        _fix_secret_perms(MCP_TOKEN_ONCE_PATH)


def ensure_install_token(*, token_id: str = DEFAULT_TOKEN_ID, label: str = "install") -> str | None:
    """Create default token if missing. Returns plaintext only when newly created."""
    data = _load()
    tokens = data.setdefault("tokens", {})
    existing = tokens.get(token_id)
    if isinstance(existing, dict) and existing.get("hash"):
        # Still fix ownership if sudo left root-only secrets.
        if MCP_CREDENTIALS_PATH.is_file():
            _fix_secret_perms(MCP_CREDENTIALS_PATH)
        return None
    plaintext = _generate_plaintext()
    now = _utc_now()
    tokens[token_id] = {
        "label": label,
        "created_at": now,
        "rotated_at": now,
        "prefix": plaintext[:10],
        "hash": _hasher.hash(plaintext),
        "openfga_subject": "agent:mcp",
    }
    _save(data)
    _write_once_file(plaintext)
    return plaintext


def rotate_token(*, token_id: str = DEFAULT_TOKEN_ID, label: str | None = None) -> str:
    """Replace token hash; returns new plaintext (also written to once-file)."""
    data = _load()
    tokens = data.setdefault("tokens", {})
    prev = tokens.get(token_id) if isinstance(tokens.get(token_id), dict) else {}
    plaintext = _generate_plaintext()
    now = _utc_now()
    tokens[token_id] = {
        "label": label or (prev or {}).get("label") or token_id,
        "created_at": (prev or {}).get("created_at") or now,
        "rotated_at": now,
        "prefix": plaintext[:10],
        "hash": _hasher.hash(plaintext),
        "openfga_subject": (prev or {}).get("openfga_subject") or "agent:mcp",
    }
    _save(data)
    _write_once_file(plaintext)
    return plaintext


def verify_token(plaintext: str | None) -> str | None:
    """Return matching token id if valid, else None.

    Raises PermissionError if the credentials file is unreadable (caller maps to 503).
    Rehash persistence failures are logged and ignored so auth still succeeds.
    """
    if not plaintext or not str(plaintext).strip():
        return None
    raw = str(plaintext).strip()
    data = _load()
    for tid, rec in (data.get("tokens") or {}).items():
        if not isinstance(rec, dict):
            continue
        hashed = rec.get("hash")
        if not hashed:
            continue
        try:
            if _hasher.verify(str(hashed), raw):
                if _hasher.check_needs_rehash(str(hashed)):
                    rec["hash"] = _hasher.hash(raw)
                    try:
                        _save(data)
                    except PermissionError as exc:
                        log.warning("token verified but rehash not saved: %s", exc)
                return str(tid)
        except (VerifyMismatchError, ValueError, TypeError):
            continue
    return None


def openfga_subject_for_token_id(token_id: str) -> str:
    data = _load()
    rec = (data.get("tokens") or {}).get(token_id)
    if isinstance(rec, dict) and rec.get("openfga_subject"):
        return str(rec["openfga_subject"])
    return "agent:mcp"


def read_once_plaintext(*, consume: bool = False) -> str | None:
    """Read plaintext from once-file if present. Optionally delete after read."""
    if not MCP_TOKEN_ONCE_PATH.is_file():
        return None
    try:
        text = MCP_TOKEN_ONCE_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if consume:
        _clear_once_file()
    return text or None


def extract_bearer(authorization: str | None, *, alt_header: str | None = None) -> str | None:
    if alt_header and alt_header.strip():
        return alt_header.strip()
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None
