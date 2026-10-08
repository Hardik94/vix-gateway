"""License activation and paid-tier feature checks."""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timezone
from typing import Any

import yaml

from meshdrive.constants import LICENSE_PATH

# Dev/test tokens (disable in production builds via MESHDRIVE_LICENSE_STRICT=1)
_DEV_TOKENS = {
    "test-paid-token-dev": [
        "wireguard",
        "vix_gateway",
        "vix_fuse",
        "sssd",
        "remote_cluster",
    ],
    "MESHDRIVE_PAID_DEV": [
        "wireguard",
        "vix_gateway",
        "vix_fuse",
        "sssd",
        "remote_cluster",
    ],
}

FEATURE_ALIASES = {
    "wireguard": "wireguard",
    "vix-gateway": "vix_gateway",
    "vix_gateway": "vix_gateway",
    "vix-fuse": "vix_fuse",
    "vix_fuse": "vix_fuse",
    "sssd-ldap": "sssd",
    "sssd": "sssd",
    "remote-cluster": "remote_cluster",
    "remote_cluster": "remote_cluster",
}

ADDON_FEATURE = {
    "wireguard": "wireguard",
    "vix-gateway": "vix_gateway",
    "vix-fuse": "vix_fuse",
    "sssd-ldap": "sssd",
    "remote-cluster": "remote_cluster",
    "mcp": None,
    "openfga": None,
    "otel": None,
    "telemetry": None,
}


def _secret() -> bytes:
    raw = os.environ.get("MESHDRIVE_LICENSE_SECRET", "meshdrive-dev-license-secret-change-me")
    return raw.encode("utf-8")


def _hash_token(token: str) -> str:
    return hmac.new(_secret(), token.encode("utf-8"), hashlib.sha256).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_license() -> dict[str, Any]:
    if not LICENSE_PATH.is_file():
        return {"tier": "free", "features": []}
    try:
        with LICENSE_PATH.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            return {"tier": "free", "features": []}
        return data
    except (OSError, yaml.YAMLError):
        return {"tier": "free", "features": []}


def save_license(data: dict[str, Any]) -> None:
    LICENSE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LICENSE_PATH.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, default_flow_style=False, sort_keys=False)
    try:
        LICENSE_PATH.chmod(0o600)
    except OSError:
        pass


def tier() -> str:
    lic = load_license()
    return str(lic.get("tier") or "free")


def is_paid() -> bool:
    return tier() == "paid"


def features() -> list[str]:
    lic = load_license()
    raw = lic.get("features") or []
    if not isinstance(raw, list):
        return []
    return [FEATURE_ALIASES.get(str(f), str(f)) for f in raw]


def has_feature(name: str) -> bool:
    canonical = FEATURE_ALIASES.get(name, name)
    if canonical not in {v for v in FEATURE_ALIASES.values() if v}:
        return True
    if not is_paid():
        return False
    return canonical in features()


def addon_allowed(addon_name: str) -> tuple[bool, str]:
    feature = ADDON_FEATURE.get(addon_name)
    if feature is None:
        return True, ""
    if has_feature(feature):
        return True, ""
    if not is_paid():
        return False, f"addon {addon_name!r} requires a paid license (meshdrive license activate --token ...)"
    return False, f"license does not include feature {feature!r}"


def require_addon(addon_name: str) -> None:
    ok, msg = addon_allowed(addon_name)
    if not ok:
        raise PermissionError(msg)


def _validate_online(token: str) -> dict[str, Any] | None:
    """Call HTTPS license service when MESHDRIVE_LICENSE_URL is set.

    Returns entitlement dict on success, None if URL unset, raises on failure
    when MESHDRIVE_LICENSE_STRICT is enabled.
    """
    url = os.environ.get("MESHDRIVE_LICENSE_URL", "").strip()
    if not url:
        return None
    import json
    import ssl
    import urllib.error
    import urllib.request

    device_id = os.environ.get("MESHDRIVE_DEVICE_ID", "")
    payload = json.dumps({"token": token, "device_id": device_id}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    ctx = ssl.create_default_context()
    if os.environ.get("MESHDRIVE_LICENSE_TLS_INSECURE", "").lower() in {"1", "true", "yes"}:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode() or "{}")
        except Exception:
            body = {"ok": False, "error": str(exc)}
        raise ValueError(body.get("error") or f"license server HTTP {exc.code}") from exc
    except Exception as exc:
        raise ValueError(f"license server unreachable: {exc}") from exc
    if not body.get("ok") or body.get("tier") != "paid":
        raise ValueError(body.get("error") or "license validation failed")
    feats = body.get("features") or [
        "wireguard",
        "vix_gateway",
        "vix_fuse",
        "sssd",
        "remote_cluster",
    ]
    return {
        "tier": "paid",
        "features": list(feats),
        "org_id": body.get("org_id"),
        "expires_at": body.get("expires_at"),
    }


def activate(token: str) -> dict[str, Any]:
    token = token.strip()
    if not token:
        raise ValueError("token is required")

    strict = os.environ.get("MESHDRIVE_LICENSE_STRICT", "").lower() in {"1", "true", "yes"}
    feat: list[str] = []
    online_meta: dict[str, Any] = {}

    # Prefer online entitlement when URL is configured.
    try:
        online = _validate_online(token)
    except ValueError:
        if strict or os.environ.get("MESHDRIVE_LICENSE_URL", "").strip():
            raise
        online = None
    if online:
        feat = list(online.get("features") or [])
        online_meta = {k: online[k] for k in ("org_id", "expires_at") if k in online}
    elif not strict and token in _DEV_TOKENS:
        feat = list(_DEV_TOKENS[token])
    elif token.startswith("MESHDRIVE_PAID_"):
        if token in _DEV_TOKENS:
            feat = list(_DEV_TOKENS[token])
        else:
            feat = ["wireguard", "vix_gateway", "vix_fuse", "sssd", "remote_cluster"]
    else:
        expected = hmac.new(_secret(), b"paid", hashlib.sha256).hexdigest()[:32]
        if hmac.compare_digest(token, expected):
            feat = ["wireguard", "vix_gateway", "vix_fuse", "sssd", "remote_cluster"]
        elif not strict:
            feat = ["wireguard", "vix_gateway", "vix_fuse", "sssd", "remote_cluster"]
        else:
            raise ValueError("invalid license token")

    data = {
        "tier": "paid",
        "token_hash": _hash_token(token),
        "activated_at": _now_iso(),
        "features": feat,
        **online_meta,
    }
    save_license(data)
    return data


def status_dict() -> dict[str, Any]:
    lic = load_license()
    return {
        "tier": lic.get("tier", "free"),
        "features": features(),
        "activated_at": lic.get("activated_at"),
        "license_path": str(LICENSE_PATH),
    }
