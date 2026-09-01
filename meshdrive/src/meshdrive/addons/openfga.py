"""OpenFGA loopback client. Store and model live under /opt/meshdrive/var/openfga."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from meshdrive.constants import BIN, ETC, VAR

OPENFGA_HTTP = os.environ.get("MESHDRIVE_OPENFGA_HTTP", "http://127.0.0.1:8081")
STORE_META = VAR / "openfga" / "store.json"
MODEL_JSON = ETC / "openfga-model.json"
OPENFGA_BIN = BIN / "openfga"


def which_openfga() -> Path | None:
    if OPENFGA_BIN.is_file() and os.access(OPENFGA_BIN, os.X_OK):
        return OPENFGA_BIN
    return None


def available() -> bool:
    return which_openfga() is not None and STORE_META.is_file()


def _request(method: str, path: str, body: dict[str, Any] | None = None, timeout: float = 15.0) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(OPENFGA_HTTP + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if not raw:
                return {}
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {"raw": raw}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"error": raw or str(exc.reason)}
        raise RuntimeError(str(payload.get("message") or payload.get("error") or exc.reason)) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OpenFGA not reachable at {OPENFGA_HTTP}: {exc.reason}") from exc


def wait_healthy(timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            payload = _request("GET", "/healthz")
            status = str(payload.get("status") or "").upper()
            if status in {"SERVING", "OK", ""} or payload.get("raw"):
                return
            return
        except RuntimeError as exc:
            last = str(exc)
            time.sleep(0.5)
    raise RuntimeError(f"OpenFGA did not become healthy: {last}")


def load_store_meta() -> dict[str, str]:
    if not STORE_META.is_file():
        return {}
    try:
        return json.loads(STORE_META.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_store_meta(data: dict[str, str]) -> None:
    STORE_META.parent.mkdir(parents=True, exist_ok=True)
    STORE_META.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    try:
        STORE_META.chmod(0o600)
    except OSError:
        pass


def bootstrap() -> dict[str, str]:
    """Create store + write authorization model. Idempotent."""
    wait_healthy(timeout=60.0)
    meta = load_store_meta()
    store_id = meta.get("store_id")
    if not store_id:
        created = _request("POST", "/stores", {"name": "meshdrive"})
        store_id = created.get("id") or created.get("store", {}).get("id")
        if not store_id:
            raise RuntimeError(f"OpenFGA store create returned no id: {created}")
        meta["store_id"] = store_id
    if not MODEL_JSON.is_file():
        raise RuntimeError(f"missing authorization model {MODEL_JSON}")
    model = json.loads(MODEL_JSON.read_text(encoding="utf-8"))
    written = _request("POST", f"/stores/{store_id}/authorization-models", model)
    model_id = written.get("authorization_model_id") or meta.get("model_id", "")
    if model_id:
        meta["model_id"] = model_id
    save_store_meta(meta)
    return meta


def check(user: str, relation: str, object_id: str) -> bool:
    if not available():
        return True
    meta = load_store_meta()
    store_id = meta.get("store_id")
    if not store_id:
        return True
    body: dict[str, Any] = {
        "tuple_key": {"user": user, "relation": relation, "object": object_id},
    }
    if meta.get("model_id"):
        body["authorization_model_id"] = meta["model_id"]
    try:
        result = _request("POST", f"/stores/{store_id}/check", body)
    except RuntimeError:
        return False
    return bool(result.get("allowed"))


def write_tuple(user: str, relation: str, object_id: str) -> None:
    meta = load_store_meta()
    store_id = meta.get("store_id")
    if not store_id:
        raise RuntimeError("OpenFGA store is not bootstrapped")
    _request(
        "POST",
        f"/stores/{store_id}/write",
        {
            "writes": {
                "tuple_keys": [
                    {"user": user, "relation": relation, "object": object_id},
                ]
            }
        },
    )


def grant_mcp_reader(backend_name: str) -> None:
    """Grant MCP agent read+write on a storage backend (used by file tools via parent)."""
    if not available():
        return
    try:
        write_tuple("agent:mcp", "reader", f"storage_backend:{backend_name}")
        write_tuple("agent:mcp", "writer", f"storage_backend:{backend_name}")
    except RuntimeError:
        pass


def grant_mcp_access_all_backends() -> None:
    """Re-grant MCP tuples for every configured backend (idempotent best-effort)."""
    if not available():
        return
    from meshdrive.config import backends

    for item in backends():
        name = item.get("name")
        if name:
            grant_mcp_reader(str(name))
