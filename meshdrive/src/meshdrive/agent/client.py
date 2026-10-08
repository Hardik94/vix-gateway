"""Lightweight HTTP client for the loopback agent API."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from meshdrive.constants import CONTROL_HOST, CONTROL_PORT


def _base() -> str:
    return f"http://{CONTROL_HOST}:{CONTROL_PORT}"


def _request(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(_base() + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def health() -> dict[str, Any]:
    try:
        return _request("GET", "/health")
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
        raise RuntimeError(str(exc)) from exc
