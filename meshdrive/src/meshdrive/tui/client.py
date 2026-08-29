"""HTTP client for the local MeshDrive agent control API."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from meshdrive.constants import CONTROL_HOST, CONTROL_PORT


class AgentError(RuntimeError):
    def __init__(self, message: str, *, offline: bool = False) -> None:
        super().__init__(message)
        self.offline = offline


class AgentClient:
    def __init__(self, host: str = CONTROL_HOST, port: int = CONTROL_PORT, timeout: float = 30.0) -> None:
        self.base = f"http://{host}:{port}"
        self.timeout = timeout

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            try:
                payload = json.loads(raw)
                msg = str(payload.get("error") or exc.reason)
            except json.JSONDecodeError:
                msg = str(exc.reason)
            raise AgentError(msg) from exc
        except urllib.error.URLError as exc:
            raise AgentError("MeshDrive agent is not running", offline=True) from exc
        except TimeoutError as exc:
            raise AgentError("agent timed out", offline=True) from exc

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def state(self) -> dict[str, Any]:
        return self._request("GET", "/state")

    def add_storage(self, name: str, data_path: str = "", capacity_gb: str | int | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"name": name, "data_path": data_path}
        if capacity_gb is not None and capacity_gb != "":
            body["capacity_gb"] = capacity_gb
        return self._request("POST", "/storage/add", body)

    def mount(self, name: str) -> dict[str, Any]:
        return self._request("POST", "/storage/mount", {"name": name})

    def unmount(self, name: str) -> dict[str, Any]:
        return self._request("POST", "/storage/unmount", {"name": name})

    def delete_storage(self, name: str, *, wipe_data: bool = False) -> dict[str, Any]:
        query = urllib.parse.urlencode({"wipe_data": "1"}) if wipe_data else ""
        path = f"/storage/{urllib.parse.quote(name, safe='')}"
        if query:
            path = f"{path}?{query}"
        return self._request("DELETE", path)

    def add_user(self, username: str, password: str, admin: bool = False) -> dict[str, Any]:
        return self._request(
            "POST", "/users", {"username": username, "password": password, "admin": admin}
        )

    def delete_user(self, username: str) -> dict[str, Any]:
        return self._request("DELETE", f"/users/{username}")

    def start_filebrowser(self) -> dict[str, Any]:
        return self._request("POST", "/filebrowser/start", {})

    def stop_filebrowser(self) -> dict[str, Any]:
        return self._request("POST", "/filebrowser/stop", {})

    def install_addons(self, *names: str) -> dict[str, Any]:
        return self._request("POST", "/addons/install", {"names": list(names)})

    def save_settings(self, **kwargs: Any) -> dict[str, Any]:
        return self._request("POST", "/settings", kwargs)
