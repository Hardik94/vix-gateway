"""Loopback JSON control API for the TUI (not MCP)."""

from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from meshdrive.auth import add_user, delete_user, list_users, remove_storage_access
from meshdrive.config import backends, delete_backend, get_backend, load_config, root, save_config, upsert_backend
from meshdrive.constants import BOOTSTRAP_PASSWORD, CONTROL_HOST, CONTROL_PORT, MNT
from meshdrive.storage.filebrowser import (
    add_filebrowser_user,
    delete_filebrowser_user,
    which_filebrowser,
    write_filebrowser_json,
)
from meshdrive.storage.juicefs import (
    default_backend,
    format_backend,
    is_mounted,
    mount_backend,
    parse_capacity_gb,
    unmount_backend,
    which_juicefs,
    wipe_backend_data,
)
from meshdrive.agent import systemd
from meshdrive.agent.health import collect_state
from meshdrive.state import save_state


class AgentAPI:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.refresh()

    def refresh(self) -> dict[str, Any]:
        state = collect_state()
        save_state(state)
        return state

    def handle(self, method: str, path: str, body: dict[str, Any] | None) -> tuple[int, dict[str, Any]]:
        with self._lock:
            try:
                return self._handle(method, path, body or {})
            except KeyError as exc:
                return 404, {"ok": False, "error": str(exc)}
            except ValueError as exc:
                return 400, {"ok": False, "error": str(exc)}
            except RuntimeError as exc:
                return 500, {"ok": False, "error": str(exc)}

    def _handle(self, method: str, path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if method == "GET" and path == "/health":
            return 200, {"ok": True, "state": self.refresh()}
        if method == "GET" and path == "/state":
            return 200, self.refresh()
        if method == "GET" and path == "/config":
            return 200, load_config()
        if method == "GET" and path == "/users":
            return 200, {"ok": True, "users": list_users()}
        if method == "POST" and path == "/storage/add":
            return 200, self._add_storage(body)
        if method == "POST" and path == "/storage/mount":
            return 200, self._mount(body.get("name", ""))
        if method == "POST" and path == "/storage/unmount":
            return 200, self._unmount(body.get("name", ""))
        if method == "DELETE" and path.startswith("/storage/"):
            name = unquote(path[len("/storage/") :])
            wipe_raw = str((body or {}).get("wipe_data") or "").lower()
            wipe_data = wipe_raw in {"1", "true", "yes"}
            return 200, self._delete_storage(name, wipe_data=wipe_data)
        if method == "POST" and path == "/users":
            return 200, self._add_user(body)
        if method == "DELETE" and path.startswith("/users/"):
            username = unquote(path[len("/users/") :])
            return 200, self._delete_user(username)
        if method == "POST" and path == "/filebrowser/start":
            return 200, self._filebrowser_start()
        if method == "POST" and path == "/filebrowser/stop":
            systemd.stop_unit(systemd.filebrowser_unit())
            return 200, {"ok": True, "state": self.refresh()}
        if method == "POST" and path == "/settings":
            return 200, self._save_settings(body)
        if method == "GET" and path == "/addons":
            return 200, {"ok": True, "addons": self.refresh().get("addons")}
        if method == "GET" and path == "/license":
            from meshdrive.license import status_dict

            return 200, {"ok": True, "license": status_dict()}
        if method == "POST" and path == "/license/activate":
            from meshdrive.license import activate

            token = str(body.get("token") or "")
            if not token:
                raise ValueError("token required")
            lic = activate(token)
            return 200, {"ok": True, "license": lic, "state": self.refresh()}
        if method == "POST" and path == "/addons/install":
            return 200, self._install_addons(body)
        return 404, {"ok": False, "error": f"unknown {method} {path}"}

    def _add_storage(self, body: dict[str, Any]) -> dict[str, Any]:
        name = (body.get("name") or "primary").strip()
        data_path = (body.get("data_path") or "").strip() or None
        try:
            capacity_gb = parse_capacity_gb(
                body.get("capacity_gb", body.get("size_gb", body.get("size")))
            )
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        if get_backend(name):
            raise ValueError(f"backend {name!r} already exists")
        if not which_juicefs():
            raise RuntimeError("juicefs is not installed yet")
        backend = default_backend(name, data_path, capacity_gb=capacity_gb)
        format_backend(backend)
        upsert_backend(backend)
        self._sync_filebrowser_root()
        try:
            from meshdrive.addons.openfga import grant_mcp_reader

            grant_mcp_reader(backend["name"])
        except Exception:
            pass
        return {"ok": True, "backend": backend, "state": self.refresh()}

    def _mount(self, name: str) -> dict[str, Any]:
        backend = get_backend(name)
        if not backend:
            raise KeyError(f"unknown backend {name!r}")
        if not backend.get("formatted"):
            format_backend(backend)
            upsert_backend(backend)
        else:
            # Push capacity into JuiceFS metadata so `df` shows allocated size.
            from meshdrive.storage.juicefs import apply_capacity

            try:
                apply_capacity(backend)
                upsert_backend(backend)
            except RuntimeError:
                pass
        if systemd.systemd_available():
            systemd.enable_now(systemd.mount_unit(name))
        else:
            mount_backend(backend, foreground=False)
        self._sync_filebrowser_root()
        return {"ok": True, "mounted": is_mounted(backend["mount_point"]), "state": self.refresh()}

    def _unmount(self, name: str) -> dict[str, Any]:
        backend = get_backend(name)
        if not backend:
            raise KeyError(f"unknown backend {name!r}")
        if systemd.systemd_available():
            systemd.stop_unit(systemd.mount_unit(name))
        try:
            unmount_backend(backend)
        except RuntimeError:
            if is_mounted(backend["mount_point"]):
                raise
        return {"ok": True, "state": self.refresh()}

    def _delete_storage(self, name: str, *, wipe_data: bool = False) -> dict[str, Any]:
        backend = get_backend(name)
        if not backend:
            raise KeyError(f"unknown backend {name!r}")
        unit = systemd.mount_unit(name)
        if systemd.systemd_available():
            systemd.stop_unit(unit)
            systemd.disable_unit(unit)
        if is_mounted(backend["mount_point"]):
            try:
                unmount_backend(backend)
            except RuntimeError:
                if is_mounted(backend["mount_point"]):
                    raise RuntimeError(
                        f"failed to unmount {name!r}; stop processes using the mount and retry"
                    )
        if wipe_data:
            wipe_backend_data(backend)
        delete_backend(name)
        remove_storage_access(name)
        self._sync_filebrowser_root()
        return {"ok": True, "deleted": name, "wipe_data": wipe_data, "state": self.refresh()}

    def _add_user(self, body: dict[str, Any]) -> dict[str, Any]:
        username = body.get("username") or ""
        password = body.get("password") or ""
        admin = bool(body.get("admin"))
        rec = add_user(username, password, admin=admin)
        unit = systemd.filebrowser_unit()
        was_running = systemd.unit_is_active(unit)
        # BoltDB is single-writer; stop Filebrowser before CLI user changes.
        if was_running:
            systemd.stop_unit(unit)
        try:
            add_filebrowser_user(username, password, admin=admin)
        except RuntimeError as exc:
            if was_running:
                try:
                    systemd.start_unit(unit)
                except RuntimeError:
                    pass
            raise RuntimeError(
                f"MeshDrive user saved, but Filebrowser sync failed: {exc}. "
                "Fix with: sudo systemctl stop meshdrive-filebrowser && "
                f"sudo -u meshdrive /opt/meshdrive/bin/filebrowser users update "
                f"{username} -p '<password>' -d /opt/meshdrive/var/filebrowser.db && "
                "sudo systemctl start meshdrive-filebrowser"
            ) from exc
        if was_running:
            systemd.start_unit(unit)
        return {"ok": True, "user": rec, "state": self.refresh()}

    def _delete_user(self, username: str) -> dict[str, Any]:
        delete_user(username)
        unit = systemd.filebrowser_unit()
        was_running = systemd.unit_is_active(unit)
        if was_running:
            systemd.stop_unit(unit)
        try:
            delete_filebrowser_user(username)
        finally:
            if was_running:
                try:
                    systemd.start_unit(unit)
                except RuntimeError:
                    pass
        return {"ok": True, "state": self.refresh()}

    def _filebrowser_start(self) -> dict[str, Any]:
        if not which_filebrowser():
            raise RuntimeError("filebrowser binary not found")
        self._sync_filebrowser_root()
        self._ensure_bootstrap_admin()
        if systemd.systemd_available():
            systemd.enable_now(systemd.filebrowser_unit())
        return {"ok": True, "state": self.refresh()}

    def _ensure_bootstrap_admin(self) -> None:
        if list_users():
            return
        if BOOTSTRAP_PASSWORD.is_file():
            password = BOOTSTRAP_PASSWORD.read_text(encoding="utf-8").strip()
        else:
            password = secrets.token_urlsafe(12)
            BOOTSTRAP_PASSWORD.write_text(password + "\n", encoding="utf-8")
            try:
                BOOTSTRAP_PASSWORD.chmod(0o600)
            except OSError:
                pass
        try:
            add_user("admin", password, admin=True)
        except ValueError:
            pass
        unit = systemd.filebrowser_unit()
        was_running = systemd.unit_is_active(unit)
        if was_running:
            systemd.stop_unit(unit)
        try:
            add_filebrowser_user("admin", password, admin=True)
        except RuntimeError:
            pass
        finally:
            if was_running:
                try:
                    systemd.start_unit(unit)
                except RuntimeError:
                    pass

    def _sync_filebrowser_root(self) -> None:
        """One Filebrowser instance serves all volumes under $ROOT/mnt/<name>/."""
        cfg = load_config()
        md = root(cfg)
        fb = md.setdefault("filebrowser", {})
        MNT.mkdir(parents=True, exist_ok=True)
        root_path = str(MNT)
        fb["root"] = root_path
        save_config(cfg)
        write_filebrowser_json(
            address=str(fb.get("address") or "127.0.0.1"),
            port=int(fb.get("port") or 8080),
            root=str(root_path),
            database=str(fb.get("database") or ""),
        )

    def _install_addons(self, body: dict[str, Any]) -> dict[str, Any]:
        names = list(body.get("names") or [])
        if body.get("name"):
            names.append(body["name"])
        names = [str(n).strip() for n in names if str(n).strip()]
        if not names:
            raise ValueError("name or names required")
        from meshdrive.addons.install import AddonError, _canonical, install

        for name in names:
            _canonical(name)

        def work() -> None:
            try:
                install(names)
            except AddonError:
                pass
            self.refresh()

        threading.Thread(target=work, name="meshdrive-addon-install", daemon=True).start()
        return {"ok": True, "started": True, "names": names, "state": self.refresh()}

    def _save_settings(self, body: dict[str, Any]) -> dict[str, Any]:
        cfg = load_config()
        md = root(cfg)
        tel = md.setdefault("telemetry", {})
        if "telemetry_enabled" in body:
            tel["enabled"] = bool(body["telemetry_enabled"])
        fb = md.setdefault("filebrowser", {})
        if "filebrowser_port" in body:
            fb["port"] = int(body["filebrowser_port"])
        save_config(cfg)
        self._sync_filebrowser_root()
        return {"ok": True, "state": self.refresh()}


def make_handler(api: AgentAPI) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _send(self, code: int, payload: dict[str, Any]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _read_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or "0")
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            if not raw:
                return {}
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("JSON object required")
            return data

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            code, payload = api.handle("GET", parsed.path, None)
            self._send(code, payload)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            try:
                body = self._read_body()
            except (ValueError, json.JSONDecodeError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
                return
            code, payload = api.handle("POST", parsed.path, body)
            self._send(code, payload)

        def do_DELETE(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            query = {key: values[0] for key, values in parse_qs(parsed.query).items() if values}
            code, payload = api.handle("DELETE", parsed.path, query or None)
            self._send(code, payload)

    return Handler


def serve(api: AgentAPI, host: str = CONTROL_HOST, port: int = CONTROL_PORT) -> ThreadingHTTPServer:
    handler = make_handler(api)
    httpd = ThreadingHTTPServer((host, port), handler)
    thread = threading.Thread(target=httpd.serve_forever, name="meshdrive-api", daemon=True)
    thread.start()
    return httpd
