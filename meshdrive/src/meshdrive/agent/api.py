"""Loopback JSON control API for the TUI (not MCP)."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from meshdrive.auth import (
    add_user,
    delete_user,
    list_users,
    remove_storage_access,
    set_backend_users,
    set_storage_access,
    users_for_backend,
)
from meshdrive.config import backends, delete_backend, get_backend, load_config, root, save_config, upsert_backend
from meshdrive.constants import BOOTSTRAP_PASSWORD, CONTROL_HOST, CONTROL_PORT, MNT, ROOT
from meshdrive.storage.filebrowser import (
    add_filebrowser_user,
    delete_filebrowser_user,
    set_filebrowser_scope,
    which_filebrowser,
    write_filebrowser_json,
)
from meshdrive.storage.homes import ensure_user_private
from meshdrive.storage.portals import (
    filebrowser_scope_for_user,
    remove_user_portal,
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
        if method == "POST" and path.startswith("/storage/") and path.endswith("/users"):
            name = unquote(path[len("/storage/") : -len("/users")].rstrip("/"))
            return 200, self._set_storage_users(name, body)
        if method == "GET" and path.startswith("/storage/") and path.endswith("/users"):
            name = unquote(path[len("/storage/") : -len("/users")].rstrip("/"))
            return 200, {"ok": True, "backend": name, "users": users_for_backend(name)}
        if method == "DELETE" and path.startswith("/storage/"):
            name = unquote(path[len("/storage/") :])
            wipe_raw = str((body or {}).get("wipe_data") or "").lower()
            wipe_data = wipe_raw in {"1", "true", "yes"}
            return 200, self._delete_storage(name, wipe_data=wipe_data)
        if method == "POST" and path == "/users":
            return 200, self._add_user(body)
        if method == "POST" and path.startswith("/users/") and path.endswith("/storage_access"):
            username = unquote(path[len("/users/") : -len("/storage_access")].rstrip("/"))
            return 200, self._set_user_storage_access(username, body)
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
        # Ensure private dirs exist for users already granted this bucket
        mount = backend.get("mount_point") or ""
        if mount:
            for username in users_for_backend(name):
                try:
                    ensure_user_private(mount, username)
                except OSError:
                    pass
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
        # Refresh portals for all users (symlinks to deleted bucket removed)
        self._rebuild_all_user_portals()
        self._sync_filebrowser_root()
        return {"ok": True, "deleted": name, "wipe_data": wipe_data, "state": self.refresh()}

    def _add_user(self, body: dict[str, Any]) -> dict[str, Any]:
        username = body.get("username") or ""
        password = body.get("password") or ""
        admin = bool(body.get("admin"))
        raw_access = body.get("storage_access")
        storage_access: list[str] | None = None
        if isinstance(raw_access, list):
            storage_access = [str(x).strip() for x in raw_access if str(x).strip()]
            self._validate_bucket_names(storage_access)
        rec = add_user(username, password, admin=admin, storage_access=storage_access)
        scope = filebrowser_scope_for_user(
            username,
            admin=admin,
            storage_access=list(rec.get("storage_access") or []),
        )
        unit = systemd.filebrowser_unit()
        was_running = systemd.unit_is_active(unit)
        if was_running:
            systemd.stop_unit(unit)
        try:
            add_filebrowser_user(username, password, admin=admin, scope=scope)
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
        return {"ok": True, "user": rec, "scope": scope, "state": self.refresh()}

    def _set_user_storage_access(self, username: str, body: dict[str, Any]) -> dict[str, Any]:
        username = username.strip()
        if not username:
            raise ValueError("username required")
        raw = body.get("storage_access")
        if not isinstance(raw, list):
            raise ValueError("storage_access must be a list of bucket names")
        access = [str(x).strip() for x in raw if str(x).strip()]
        self._validate_bucket_names(access)
        rec = set_storage_access(username, access)
        scope = self._apply_user_portal_and_scope(username)
        return {
            "ok": True,
            "user": rec,
            "scope": scope,
            "state": self.refresh(),
        }

    def _set_storage_users(self, name: str, body: dict[str, Any]) -> dict[str, Any]:
        name = name.strip()
        if not get_backend(name):
            raise KeyError(f"unknown backend {name!r}")
        raw = body.get("users")
        if not isinstance(raw, list):
            raise ValueError("users must be a list of usernames")
        wanted = [str(u).strip() for u in raw if str(u).strip()]
        known = {u["username"] for u in list_users()}
        unknown = [u for u in wanted if u not in known]
        if unknown:
            raise ValueError(f"unknown users: {', '.join(unknown)}")
        set_backend_users(name, wanted)
        # Rebuild portals for everyone (membership may have been removed)
        touched = self._rebuild_all_user_portals()
        return {
            "ok": True,
            "backend": name,
            "users": users_for_backend(name),
            "portals": touched,
            "state": self.refresh(),
        }

    def _validate_bucket_names(self, names: list[str]) -> None:
        known = {str(item.get("name") or "") for item in backends()}
        bad = [n for n in names if n not in known]
        if bad:
            raise ValueError(
                f"unknown storage bucket(s): {', '.join(bad)}. "
                "Create/mount storage first, then assign."
            )

    def _apply_user_portal_and_scope(self, username: str) -> str | None:
        access: list[str] = []
        admin = False
        for user in list_users():
            if user.get("username") == username:
                access = list(user.get("storage_access") or [])
                admin = "admin" in (user.get("groups") or [])
                break
        else:
            raise KeyError(username)
        scope = filebrowser_scope_for_user(username, admin=admin, storage_access=access)
        unit = systemd.filebrowser_unit()
        was_running = systemd.unit_is_active(unit)
        if was_running:
            systemd.stop_unit(unit)
        try:
            if which_filebrowser():
                if scope:
                    set_filebrowser_scope(username, scope)
                else:
                    # Admin / unrestricted — scope to global mnt root
                    set_filebrowser_scope(username, str(MNT))
        except RuntimeError as exc:
            if was_running:
                try:
                    systemd.start_unit(unit)
                except RuntimeError:
                    pass
            raise RuntimeError(f"Filebrowser scope update failed: {exc}") from exc
        if was_running:
            systemd.start_unit(unit)
        return scope

    def _rebuild_all_user_portals(self) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        unit = systemd.filebrowser_unit()
        was_running = systemd.unit_is_active(unit)
        if was_running:
            systemd.stop_unit(unit)
        try:
            for user in list_users():
                name = str(user.get("username") or "")
                if not name:
                    continue
                admin = "admin" in (user.get("groups") or [])
                access = list(user.get("storage_access") or [])
                scope = filebrowser_scope_for_user(name, admin=admin, storage_access=access)
                try:
                    if which_filebrowser():
                        set_filebrowser_scope(name, scope or str(MNT))
                except RuntimeError:
                    pass
                out[name] = scope
        finally:
            if was_running:
                try:
                    systemd.start_unit(unit)
                except RuntimeError:
                    pass
        return out

    def _delete_user(self, username: str) -> dict[str, Any]:
        delete_user(username)
        remove_user_portal(username)
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
        self._ensure_local_hostname()
        self._ensure_bootstrap_admin()
        if systemd.systemd_available():
            # Refresh unit (LAN bind; no IPAddressDeny) from overlay if present.
            unit_src = ROOT / "systemd" / "meshdrive-filebrowser.service"
            if not unit_src.is_file():
                cand = Path(__file__).resolve().parents[3] / "overlay" / "opt" / "meshdrive" / "systemd" / "meshdrive-filebrowser.service"
                if cand.is_file():
                    unit_src = cand
            if unit_src.is_file():
                dest = Path("/etc/systemd/system/meshdrive-filebrowser.service")
                try:
                    shutil.copy2(unit_src, dest)
                    systemd.systemctl("daemon-reload")
                except OSError:
                    pass
            systemd.enable_now(systemd.filebrowser_unit())
        return {"ok": True, "state": self.refresh()}

    def _ensure_local_hostname(self) -> None:
        """Best-effort: meshdrive.local in /etc/hosts (+ Avahi if present)."""
        script = ROOT / "packaging" / "ensure-local-hostname.sh"
        if not script.is_file():
            alt = Path(__file__).resolve().parents[3] / "packaging" / "ensure-local-hostname.sh"
            if alt.is_file():
                script = alt
        if not script.is_file():
            return
        cfg = load_config()
        fb = root(cfg).get("filebrowser") or {}
        fqdn = str(fb.get("hostname") or "meshdrive.local")
        env = {**os.environ, "MESHDRIVE_LOCAL_FQDN": fqdn}
        try:
            subprocess.run(
                ["bash", str(script)],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

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
        fb.setdefault("hostname", "meshdrive.local")
        # Empty string = all interfaces (dual-stack). Keep explicit loopback if set.
        if "address" not in fb:
            fb["address"] = ""
        save_config(cfg)
        write_filebrowser_json(
            address=str(fb.get("address") if fb.get("address") is not None else ""),
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
