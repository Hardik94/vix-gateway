"""MeshDrive Textual TUI — dashboard, storage, users, add-ons."""

from __future__ import annotations

from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    Static,
    TabbedContent,
    TabPane,
)

from meshdrive import __version__
from meshdrive.tui.client import AgentClient, AgentError
from meshdrive.tui.screens import (
    AddStorageScreen,
    AddUserScreen,
    AssignBucketsScreen,
    AssignUsersScreen,
    DeleteStorageScreen,
)

CSS = """
Screen {
    background: $surface;
}
#banner {
    padding: 1 2;
    height: auto;
    border: solid $primary;
    margin: 1 1 0 1;
}
.status-ok { color: $success; }
.status-bad { color: $error; }
.status-warn { color: $warning; }
.section {
    border: solid $primary;
    padding: 1 2;
    margin: 1;
    height: auto;
}
.row { height: auto; }
DataTable { height: 12; margin: 1 0; }
#addon-list { height: auto; }
.addon-row {
    height: 3;
    margin: 0 0 1 0;
}
ProgressBar { width: 1fr; }
#dialog {
    width: 70;
    height: auto;
    max-height: 90%;
    padding: 1 2;
    border: solid $accent;
    background: $panel;
}
#bucket-checks, #user-checks {
    height: 12;
    margin: 1 0;
}
.dialog-title { text-style: bold; margin-bottom: 1; }
.dialog-buttons { height: auto; margin-top: 1; }
"""


def _bar(percent: int, width: int = 10) -> str:
    """ASCII progress bar — Unicode blocks break Textual DataTable rendering (e.g. '1 P')."""
    pct = max(0, min(100, int(percent)))
    filled = max(0, min(width, round(pct * width / 100)))
    return f"[{'#' * filled}{'-' * (width - filled)}] {pct}%"


def _fmt_bytes(n: int) -> str:
    value = float(max(0, int(n)))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)}{unit}"
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{n}B"


def _size_label(capacity_gb: object) -> str:
    if capacity_gb in (None, "", 0, "0"):
        return "unlimited"
    try:
        return f"{int(capacity_gb)}G"
    except (TypeError, ValueError):
        return str(capacity_gb)


def _status_glyph(status: str) -> str:
    mapping = {
        "ready": "OK",
        "running": "OK",
        "missing": "missing",
        "error": "error",
            "installing": "installing",
            "installed": "installed",
            "coming_later": "later",
        "unknown": "unknown",
    }
    return mapping.get(status, status)


class MeshDriveTUI(App[None]):
    TITLE = "MeshDrive Agent"
    SUB_TITLE = f"v{__version__}  local-first"
    CSS = CSS
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("s", "focus_storage", "Storage"),
        Binding("u", "focus_users", "Users"),
        Binding("a", "focus_addons", "Add-ons"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.client = AgentClient()
        self.state: dict[str, Any] = {}
        self.offline = True

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Connecting to agent…", id="banner")
        with TabbedContent(id="tabs"):
            with TabPane("Dashboard", id="tab-dash"):
                yield VerticalScroll(Static("Loading…", id="dash-body"))
            with TabPane("Storage", id="tab-storage"):
                yield Vertical(
                    Static("JuiceFS backends", classes="section"),
                    DataTable(id="storage-table"),
                    Horizontal(
                        Button("Add storage", id="btn-add-storage", variant="primary"),
                        Button("Mount", id="btn-mount"),
                        Button("Unmount", id="btn-unmount"),
                        Button("Assign users", id="btn-assign-users"),
                        Button("Delete storage", id="btn-del-storage", variant="error"),
                        Button("Start Filebrowser", id="btn-fb-start"),
                        classes="row",
                    ),
                )
            with TabPane("Users", id="tab-users"):
                yield Vertical(
                    Static(
                        "Local users — assign storage buckets (many-to-many). "
                        "Filebrowser portal = only assigned buckets.",
                        classes="section",
                    ),
                    DataTable(id="users-table"),
                    Horizontal(
                        Button("Add user", id="btn-add-user", variant="primary"),
                        Button("Assign buckets", id="btn-assign-buckets"),
                        Button("Delete user", id="btn-del-user", variant="error"),
                        classes="row",
                    ),
                )
            with TabPane("Add-ons", id="tab-addons"):
                yield VerticalScroll(id="addon-list")
            with TabPane("Settings", id="tab-settings"):
                yield Vertical(
                    Static("Settings", classes="section"),
                    Checkbox("Keep local telemetry files under /opt/meshdrive/var/telemetry", id="chk-telemetry"),
                    Label("Filebrowser port"),
                    Input(value="8080", id="fb-port"),
                    Button("Save settings", id="btn-save-settings", variant="primary"),
                )
        yield Footer()

    def on_mount(self) -> None:
        storage = self.query_one("#storage-table", DataTable)
        storage.add_columns("Name", "Mounted", "Size", "Usage", "Free", "Users", "Path")
        storage.cursor_type = "row"
        users = self.query_one("#users-table", DataTable)
        users.add_columns("Username", "Groups", "Buckets")
        users.cursor_type = "row"
        self.set_interval(3.0, self.action_refresh)
        self.action_refresh()

    def action_refresh(self) -> None:
        # Exclusive worker avoids remounting addon buttons while prior remove_children is in flight.
        self.run_worker(self._refresh_async(), exclusive=True, group="meshdrive-refresh")

    async def _refresh_async(self) -> None:
        try:
            payload = self.client.state()
            self.state = payload.get("state", payload)
            self.offline = False
        except AgentError as exc:
            self.offline = True
            self.state = {}
            banner = self.query_one("#banner", Static)
            from meshdrive.agent.systemd import agent_start_hint, snap_installed

            if snap_installed():
                hint = (
                    "Snap unit is snap.meshdrive.agent.service (not meshdrive-agent).\n"
                    f"Start it with:  {agent_start_hint()}"
                )
            else:
                hint = f"Start it with:  {agent_start_hint()}"
            banner.update(f"[bold red]Agent offline[/]  {exc}\n{hint}")
            return
        await self._render()

    async def _render(self) -> None:
        st = self.state
        agent = st.get("agent") or {}
        comps = st.get("components") or {}
        fuse = (comps.get("fuse") or {}).get("status", "unknown")
        juice = comps.get("juicefs") or {}
        fb = comps.get("filebrowser") or {}
        users = st.get("users") or {}
        banner = self.query_one("#banner", Static)
        glyph = "operational" if not self.offline else "offline"
        url = st.get("filebrowser_url") or fb.get("url") or "http://127.0.0.1:8080"
        banner.update(
            f"Status: {glyph}    Agent: {agent.get('listen', '')}\n"
            f"FUSE: {_status_glyph(fuse)}    JuiceFS: {_status_glyph(juice.get('status', ''))} "
            f"{juice.get('version') or ''}    Filebrowser: {_status_glyph(fb.get('status', ''))}  {url}"
        )

        lines = ["[b]Storage[/b]"]
        for row in st.get("storage") or []:
            mounted = "mounted" if row.get("mounted") else "unmounted"
            lines.append(
                f"  {row.get('name')}  {_bar(int(row.get('usage_percent') or 0))}  "
                f"{mounted}  free {_fmt_bytes(int(row.get('free_bytes') or 0))}"
            )
        if not st.get("storage"):
            lines.append("  (none yet — open the Storage tab and add a backend)")
        lines.append("")
        lines.append(f"[b]Authentication[/b]    local users: {users.get('count', 0)}")
        if st.get("bootstrap_password_present"):
            lines.append("  bootstrap password file: /opt/meshdrive/var/bootstrap-password.txt")
        lines.append("")
        lines.append("[b]Network[/b]")
        addons = st.get("addons") or {}
        wg = (addons.get("wireguard") or {}).get("status", "not_installed")
        mcp = (addons.get("mcp") or {}).get("status", "not_installed")
        lines.append(f"  WireGuard: {_status_glyph(wg)}")
        lines.append(f"  Local Filebrowser: {url}")
        lines.append(f"  MCP: {_status_glyph(mcp)}")
        self.query_one("#dash-body", Static).update("\n".join(lines))

        table = self.query_one("#storage-table", DataTable)
        table.clear()
        user_items = (st.get("users") or {}).get("items") or []
        for row in st.get("storage") or []:
            size_label = _size_label(row.get("capacity_gb"))
            bname = str(row.get("name") or "")
            members = [
                str(u.get("username") or "")
                for u in user_items
                if bname and bname in (u.get("storage_access") or [])
            ]
            table.add_row(
                bname,
                "yes" if row.get("mounted") else "no",
                size_label,
                _bar(int(row.get("usage_percent") or 0)),
                _fmt_bytes(int(row.get("free_bytes") or 0)),
                ",".join(members) if members else "—",
                str(row.get("mount_point") or row.get("data_path") or ""),
                key=bname,
            )

        utable = self.query_one("#users-table", DataTable)
        utable.clear()
        for user in users.get("items") or []:
            groups = ",".join(user.get("groups") or [])
            access = ",".join(user.get("storage_access") or [])
            utable.add_row(user.get("username", ""), groups, access, key=user.get("username", ""))

        addon_list = self.query_one("#addon-list", VerticalScroll)
        await addon_list.remove_children()
        addons = st.get("addons") or {}
        labels = {
            "mcp": ("MCP server (AI tools)", "mcp"),
            "openfga": ("OpenFGA authorization", "openfga"),
            "telemetry": ("OpenTelemetry collector", "otel"),
            "wireguard": ("WireGuard hub-spoke client", "wireguard"),
            "vix_gateway": ("VIX QUIC gateway", "vix-gateway"),
            "vix_fuse": ("VIX FUSE remote mount", "vix-fuse"),
            "sssd": ("SSSD / LDAP over WG", "sssd-ldap"),
            "remote_cluster": ("Remote JuiceFS cluster", "remote-cluster"),
        }
        await addon_list.mount(
            Static(
                "Modules install into the MeshDrive root only. Paid modules require meshdrive license activate.",
                classes="section",
            )
        )
        for key, (title, install_name) in labels.items():
            info = addons.get(key) or {}
            status = info.get("status", "not_installed")
            progress = int(info.get("progress") or 0)
            locked = bool(info.get("locked"))
            msg = info.get("message") or _status_glyph(status)
            prefix = "🔒 " if locked else ""
            await addon_list.mount(Static(f"{prefix}{title}  —  {msg}", classes="addon-row"))
            bar = ProgressBar(total=100, show_eta=False, classes="addon-row")
            await addon_list.mount(bar)
            bar.progress = progress
            if locked:
                await addon_list.mount(
                    Static("Activate license: meshdrive license activate --token …", classes="addon-row")
                )
            elif install_name and status not in {"ready", "installing"}:
                # Avoid fixed IDs — refresh remounts these every few seconds (Textual
                # duplicateId if remove_children has not finished yet).
                btn = Button(
                    f"Install {install_name}",
                    classes="addon-install",
                    variant="primary",
                )
                btn.addon_name = install_name  # type: ignore[attr-defined]
                await addon_list.mount(btn)

        tel = (addons.get("telemetry") or {}).get("enabled", False)
        self.query_one("#chk-telemetry", Checkbox).value = bool(tel)

    def _selected_storage(self) -> str | None:
        table = self.query_one("#storage-table", DataTable)
        if table.row_count == 0:
            return None
        row = table.get_row_at(table.cursor_row)
        return str(row[0]) if row else None

    def _selected_user(self) -> str | None:
        table = self.query_one("#users-table", DataTable)
        if table.row_count == 0:
            return None
        row = table.get_row_at(table.cursor_row)
        return str(row[0]) if row else None

    def _call(self, fn, *args: Any, **kwargs: Any) -> None:
        try:
            fn(*args, **kwargs)
            self.action_refresh()
        except AgentError as exc:
            self.notify(str(exc), severity="error", title="MeshDrive")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-add-storage":
            self.push_screen(AddStorageScreen(), self._on_add_storage)
        elif bid == "btn-mount":
            name = self._selected_storage()
            if not name:
                self.notify("Select a storage backend", severity="warning")
                return
            self._call(self.client.mount, name)
        elif bid == "btn-unmount":
            name = self._selected_storage()
            if not name:
                self.notify("Select a storage backend", severity="warning")
                return
            self._call(self.client.unmount, name)
        elif bid == "btn-del-storage":
            name = self._selected_storage()
            if not name:
                self.notify("Select a storage backend", severity="warning")
                return
            self.push_screen(DeleteStorageScreen(name), self._on_delete_storage)
        elif bid == "btn-fb-start":
            self._call(self.client.start_filebrowser)
        elif bid == "btn-assign-users":
            name = self._selected_storage()
            if not name:
                self.notify("Select a storage backend", severity="warning")
                return
            usernames = [
                str(u.get("username") or "")
                for u in (self.state.get("users") or {}).get("items") or []
                if u.get("username")
            ]
            selected = [
                str(u.get("username") or "")
                for u in (self.state.get("users") or {}).get("items") or []
                if name in (u.get("storage_access") or [])
            ]
            self.push_screen(
                AssignUsersScreen(name, usernames, selected),
                self._on_assign_users,
            )
        elif bid == "btn-add-user":
            buckets = [str(r.get("name") or "") for r in self.state.get("storage") or [] if r.get("name")]
            self.push_screen(AddUserScreen(buckets), self._on_add_user)
        elif bid == "btn-assign-buckets":
            name = self._selected_user()
            if not name:
                self.notify("Select a user", severity="warning")
                return
            buckets = [str(r.get("name") or "") for r in self.state.get("storage") or [] if r.get("name")]
            selected: list[str] = []
            for u in (self.state.get("users") or {}).get("items") or []:
                if u.get("username") == name:
                    selected = list(u.get("storage_access") or [])
                    break
            self.push_screen(
                AssignBucketsScreen(name, buckets, selected),
                self._on_assign_buckets,
            )
        elif bid == "btn-del-user":
            name = self._selected_user()
            if not name:
                self.notify("Select a user", severity="warning")
                return
            self._call(self.client.delete_user, name)
        elif bid == "btn-save-settings":
            port_raw = self.query_one("#fb-port", Input).value.strip() or "8080"
            try:
                port = int(port_raw)
            except ValueError:
                self.notify("Port must be a number", severity="error")
                return
            enabled = self.query_one("#chk-telemetry", Checkbox).value
            self._call(self.client.save_settings, telemetry_enabled=enabled, filebrowser_port=port)
        elif event.button.has_class("addon-install"):
            addon = getattr(event.button, "addon_name", None) or ""
            if not addon:
                return
            self.notify(f"Installing {addon}…")
            self._call(self.client.install_addons, addon)

    def _on_add_storage(self, result: dict | None) -> None:
        if not result:
            return
        self._call(
            self.client.add_storage,
            result["name"],
            result.get("data_path") or "",
            result.get("capacity_gb"),
        )

    def _on_delete_storage(self, result: dict | None) -> None:
        if not result:
            return
        self._call(
            self.client.delete_storage,
            result["name"],
            wipe_data=bool(result.get("wipe_data")),
        )

    def _on_add_user(self, result: dict | None) -> None:
        if not result:
            return
        self._call(
            self.client.add_user,
            result["username"],
            result["password"],
            result["admin"],
            result.get("storage_access") or [],
        )

    def _on_assign_buckets(self, result: dict | None) -> None:
        if not result:
            return
        self._call(
            self.client.set_user_storage_access,
            result["username"],
            result.get("storage_access") or [],
        )

    def _on_assign_users(self, result: dict | None) -> None:
        if not result:
            return
        self._call(
            self.client.set_storage_users,
            result["backend"],
            result.get("users") or [],
        )

    def action_focus_storage(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-storage"

    def action_focus_users(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-users"

    def action_focus_addons(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-addons"


def run() -> None:
    MeshDriveTUI().run()
