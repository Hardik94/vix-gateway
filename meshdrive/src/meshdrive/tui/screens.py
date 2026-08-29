"""Modal screens for storage and user forms."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Static


class AddStorageScreen(ModalScreen[dict | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static("Add storage backend", classes="dialog-title")
            yield Label("Name")
            yield Input(value="primary", id="name")
            yield Label("Data path (directory on the disk to use)")
            yield Input(placeholder="/opt/meshdrive/var/data/primary", id="data_path")
            yield Label("Size / capacity (GB) — leave empty for unlimited")
            yield Input(placeholder="e.g. 100 or 100G", id="capacity_gb")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Add", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        name = self.query_one("#name", Input).value.strip()
        data_path = self.query_one("#data_path", Input).value.strip()
        capacity_raw = self.query_one("#capacity_gb", Input).value.strip()
        if not name:
            self.app.notify("Name is required", severity="error")
            return
        payload: dict = {"name": name, "data_path": data_path}
        if capacity_raw:
            payload["capacity_gb"] = capacity_raw
        self.dismiss(payload)


class AddUserScreen(ModalScreen[dict | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static("Add local user", classes="dialog-title")
            yield Label("Username")
            yield Input(placeholder="alice", id="username")
            yield Label("Password (min 12 characters — Filebrowser requirement)")
            yield Input(password=True, id="password")
            yield Label("Confirm password")
            yield Input(password=True, id="confirm")
            yield Checkbox("Admin", id="admin")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Create", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        username = self.query_one("#username", Input).value.strip()
        password = self.query_one("#password", Input).value
        confirm = self.query_one("#confirm", Input).value
        admin = self.query_one("#admin", Checkbox).value
        if not username or not password:
            self.app.notify("Username and password are required", severity="error")
            return
        if len(password) < 12:
            self.app.notify(
                "Password must be at least 12 characters (Filebrowser requirement)",
                severity="error",
            )
            return
        if password != confirm:
            self.app.notify("Passwords do not match", severity="error")
            return
        self.dismiss({"username": username, "password": password, "admin": admin})


class DeleteStorageScreen(ModalScreen[dict | None]):
    """Confirm removal of a storage backend."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, backend_name: str) -> None:
        super().__init__()
        self.backend_name = backend_name

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static("Delete storage backend", classes="dialog-title")
            yield Static(
                f"Remove {self.backend_name} from MeshDrive?\n"
                "The backend is unmounted and removed from config.",
            )
            yield Checkbox(
                "Also delete data files (metadata, objects, cache)",
                id="wipe_data",
            )
            with Horizontal(classes="dialog-buttons"):
                yield Button("Delete", id="ok", variant="error")
                yield Button("Cancel", id="cancel")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        wipe = self.query_one("#wipe_data", Checkbox).value
        self.dismiss({"name": self.backend_name, "wipe_data": wipe})
