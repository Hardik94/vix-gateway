"""Modal screens for storage and user forms."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
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

    def __init__(self, bucket_names: list[str] | None = None) -> None:
        super().__init__()
        self.bucket_names = list(bucket_names or [])

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static("Add local user", classes="dialog-title")
            yield Label("Username")
            yield Input(placeholder="alice", id="username")
            yield Label("Password (min 12 characters — Filebrowser requirement)")
            yield Input(password=True, id="password")
            yield Label("Confirm password")
            yield Input(password=True, id="confirm")
            yield Checkbox("Admin (sees all buckets in Filebrowser)", id="admin")
            if self.bucket_names:
                yield Label("Storage buckets (optional — assign later)")
                with VerticalScroll(id="bucket-checks"):
                    for name in self.bucket_names:
                        yield Checkbox(name, id=f"new-bucket-{name}")
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
        access: list[str] = []
        for name in self.bucket_names:
            try:
                box = self.query_one(f"#new-bucket-{name}", Checkbox)
            except Exception:
                continue
            if box.value:
                access.append(name)
        self.dismiss(
            {
                "username": username,
                "password": password,
                "admin": admin,
                "storage_access": access,
            }
        )


class AssignBucketsScreen(ModalScreen[dict | None]):
    """Assign many buckets to one user."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(
        self,
        username: str,
        bucket_names: list[str],
        selected: list[str] | None = None,
    ) -> None:
        super().__init__()
        self.username = username
        self.bucket_names = list(bucket_names)
        self.selected = set(selected or [])

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(f"Assign buckets → {self.username}", classes="dialog-title")
            yield Static(
                "Checked buckets appear in this user's Filebrowser portal.\n"
                "Admins still see all mounts; ACL is stored for MCP/paid sync."
            )
            if not self.bucket_names:
                yield Static("No storage backends yet — add storage first.")
            else:
                with VerticalScroll(id="bucket-checks"):
                    for name in self.bucket_names:
                        yield Checkbox(
                            name,
                            id=f"assign-bucket-{name}",
                            value=name in self.selected,
                        )
            with Horizontal(classes="dialog-buttons"):
                yield Button("Save", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        access: list[str] = []
        for name in self.bucket_names:
            try:
                box = self.query_one(f"#assign-bucket-{name}", Checkbox)
            except Exception:
                continue
            if box.value:
                access.append(name)
        self.dismiss({"username": self.username, "storage_access": access})


class AssignUsersScreen(ModalScreen[dict | None]):
    """Assign many users to one storage bucket."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(
        self,
        backend_name: str,
        usernames: list[str],
        selected: list[str] | None = None,
    ) -> None:
        super().__init__()
        self.backend_name = backend_name
        self.usernames = list(usernames)
        self.selected = set(selected or [])

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(f"Assign users → bucket {self.backend_name}", classes="dialog-title")
            yield Static("Checked users get this bucket in their Filebrowser portal.")
            if not self.usernames:
                yield Static("No local users yet — add a user first.")
            else:
                with VerticalScroll(id="user-checks"):
                    for name in self.usernames:
                        yield Checkbox(
                            name,
                            id=f"assign-user-{name}",
                            value=name in self.selected,
                        )
            with Horizontal(classes="dialog-buttons"):
                yield Button("Save", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        users: list[str] = []
        for name in self.usernames:
            try:
                box = self.query_one(f"#assign-user-{name}", Checkbox)
            except Exception:
                continue
            if box.value:
                users.append(name)
        self.dismiss({"backend": self.backend_name, "users": users})


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
                "The backend is unmounted and removed from config.\n"
                "User bucket assignments for this name are cleared."
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
