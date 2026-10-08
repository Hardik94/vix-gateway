# Agent API

The MeshDrive agent exposes a **loopback-only** JSON HTTP API for the TUI and automation. It is **not** the MCP server and is not reachable from the network by default.

**Base URL:** `http://127.0.0.1:12700` (override with `MESHDRIVE_CONTROL_HOST` / `MESHDRIVE_CONTROL_PORT`)

Implementation: `src/meshdrive/agent/api.py`

## Endpoints

### Health and state

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Agent OK + full state snapshot |
| `GET` | `/state` | Current `state.json` contents |
| `GET` | `/config` | Raw `config.yaml` |

Example:

```bash
curl -sS http://127.0.0.1:12700/health | jq .
curl -sS http://127.0.0.1:12700/state | jq .storage
```

### Storage

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `POST` | `/storage/add` | `{"name":"primary","data_path":"/path"}` | Format new JuiceFS backend |
| `POST` | `/storage/mount` | `{"name":"primary"}` | Mount backend (systemd unit) |
| `POST` | `/storage/unmount` | `{"name":"primary"}` | Unmount backend |
| `DELETE` | `/storage/{name}` | Query: `wipe_data=1` (optional) | Remove backend; optionally delete local data files |

Add flow runs `juicefs format` with sqlite metadata and local `file://` storage, then upserts `config.yaml`. If OpenFGA is installed, grants MCP reader tuple on the new backend.

Delete flow unmounts the backend, disables `meshdrive-mount@<name>.service`, removes the config entry, and clears the name from user `storage_access` (portals rebuilt). With `wipe_data=1`, local metadata DB, object directory, cache, and mount folder are removed (local `juicefs` backends only).

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `GET` | `/storage/{name}/users` | — | Users assigned to this bucket |
| `POST` | `/storage/{name}/users` | `{"users":["alice","bob"]}` | Replace membership for this bucket |

### Users

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `GET` | `/users` | — | List local users (includes `storage_access`) |
| `POST` | `/users` | `{"username":"u","password":"p","admin":false,"storage_access":["primary"]}` | Create user (+ Filebrowser portal scope) |
| `POST` | `/users/{username}/storage_access` | `{"storage_access":["primary","photos"]}` | Replace user's bucket ACL + rebuild portal |
| `DELETE` | `/users/{username}` | — | Delete user (+ portal) |

User administration is intentionally **absent from MCP**. See [storage-acl.md](storage-acl.md).

### Filebrowser

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/filebrowser/start` | Sync root, ensure bootstrap admin, start unit |
| `POST` | `/filebrowser/stop` | Stop `meshdrive-filebrowser.service` |

### Settings

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `POST` | `/settings` | `{"telemetry_enabled":true,"filebrowser_port":8080}` | Update config |

### Add-ons

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `GET` | `/addons` | — | Addon status map |
| `POST` | `/addons/install` | `{"name":"mcp"}` or `{"names":["mcp","openfga"]}` | Start async install |

Install runs in a background thread; poll `/state` or TUI for progress. Paid addons fail license check before starting.

### License

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `GET` | `/license` | — | License status |
| `POST` | `/license/activate` | `{"token":"…"}` | Activate paid tier |

## Response format

Success responses include `"ok": true` where applicable. Errors:

```json
{"ok": false, "error": "message"}
```

HTTP status codes: `400` validation, `404` not found, `500` runtime failure.

## State snapshot

`/health` and `/state` return a structure similar to `var/state.json`:

```json
{
  "agent": {"status": "running", "listen": "127.0.0.1:12700"},
  "components": {
    "fuse": {"status": "ready"},
    "juicefs": {"status": "ready", "version": "1.4.1", "path": "/opt/meshdrive/bin/juicefs"},
    "filebrowser": {"status": "ready", "url": "http://127.0.0.1:8080", "listening": true}
  },
  "storage": [
    {"name": "primary", "mounted": true, "mount_point": "/opt/meshdrive/mnt/primary", "usage_percent": 12}
  ],
  "users": {"count": 1, "items": [...]},
  "addons": {
    "mcp": {"status": "ready", "tier": "free", "locked": false},
    "wireguard": {"status": "not_installed", "tier": "paid", "locked": true}
  }
}
```

## TUI client

The TUI uses `src/meshdrive/tui/client.py` — thin urllib wrapper over these endpoints.

Python helper for scripts:

```python
from meshdrive.agent.client import health
print(health())
```

## Security

- Binds **`127.0.0.1` only** — no authentication layer because it is not exposed externally
- Do not reverse-proxy this API to the network without adding auth and TLS
- MCP is a separate server with its own path isolation model — see [mcp.md](mcp.md)
