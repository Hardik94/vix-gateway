# MCP integration

The MeshDrive MCP (Model Context Protocol) server exposes **storage tools** to AI assistants with strict path isolation.

## Connect your client (start here)

**Step-by-step for Cursor, Claude Code, Open WebUI, and Hermes:**

→ **[mcp-clients.md](mcp-clients.md)**

## Overview

| Property | Value |
|----------|-------|
| Install | `meshdrive addons install mcp` |
| Transport | `stdio` (default) or `sse` on `127.0.0.1:9000` |
| Command | `$ROOT/bin/meshdrive-mcp` |
| Systemd | `meshdrive-mcp.service` |
| Path scope | `isolation.allowed_paths` (default: install root only) |

Implementation: `src/meshdrive/mcp/server.py`

## Minimal stdio config (Cursor / Claude Code)

```json
{
  "mcpServers": {
    "meshdrive": {
      "command": "/opt/meshdrive/bin/meshdrive-mcp",
      "args": [],
      "env": {
        "MESHDRIVE_ROOT": "/opt/meshdrive",
        "MESHDRIVE_MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

Example on disk: [`overlay/opt/meshdrive/etc/mcp-client.json`](../overlay/opt/meshdrive/etc/mcp-client.json).

For snap: set `MESHDRIVE_ROOT` to `/var/snap/meshdrive/common`.

The installer does **not** auto-write into `~/.cursor` or Claude config — copy the JSON yourself (privacy / isolation policy).

## Available tools

| Tool | Description |
|------|-------------|
| `list_storage_backends` | Names, mount points, usage |
| `get_storage_stats` | Disk stats for a backend |
| `read_file` | Read file under allowed paths |
| `write_file` | Write file under allowed paths |
| `list_directory` | List directory entries |
| `get_file_info` | Metadata for a path |
| `health_check` | MCP + component health |

### Intentionally blocked

- `create_user`, `delete_user`
- `change_permissions`, `system_config`
- `auth.add_user`, `auth.users`

User administration remains TUI/agent only.

## Path isolation

```text
Allowed:  /opt/meshdrive/mnt/primary/docs/readme.txt
Denied:   /etc/passwd
Denied:   /home/user/secret.txt
```

See `src/meshdrive/paths.py` and `isolation.allowed_paths` in config.

## OpenFGA

Optional: `meshdrive addons install openfga` — MCP principal `agent:mcp` checked for reader/writer on files and backends.

## Running manually

```bash
# stdio (editors)
MESHDRIVE_ROOT=/opt/meshdrive meshdrive-mcp

# SSE (Open WebUI / HTTP clients)
MESHDRIVE_ROOT=/opt/meshdrive MESHDRIVE_MCP_TRANSPORT=sse \
  MESHDRIVE_MCP_HOST=127.0.0.1 MESHDRIVE_MCP_PORT=9000 \
  /opt/meshdrive/bin/meshdrive-mcp
```

## Testing isolation

1. `read_file` under `$ROOT/mnt/primary/...` → allowed  
2. `read_file` on `/etc/passwd` → denied  

## Logs

```bash
journalctl -u meshdrive-mcp -b --no-pager
```

## Related

- [mcp-clients.md](mcp-clients.md) — Cursor, Claude Code, Open WebUI, Hermes  
- [addons.md](addons.md) · [configuration.md](configuration.md) · [architecture.md](architecture.md)  
