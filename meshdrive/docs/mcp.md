# MCP integration

The MeshDrive MCP (Model Context Protocol) server exposes **storage tools** to AI assistants with strict path isolation.

## Connect your client (start here)

**Step-by-step for Cursor, Claude Code, Open WebUI, and Hermes:**

→ **[mcp-clients.md](mcp-clients.md)**

## Overview

| Property | Value |
|----------|-------|
| Install | `meshdrive addons install mcp` |
| **stdio** | Default for Cursor/Claude — `snap run meshdrive.mcp` or `$ROOT/bin/meshdrive-mcp` (no port) |
| **SSE** | `http://127.0.0.1:9000/sse` — Bearer token required; started by install (systemd on `.deb`, background process on **snap**) |
| Systemd | `meshdrive-mcp.service` (non-snap) |
| Path scope | JuiceFS bucket mounts only (see `paths.py`) |
| Credentials | Install-time API token (not a Filebrowser/LDAP user) |

**Snap note:** Install marks MCP ready for **stdio** and starts SSE on **127.0.0.1:9000**. Check with:

```bash
ss -ltn | grep 9000
curl -sS http://127.0.0.1:9000/ready
# log: /var/snap/meshdrive/common/var/log/mcp-sse.log
```

Implementation: `src/meshdrive/mcp/server.py`, `src/meshdrive/mcp/credentials.py`

## MCP API token (security)

On `meshdrive addons install mcp`, MeshDrive creates a high-entropy **API token** (`md_…`):

- Stored as **argon2id hash** in `$ROOT/etc/mcp_credentials.yaml` (mode `0600`)
- Plaintext written once to `$ROOT/var/mcp-token-once.txt` (mode `0600`)
- **Not** a Filebrowser user and **not** created by end users in the TUI
- **stdio** trusts the local process (no HTTP header)
- **SSE/HTTP** requires `Authorization: Bearer <token>` (or `X-MeshDrive-Token`)

```bash
meshdrive mcp credentials status
meshdrive mcp credentials show --consume   # print + delete once-file
meshdrive mcp credentials rotate           # invalidate old token, print new secret
```

OpenFGA (when installed) continues to use subject `agent:mcp` for the default token.

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
| `list_storage_backends` | JuiceFS **buckets** (configured mounts only) |
| `get_storage_stats` | Disk stats for a bucket |
| `read_file` | Read file under a JuiceFS mount |
| `write_file` | Write file under a JuiceFS mount |
| `list_directory` | Omit path → list buckets; else list under a mount |
| `get_file_info` | Metadata for a path under a mount |
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

Automated ASR / FPR measurement: [benchmark/](../benchmark/README.md)
(`run_isolation_bench.py --fixture` → goal **0%** attack success rate).

## OpenFGA

Optional: `meshdrive addons install openfga` — MCP principal `agent:mcp` checked for reader/writer on files and backends.

## SSE with token

```bash
export MESHDRIVE_MCP_TRANSPORT=sse
export MESHDRIVE_MCP_HOST=127.0.0.1
export MESHDRIVE_MCP_PORT=9000
# optional: meshdrive-mcp can also read MESHDRIVE_MCP_TOKEN for local proxies
TOKEN=$(meshdrive mcp credentials show --consume)
curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9000/ready
curl -sS -H "Authorization: Bearer $TOKEN" -N http://127.0.0.1:9000/sse
```

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
