# Connect AI clients to MeshDrive MCP

This guide shows how to attach **Cursor**, **Claude Code**, **Open WebUI**, and **Hermes** to MeshDrive’s MCP server so agents can read/write files **only under the MeshDrive root**.

## Prerequisites (once)

```bash
# Free addon
meshdrive addons install mcp
# or
sudo meshdrive-addons install mcp

# Confirm wrapper exists
ls -la /opt/meshdrive/bin/meshdrive-mcp
meshdrive doctor -v
```

Mount at least one storage backend and start Filebrowser if you want a human UI too:

```bash
meshdrive-tui   # Storage → Add → Mount → Start Filebrowser
```

| Transport | When to use | Endpoint / command |
|-----------|-------------|--------------------|
| **stdio** | Cursor, Claude Code, most desktop agents | `/opt/meshdrive/bin/meshdrive-mcp` |
| **SSE** | Open WebUI, HTTP-based tools | `http://127.0.0.1:9000/sse` |

Snap installs: replace `/opt/meshdrive` with `/var/snap/meshdrive/common` and use the snap binary path if wrappers differ.

Shipped example: [`overlay/opt/meshdrive/etc/mcp-client.json`](../overlay/opt/meshdrive/etc/mcp-client.json).

---

## 1. Cursor

Cursor reads MCP config from the project or user settings.

### Option A — project (recommended)

Create or merge **`.cursor/mcp.json`** in your project (or global Cursor MCP settings):

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

### Option B — Cursor Settings UI

1. **Cursor Settings → MCP → Add new MCP server**
2. Type: **command**
3. Command: `/opt/meshdrive/bin/meshdrive-mcp`
4. Env: `MESHDRIVE_ROOT=/opt/meshdrive`

### Verify

1. Restart Cursor or reload MCP servers  
2. In chat, ask: *“Use meshdrive health_check”* or *“list_storage_backends”*  
3. Try: *“list_directory /opt/meshdrive/mnt/primary”*

**Do not** ask the agent to read `/etc/passwd` — MeshDrive must deny it.

---

## 2. Claude Code (Claude CLI)

Claude Code uses an MCP config file (project or user).

### Project file: `.mcp.json`

In the repo you work in:

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

### CLI (if available on your Claude Code build)

```bash
claude mcp add meshdrive --env MESHDRIVE_ROOT=/opt/meshdrive -- /opt/meshdrive/bin/meshdrive-mcp
```

### Verify

```bash
claude mcp list
# then in a Claude Code session:
# "Call meshdrive health_check and list_storage_backends"
```

---

## 3. Open WebUI

Open WebUI typically talks to MCP over **HTTP/SSE**, not stdio.

### Start MeshDrive MCP in SSE mode

```bash
# one-shot (foreground)
MESHDRIVE_ROOT=/opt/meshdrive MESHDRIVE_MCP_TRANSPORT=sse MESHDRIVE_MCP_HOST=127.0.0.1 MESHDRIVE_MCP_PORT=9000 \
  /opt/meshdrive/bin/meshdrive-mcp

# or systemd unit (if configured for SSE — default unit may use stdio;
# override Environment= in a drop-in):
sudo systemctl edit meshdrive-mcp.service
```

Drop-in example:

```ini
[Service]
Environment=MESHDRIVE_ROOT=/opt/meshdrive
Environment=MESHDRIVE_MCP_TRANSPORT=sse
Environment=MESHDRIVE_MCP_HOST=127.0.0.1
Environment=MESHDRIVE_MCP_PORT=9000
```

Then:

```bash
sudo systemctl restart meshdrive-mcp
curl -sS -I http://127.0.0.1:9000/sse
```

### Configure Open WebUI

UI labels vary by Open WebUI version. Typical path:

1. **Admin Panel → Settings → Tools** (or **Connections → MCP**)
2. Add MCP / tool server:
   - **URL:** `http://127.0.0.1:9000/sse`
   - **Type:** MCP SSE (if offered)
3. Enable the **meshdrive** tools for the model/chat
4. Ensure Open WebUI runs on the **same host** (loopback only) or reverse-proxy with auth — do **not** expose `:9000` to the internet

If your Open WebUI build only supports OpenAPI tools (not MCP SSE yet), use a small MCP↔OpenAPI bridge, or run agents that support stdio MCP on the same machine and point them at MeshDrive instead.

### Verify in chat

Ask the model: *“Use the meshdrive MCP tool health_check”* and *“list files under /opt/meshdrive/mnt/primary”*.

---

## 4. Hermes

“Hermes” usually means an MCP-capable agent runtime (e.g. Hermes agent / CLI that loads MCP servers). Use the same **stdio** pattern as Cursor.

### Config sketch

Wherever Hermes reads MCP servers (check its docs for `mcpServers` / `mcp.json`):

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

### If Hermes only supports SSE

Point it at `http://127.0.0.1:9000/sse` with MCP SSE mode enabled (same as Open WebUI section).

### Verify

From Hermes, invoke `health_check` and `list_storage_backends`. Confirm denied paths outside `$MESHDRIVE_ROOT`.

---

## Quick reference — env vars

| Variable | Default | Meaning |
|----------|---------|---------|
| `MESHDRIVE_ROOT` | `/opt/meshdrive` or `$SNAP_COMMON` | Install root / isolation base |
| `MESHDRIVE_MCP_TRANSPORT` | `stdio` | `stdio` or `sse` |
| `MESHDRIVE_MCP_HOST` | `127.0.0.1` | SSE bind address |
| `MESHDRIVE_MCP_PORT` | `9000` | SSE port |

---

## What tools the model can call

| Tool | Purpose |
|------|---------|
| `health_check` | MCP + component health |
| `list_storage_backends` | Backends and mounts |
| `get_storage_stats` | Usage for a backend |
| `list_directory` | List under allowed path |
| `get_file_info` | Stat a file |
| `read_file` | Read file content |
| `write_file` | Write file content |

Blocked: user admin / system config tools — see [mcp.md](mcp.md).

---

## Security checklist

- [ ] MCP only on **127.0.0.1** (stdio or SSE loopback)  
- [ ] `isolation.allowed_paths` stays under MeshDrive root  
- [ ] Do not publish port 9000 publicly  
- [ ] Prefer OpenFGA addon for finer read/write grants (`meshdrive addons install openfga`)  
- [ ] Mount volumes before expecting files under `$ROOT/mnt/<name>`  

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Client can’t start MCP | `ls /opt/meshdrive/bin/meshdrive-mcp`; reinstall `meshdrive addons install mcp` |
| Tools missing in Cursor | Reload MCP; check JSON syntax in `.cursor/mcp.json` |
| Open WebUI can’t connect | Ensure `MESHDRIVE_MCP_TRANSPORT=sse` and `curl http://127.0.0.1:9000/sse` |
| Permission denied on path | Path outside `isolation.allowed_paths`; use `$ROOT/mnt/...` |
| Empty directories | Mount backend in TUI first |

Logs:

```bash
journalctl -u meshdrive-mcp -b --no-pager
```

---

## Related

- [mcp.md](mcp.md) — protocol, tools, isolation  
- [addons.md](addons.md) — install MCP  
- [storage.md](storage.md) — mounts Filebrowser sees  
