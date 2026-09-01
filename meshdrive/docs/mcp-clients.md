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

“Hermes” (NousResearch hermes-agent) can use **stdio** (simplest) or **SSE**.

### Preferred: stdio (no HTTP 405 issues)

```yaml
# ~/.hermes/config.yaml  (keys may vary slightly by Hermes version)
mcp_servers:
  meshdrive:
    command: /opt/meshdrive/bin/meshdrive-mcp
    args: []
    env:
      MESHDRIVE_ROOT: /opt/meshdrive
      MESHDRIVE_MCP_TRANSPORT: stdio
    enabled: true
```

```yaml
mcp_servers:
  meshdrive:
    command: /opt/data/mcp/meshdrive-mcp
    args: []
    env:
      MESHDRIVE_ROOT: /opt/meshdrive
      MESHDRIVE_MCP_TRANSPORT: stdio
    enabled: true
```

Or JSON-style `mcpServers` if your Hermes build uses that (same command/env as Cursor).

### SSE URL — must set `transport: sse`

MeshDrive SSE is the **legacy MCP SSE** shape:

| Method | Path | Role |
|--------|------|------|
| **GET** | `/sse` | Open event stream |
| **POST** | `/messages/` | Client → server messages |

Hermes **defaults URL servers to Streamable HTTP** (it **POST**s to the URL). That hits `/sse` with POST → **`405 Method Not Allowed`**.

Fix — edit `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  meshdrive:
    url: "http://127.0.0.1:9000/sse"
    transport: sse          # REQUIRED — do not omit
    enabled: true
    connect_timeout: 15
```

Then:

```bash
hermes mcp test meshdrive
# or restart Hermes and check MCP status
```

Verify the server side:

```bash
curl -sS -I http://127.0.0.1:9000/sse    # GET — should not be 405
# POST to /sse is supposed to fail:
curl -sS -X POST http://127.0.0.1:9000/sse -w "%{http_code}\n" -o /dev/null   # 405
```

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

## Release client matrix (how we ship MCP)

Separate **“MCP protocol works”** from **“chat LLM calls tools”**. They are different layers.

| Client | Transport | Release status | Notes |
|--------|-----------|----------------|-------|
| **Cursor** | stdio | **Supported (primary)** | Best end-to-end verification path |
| **Claude Code** | stdio | **Supported** | Same config as Cursor |
| **Hermes** | stdio | **Supported** | Prefer command mode, not URL |
| **Hermes** | SSE URL | Supported if `transport: sse` | Default URL mode = Streamable HTTP → 405 |
| **Open WebUI** | native MCP SSE + Ollama | **Experimental** | Session often OK (`POST /messages/ 200`) but Ollama often never emits `tool_calls` |
| **Open WebUI** | **mcpo** (MCP→OpenAPI) | **Recommended for OWUI** | More reliable than raw MCP SSE with local models |

### Diagnose in 60 seconds

On the MeshDrive machine (or any LAN client):

```bash
# 1) Protocol smoke test (does NOT use an LLM)
sudo systemctl restart meshdrive-mcp
curl -sS http://127.0.0.1:9000/ready
/opt/meshdrive/venv/bin/python /opt/meshdrive/packaging/mcp-smoke-test.py \
  --url http://127.0.0.1:9000/sse

# 2) Watch whether tools are actually invoked
journalctl -u meshdrive-mcp -f
# Expect: ListToolsRequest, then CallToolRequest name=health_check
# If you only see ListToolsRequest during chat → LLM/client never called tools
```

Interpretation:

| Logs during chat | Meaning |
|------------------|---------|
| `ListToolsRequest` only | Client connected; **model did not call tools** |
| `CallToolRequest` + `CallToolResult` | MeshDrive executed the tool; fix client UI/result display |
| No MCP log lines | Client not talking to this server |

### Open WebUI + Ollama (why qwen/gemma “don’t trigger”)

This is a **known Open WebUI/Ollama gap**, not MeshDrive-specific:

1. Set model **Function calling = native** (Workspace → Models)  
2. Raise context (`num_ctx` / `OLLAMA_CONTEXT_LENGTH` to **8192+**; 2048 truncates tool schemas)  
3. Enable the MeshDrive tools on the **chat** (not only in Admin)  
4. Prefer **[mcpo](https://github.com/open-webui/mcpo)** in front of MeshDrive for release demos:

```bash
# Example: OpenAPI bridge for Open WebUI
uvx mcpo --port 8002 -- /opt/meshdrive/bin/meshdrive-mcp
# In Open WebUI add OpenAPI tool server: http://127.0.0.1:8002
```

### Hermes release recommendation

Use **stdio**, not SSE URL:

```yaml
mcp_servers:
  meshdrive:
    command: /opt/meshdrive/bin/meshdrive-mcp
    env:
      MESHDRIVE_ROOT: /opt/meshdrive
      MESHDRIVE_MCP_TRANSPORT: stdio
    enabled: true
```

### Release messaging

- **GA claim:** “Works with Cursor / Claude Code / Hermes (stdio).”  
- **Open WebUI:** “Supported via mcpo OpenAPI bridge; native MCP SSE is experimental with local Ollama.”  
- Ship `packaging/mcp-smoke-test.py` as the CI/release gate (must PASS before tagging).

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
| Hermes `POST /sse` → **405** | Hermes defaulted to Streamable HTTP | Set `transport: sse` on that server in `~/.hermes/config.yaml`, or use **stdio** instead |
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
