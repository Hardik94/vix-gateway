# CLI reference

MeshDrive exposes a unified CLI plus legacy entry points for compatibility.

## Entry points

| Command | Purpose |
|---------|---------|
| `meshdrive` | Unified CLI (recommended) |
| `meshdrive-agent` | Run agent daemon (normally via systemd) |
| `meshdrive-tui` | Textual TUI |
| `meshdrive-addons` | Legacy addon installer (prefer `meshdrive addons`) |
| `meshdrive-mount` | Low-level mount helper |
| `meshdrive-mcp` | MCP server (stdio/SSE) |

All production wrappers live under `$ROOT/bin/` and are symlinked to `/usr/local/bin/` on `.deb` installs.

---

## `meshdrive`

```
meshdrive [--version]
meshdrive status
meshdrive doctor [-v] [--json]
meshdrive tui
meshdrive license activate --token TOKEN
meshdrive license status
meshdrive addons list
meshdrive addons install NAME [NAME ...]
meshdrive addons uninstall NAME
meshdrive wireguard bootstrap
meshdrive wireguard apply --file PATH [--v4 ADDR] [--v6 ADDR]
meshdrive wireguard up | down | status
meshdrive cluster configure --ldap-url URL [options]
meshdrive cluster status
```

### `meshdrive status`

Prints version, license tier, install root, storage backends, and agent reachability.

### `meshdrive doctor`

Diagnostics for a broken install:

- CLI binaries on `PATH`
- JuiceFS / Filebrowser / VIX binaries
- Python venv
- `config.yaml` presence
- License tier
- `meshdrive-agent.service` state
- Snap environment (`SNAP`, `SNAP_COMMON`) when applicable

Exit code `1` if issues are found. Use `--json` for machine-readable output.

**Run this first** after any install if commands are missing or the TUI cannot reach the agent.

### `meshdrive tui`

Launches the Textual UI (same as `meshdrive-tui`).

### `meshdrive license`

See [licensing.md](licensing.md).

```bash
meshdrive license activate --token "MESHDRIVE_…"
meshdrive license status
```

### `meshdrive addons`

```bash
meshdrive addons list
meshdrive addons install mcp openfga otel          # free
meshdrive addons install wireguard vix-gateway     # paid, after license
meshdrive addons uninstall mcp
```

Legacy equivalent:

```bash
meshdrive-addons list
meshdrive-addons install mcp
meshdrive-addons install all    # free addons only
meshdrive-addons install paid   # all paid addons (requires license)
```

### `meshdrive wireguard`

Paid tier. Requires root for `bootstrap`, `apply`, `up`, `down`.

```bash
sudo meshdrive wireguard bootstrap
sudo meshdrive wireguard apply --file ./wg0.conf
sudo meshdrive wireguard up
meshdrive wireguard status
sudo meshdrive wireguard down
```

See [wireguard.md](wireguard.md).

### `meshdrive cluster`

Paid tier. Configures SSSD/LDAP and optional remote JuiceFS backend.

```bash
sudo meshdrive cluster configure \
  --ldap-url ldap://ldap.internal.example \
  --ldap-base dc=meshdrive,dc=local \
  --bind-dn "cn=admin,dc=meshdrive,dc=local" \
  --bind-password 'secret' \
  --metadata-url tikv://10.200.22.3:2379/volume \
  --object-endpoint http://10.200.22.4:9000 \
  --backend-name remote

meshdrive cluster status
```

See [paid-cluster.md](paid-cluster.md).

---

## Environment variables

| Variable | Effect |
|----------|--------|
| `MESHDRIVE_ROOT` | Override install root (default `/opt/meshdrive` or `$SNAP_COMMON`) |
| `MESHDRIVE_CONTROL_HOST` | Agent API bind address (default `127.0.0.1`) |
| `MESHDRIVE_CONTROL_PORT` | Agent API port (default `12700`) |
| `MESHDRIVE_LICENSE_SECRET` | HMAC secret for production token validation |
| `MESHDRIVE_LICENSE_STRICT=1` | Reject unknown license tokens (disable dev tokens) |
| `SNAP` / `SNAP_COMMON` | Set automatically under snap |

---

## Examples

**Post-install smoke test**

```bash
meshdrive doctor
meshdrive status
curl -sS http://127.0.0.1:12700/health | jq .
```

**Install free addons**

```bash
meshdrive addons install mcp
sudo meshdrive-addons install openfga otel
meshdrive addons list
```

**Activate paid features**

```bash
meshdrive license activate --token "$MESHDRIVE_TOKEN"
meshdrive license status
meshdrive addons install wireguard
```
