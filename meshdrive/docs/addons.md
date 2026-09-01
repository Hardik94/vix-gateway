# Add-ons

Add-ons are optional modules installed into the MeshDrive root. They do not modify the user's home directory or system Python.

Install via CLI or TUI **Add-ons** tab:

```bash
meshdrive addons list
meshdrive addons install <name>
```

Progress and status are stored in `config.yaml` and `var/state.json`.

---

## Summary table

| Add-on | Tier | CLI name | Loopback bind | Data location |
|--------|------|----------|---------------|---------------|
| MCP | Free | `mcp` | stdio / `127.0.0.1:9000` | N/A (uses mount paths) |
| OpenFGA | Free | `openfga` | `127.0.0.1:8081` | `var/openfga/openfga.db` |
| OpenTelemetry | Free | `otel` | OTLP loopback | `var/telemetry/` |
| WireGuard | Paid | `wireguard` | — (host `wg0`) | templates in `share/wireguard/` |
| VIX gateway | Paid | `vix-gateway` | `127.0.0.1:9443` | serves `$ROOT/mnt/primary` |
| VIX FUSE | Paid | `vix-fuse` | — | `etc/vix-fuse-backends.json` |
| SSSD/LDAP | Paid | `sssd-ldap` | — | `/etc/sssd/sssd.conf` |
| Remote cluster | Paid | `remote-cluster` | — | `etc/cluster.yaml` + `config.yaml` |

Paid add-ons require [license activation](licensing.md) first. The TUI shows a lock icon until the license tier is `paid`.

---

## Free add-ons

### MCP (`mcp`)

AI tool server with **path isolation** — file operations only under `isolation.allowed_paths`.

**Install:**

```bash
meshdrive addons install mcp
sudo systemctl status meshdrive-mcp
```

Installs Python `[mcp]` extra into the MeshDrive venv (**`mcp>=1.2.0,<2`** — SDK 2.x breaks `list_tools`), writes `bin/meshdrive-mcp`, enables `meshdrive-mcp.service`.

If you see `Server object has no attribute list_tools`:

```bash
/opt/meshdrive/venv/bin/pip install --upgrade 'mcp>=1.2.0,<2'
meshdrive addons install mcp
```


**Integration:** see [mcp.md](mcp.md).

**Not exposed via MCP:** user create/delete, system config, auth administration.

### OpenFGA (`openfga`)

Fine-grained authorization for MCP file operations.

**Install:**

```bash
meshdrive addons install openfga
```

Downloads pinned OpenFGA binary, runs **`openfga migrate`** (sqlite schema), starts `meshdrive-openfga.service`, bootstraps store + model from `etc/openfga-model.json`, grants default tuples for storage backends.

If status stays at 90% / “not reachable”:

```bash
sudo systemctl status meshdrive-openfga --no-pager
journalctl -u meshdrive-openfga -b --no-pager | tail -40
# Re-install after updating package:
meshdrive addons install openfga
curl -sS http://127.0.0.1:8081/healthz
```

When running, MCP write/read calls are checked as `agent:mcp` against `storage_backend:<name>` and `file:<path>` objects.

### OpenTelemetry (`otel`)

Local-only telemetry collector. Writes to files under `var/telemetry/` — **no cloud export by default**.

**Install:**

```bash
meshdrive addons install otel
```

Downloads `otelcol-contrib`, installs `meshdrive-otel.service` with config from `etc/otel-collector.yaml`.

Enable collection in TUI **Settings** → telemetry checkbox.

---

## Paid add-ons

Activate license first:

```bash
meshdrive license activate --token "$MESHDRIVE_TOKEN"
```

### WireGuard (`wireguard`)

Stages hub-spoke client templates; does not start a tunnel by itself.

```bash
meshdrive addons install wireguard
sudo meshdrive wireguard bootstrap
sudo meshdrive wireguard apply --file ./wg0.conf
sudo meshdrive wireguard up
```

See [wireguard.md](wireguard.md).

### VIX gateway (`vix-gateway`)

QUIC/HTTP3 gateway over the local JuiceFS mount. Binary built from `vix_package/cpp_gateway` via `packaging/build-vix.sh`.

```bash
meshdrive addons install vix-gateway
curl -k https://127.0.0.1:9443/health
```

Unit: `meshdrive-vix-gateway.service`. Config: `etc/vix-gateway.env`.

### VIX FUSE (`vix-fuse`)

Mounts remote storage via gateway IPs **inside WireGuard** (see `etc/vix-fuse-backends.json`).

Requires WireGuard up and preferably `vix-gateway` installed locally or reachable on the overlay.

```bash
meshdrive addons install vix-fuse
```

### SSSD/LDAP (`sssd-ldap`)

Installs OS packages `sssd`, `sssd-ldap`, `ldap-utils`. LDAP connection is configured by cluster wizard.

```bash
sudo meshdrive addons install sssd-ldap
```

### Remote cluster (`remote-cluster`)

Enables the cluster configuration wizard; pairs with `meshdrive cluster configure`.

```bash
sudo meshdrive addons install remote-cluster
sudo meshdrive cluster configure --ldap-url ldap://ldap.internal.example ...
```

See [paid-cluster.md](paid-cluster.md).

---

## Systemd units (add-ons)

| Unit | Add-on |
|------|--------|
| `meshdrive-mcp.service` | MCP |
| `meshdrive-openfga.service` | OpenFGA |
| `meshdrive-otel.service` | OTEL |
| `meshdrive-vix-gateway.service` | VIX gateway |
| `meshdrive-vix-fuse.service` | VIX FUSE |

Check logs:

```bash
journalctl -u meshdrive-mcp -b --no-pager
journalctl -u meshdrive-openfga -b --no-pager
```

---

## Uninstall

```bash
meshdrive addons uninstall mcp
sudo systemctl stop meshdrive-mcp
```

Paid add-ons may leave host config (`/etc/wireguard/`, `/etc/sssd/`) — remove manually if decommissioning.

---

## Implementation

Addon registry and installers: `src/meshdrive/addons/install.py`.

Each installer:

1. Checks license (paid only)
2. Downloads binaries or pip packages into `$ROOT`
3. Copies systemd unit to `/etc/systemd/system/`
4. Updates `config.yaml` status/progress
5. Enables systemd unit where applicable
