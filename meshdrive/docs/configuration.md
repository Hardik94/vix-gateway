# Configuration

MeshDrive configuration is YAML under `$ROOT/etc/`. The install root `$ROOT` is `/opt/meshdrive`, `$SNAP_COMMON`, or `$MESHDRIVE_ROOT`.

## Files

| File | Created by | Description |
|------|------------|-------------|
| `config.yaml` | Installer overlay | Main settings |
| `auth.yaml` | Installer overlay | Local users (argon2id) |
| `license.yaml` | `meshdrive license activate` | Paid tier state |
| `cluster.yaml` | `meshdrive cluster configure` | Remote LDAP/JuiceFS |
| `filebrowser.json` | Agent (auto) | Filebrowser runtime config |
| `mcp-client.json` | Overlay | Example MCP editor config |
| `openfga-model.json` | Overlay | OpenFGA authorization model |
| `otel-collector.yaml` | Overlay | Local-only OTEL pipeline |
| `vix-gateway.env` | Overlay | VIX gateway options |
| `vix-fuse-backends.json` | Overlay | Remote FUSE backend list |

All secret-bearing files should be mode `600`.

---

## `config.yaml`

Shipped from `overlay/opt/meshdrive/etc/config.yaml`. On `.deb` installs it is marked `type: config` so package upgrades do not overwrite local edits.

### Top-level structure

```yaml
meshdrive:
  version: "2.0.0"
  mode: local              # local | hybrid (after paid cluster)

  storage:
    backends: []           # populated by TUI / API

  filebrowser:
    enabled: true
    address: "127.0.0.1"
    port: 8080
    root: /opt/meshdrive/mnt
    database: /opt/meshdrive/var/filebrowser.db

  auth:
    backend: local         # local | sssd (after cluster configure)
    path: /opt/meshdrive/etc/auth.yaml
    session_timeout: 3600

  mcp:
    enabled: false
    status: not_installed  # not_installed | installing | ready | error
    host: "127.0.0.1"
    port: 9000
    progress: 0

  openfga:
    enabled: false
    status: not_installed
    http: "127.0.0.1:8081"
    progress: 0

  telemetry:
    enabled: false
    status: not_installed
    privacy_level: anonymized
    send_interval: 86400
    mode: local_file
    progress: 0

  wireguard:
    enabled: false
    status: not_installed
    progress: 0

  vix_gateway:
    enabled: false
    status: not_installed

  vix_fuse:
    enabled: false
    status: not_installed

  sssd:
    enabled: false
    status: not_installed

  remote_cluster:
    enabled: false
    status: not_installed

  isolation:
    root_dir: /opt/meshdrive
    user: meshdrive
    group: meshdrive
    allowed_paths:
      - /opt/meshdrive
```

### Storage backend entry

Created when you add storage in the TUI:

```yaml
- name: primary
  type: juicefs
  metadata_url: sqlite3:///opt/meshdrive/var/meta/primary.db
  data_path: /opt/meshdrive/var/data/primary
  cache_dir: /opt/meshdrive/var/cache/primary
  mount_point: /opt/meshdrive/mnt/primary
  formatted: true
```

Remote (paid) backend example after `cluster configure`:

```yaml
- name: remote
  type: juicefs-remote
  metadata_url: tikv://10.200.22.3:2379/volume
  object_endpoint: http://10.200.22.4:9000
  mount_point: /opt/meshdrive/mnt/remote
  status: configured
```

Local sqlite remains the default; paid remote backends are **additional**, not auto-synced.

---

## `license.yaml`

Written by `meshdrive license activate`. Raw tokens are **never** stored — only a hash.

```yaml
tier: paid
token_hash: "<sha256-hmac>"
activated_at: "2026-08-24T12:00:00+00:00"
features:
  - wireguard
  - vix_gateway
  - vix_fuse
  - sssd
  - remote_cluster
```

See [licensing.md](licensing.md).

---

## `cluster.yaml`

Written by `meshdrive cluster configure`:

```yaml
ldap:
  url: ldap://ldap.internal.example
  base: dc=meshdrive,dc=local
  bind_dn: cn=admin,dc=meshdrive,dc=local
remote_backend:
  name: remote
  metadata_url: tikv://10.200.22.3:2379/volume
  object_endpoint: http://10.200.22.4:9000
```

LDAP URL must resolve to an address **inside the WireGuard overlay**, not a public IP.

---

## `auth.yaml`

Local users managed by the TUI/agent:

```yaml
users:
  - username: admin
    password_hash: $argon2id$...
    admin: true
    groups: [meshdrive]
    storage_access: [primary]
```

---

## `var/state.json`

Runtime snapshot written by the agent (not hand-edited). Used by the TUI dashboard for live status: mounts, binary versions, addon progress, user count.

---

## Path resolution

`src/meshdrive/constants.py` resolves `$ROOT`:

1. `MESHDRIVE_ROOT` if set
2. else `SNAP_COMMON` if running under snap
3. else `/opt/meshdrive`

MCP path checks use `isolation.allowed_paths` via `src/meshdrive/paths.py`.

---

## Editor / MCP client setup

Copy `etc/mcp-client.json` into your editor MCP configuration. It sets `MESHDRIVE_ROOT` and points at the MCP server command — no secrets included.

Example snippet:

```json
{
  "mcpServers": {
    "meshdrive": {
      "command": "/opt/meshdrive/bin/meshdrive-mcp",
      "env": {
        "MESHDRIVE_ROOT": "/opt/meshdrive"
      }
    }
  }
}
```

Adjust paths for snap (`/var/snap/meshdrive/common`).
