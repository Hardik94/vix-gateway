# Storage

How MeshDrive 2.0 manages local (and paid remote) storage with JuiceFS.

## Pinned binaries

| Component | Version |
|-----------|---------|
| JuiceFS | **v1.4.1** |
| Filebrowser | **v2.63.23** |

Fetched by [`packaging/fetch-binaries.sh`](../packaging/fetch-binaries.sh) into `$ROOT/bin/`.  
Upgrade process: [binaries.md](binaries.md).

---

## Local backend (free tier)

Each storage backend is an independent JuiceFS volume:

| Property | Default location |
|----------|------------------|
| Metadata | `$ROOT/var/meta/<name>.db` (SQLite) |
| Object data | `$ROOT/var/data/<name>/` (`file://`) |
| Cache | `$ROOT/var/cache/<name>/` |
| Mount point | `$ROOT/mnt/<name>/` |
| Capacity | Optional JuiceFS `--capacity` in **GiB** — hard volume quota; this is what `df` shows as Size |

### Add storage (TUI)

1. Open **Storage** tab
2. **Add backend** — name, optional data path, optional **size (GB)**
3. Agent runs `juicefs format --capacity N` when size is set (N GiB)
4. **Mount** — starts `meshdrive-mount@<name>.service` (also re-applies capacity via `juicefs config`)

Leave size empty for **unlimited** (JuiceFS then advertises **~1.0P** in `df` — that is normal).

When size is set, terminal should match:

```bash
df -h /opt/meshdrive/mnt/primary
# Filesystem      Size  Used Avail Use% Mounted on
# JuiceFS:…       100G  …     …     …  /opt/meshdrive/mnt/primary
```

### Existing volume still shows 1.0P

If the TUI already has a size but `df` shows `1.0P`, capacity was never written into JuiceFS metadata. Remount after updating the agent, or set it once:

```bash
# Replace NAME and N with backend name and GiB from the TUI
sudo systemctl stop meshdrive-mount@NAME
/opt/meshdrive/bin/juicefs config sqlite3:///opt/meshdrive/var/meta/NAME.db --capacity N
sudo systemctl start meshdrive-mount@NAME
df -h /opt/meshdrive/mnt/NAME
```

### Delete storage (TUI)

1. Open **Storage** tab
2. Select the backend row
3. **Unmount** first if it is mounted (delete will unmount automatically, but unmounting first avoids busy-mount errors)
4. Click **Delete storage**
5. Confirm — optionally check **Also delete data files** to remove metadata, object data, cache, and the mount directory

Without **delete data files**, the backend entry is removed from `config.yaml` but files on disk are kept (you can re-add the backend later using the same paths).

### Delete storage (API)

```bash
# Remove config only (keep files on disk)
curl -sS -X DELETE http://127.0.0.1:12700/storage/primary

# Unmount, remove config, and delete local metadata/data/cache
curl -sS -X DELETE 'http://127.0.0.1:12700/storage/primary?wipe_data=1'
```

The agent stops and disables `meshdrive-mount@<name>.service`, unmounts if needed, removes the backend from `config.yaml`, and drops the name from user `storage_access` lists.

### Add storage (API)

```bash
curl -sS -X POST http://127.0.0.1:12700/storage/add \
  -H 'Content-Type: application/json' \
  -d '{"name":"primary","data_path":"/mnt/bigdisk/meshdrive","capacity_gb":100}'

curl -sS -X POST http://127.0.0.1:12700/storage/mount \
  -H 'Content-Type: application/json' \
  -d '{"name":"primary"}'
```

`capacity_gb` accepts `100`, `"100"`, or `"100G"`. Omit or `0` for unlimited.

### Manual juicefs (debugging)

```bash
/opt/meshdrive/bin/juicefs format \
  --storage file \
  --bucket /opt/meshdrive/var/data/primary \
  --capacity 100 \
  sqlite3:///opt/meshdrive/var/meta/primary.db primary

/opt/meshdrive/bin/juicefs mount \
  sqlite3:///opt/meshdrive/var/meta/primary.db \
  /opt/meshdrive/mnt/primary \
  -d --cache-dir /opt/meshdrive/var/cache/primary
```

Production installs use the systemd template unit instead of manual mount.

## Multiple storages + Filebrowser

**Yes — one Filebrowser instance serves all backends.**

- Each backend mounts at `$ROOT/mnt/<name>/` (e.g. `primary`, `backup`)
- Filebrowser root is **`$ROOT/mnt`** (not a single volume)
- In the web UI you see folders: `primary/`, `backup/`, …
- URL remains `http://127.0.0.1:8080` (loopback only)
- Users/auth are shared (same Filebrowser DB)

You still **mount each backend** separately in the TUI (or API). Unmounted folders may appear empty until the FUSE mount is up.

```text
Filebrowser root = /opt/meshdrive/mnt/
├── primary/     ← juicefs mount (backend "primary")
└── projects/    ← juicefs mount (backend "projects")
```

## FUSE and permissions

Filebrowser runs as user `meshdrive`. JuiceFS mounts use FUSE **`allow_other`** so the web UI can read files:

- `/etc/fuse.conf` must contain `user_allow_other` (installer uncomments if needed)
- `meshdrive` user must exist and be in correct groups

## Filebrowser integration

When storage is added or mounted:

1. Agent sets `filebrowser.root` to `$ROOT/mnt`
2. Regenerates `etc/filebrowser.json`
3. Start Filebrowser from TUI or `POST /filebrowser/start`

## Remote backend (paid tier)

After [WireGuard](wireguard.md) and [cluster configure](paid-cluster.md):

```yaml
- name: remote
  type: juicefs-remote
  metadata_url: tikv://10.200.22.3:2379/volume
  object_endpoint: http://10.200.22.4:9000
  mount_point: /opt/meshdrive/mnt/remote
```

Remote endpoints must be reachable **inside the WireGuard overlay**.

Local sqlite backend remains; remote is an **additional** mount under the same Filebrowser root — no automatic sync.

## MCP access

MCP tools operate on paths under `isolation.allowed_paths`. Typically files are accessed via `$ROOT/mnt/<backend>/…`.

See [mcp.md](mcp.md).

## Troubleshooting

See [troubleshooting.md](troubleshooting.md#storage--juicefs).

```bash
mountpoint /opt/meshdrive/mnt/primary
/opt/meshdrive/bin/juicefs status /opt/meshdrive/mnt/primary
journalctl -u meshdrive-mount@primary -b
```
