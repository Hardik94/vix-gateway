# Changelog

## 2.3.10 — MCP credentials Permission denied / 500 with Bearer token

### Bug fixes

- **`meshdrive-mcp.service`**: include `/opt/meshdrive/etc` in `ReadWritePaths` (was read-only; argon2 rehash + token updates failed with `PermissionError`).
- **Credentials ownership**: after `sudo` MCP install, `mcp_credentials.yaml` is chowned to `meshdrive:meshdrive` mode `0600`.
- **SSE middleware**: unreadable credentials → **503** with fix hint instead of opaque **500**; rehash write failures no longer fail a valid token.

### Package

- Version **2.3.10**.

## 2.3.9 — Fix Filebrowser lstat …/mnt/bucket/opt

### Filebrowser

- Keep server ``--root`` at ``$ROOT/mnt`` (not the bucket mount).
- Normalize user ``--scope`` to a path **relative** to that root (e.g. ``fifth``) so Filebrowser does not join ``root + /opt/...`` into ``…/fifth/opt``.
- Single-bucket admins still get scope = that mount (relative) for a correct usage bar.

### Version

- Package version **2.3.9**.

## 2.3.8 — Filebrowser usage bar = JuiceFS capacity

### Filebrowser / capacity

- With a **single** mounted bucket, Filebrowser ``--root`` is that mount (not ``$ROOT/mnt``), so the UI progress bar matches JuiceFS ``--capacity``.
- Single-bucket non-admin scopes point at the mount directly (same reason).
- ``juicefs config --capacity`` remounts a live volume so ``df`` / Filebrowser pick up the size.

### Version

- Package version **2.3.8**.

## 2.3.7 — Deb Filebrowser root + MCP :9000

### Deb / Filebrowser

- Push ``--root $ROOT/mnt`` into Filebrowser **Bolt DB** (JSON alone was ignored).
- After storage create/mount: stop FB → sync root + rebuild portals/scopes → restart so UI shows JuiceFS buckets.

### Deb / MCP SSE

- Resolve ``meshdrive-mcp.service`` from ``/opt/meshdrive/systemd`` (was looking at a non-existent overlay path under site-packages).
- Install/enable the unit; fall back to SSE process if enable fails; ship unit via nfpm.
- ``use_host_units`` only disables for a **running** snap — leftover ``/snap/meshdrive`` no longer breaks deb systemd.

### Version

- Package version **2.3.7**.

## 2.3.6 — MCP SSE listens on :9000 under snap

### MCP / snap

- ``addons install mcp`` starts an SSE process on **127.0.0.1:9000** (snap has no ``meshdrive-mcp.service``).
- Status/health report the real SSE URL when the port is open; stdio remains ``snap run meshdrive.mcp``.

### Version

- Package version **2.3.6**.

## 2.3.5 — Snap JuiceFS mount (host fusermount)

### Snap / FUSE

- Prefer **host** `/usr/bin/fusermount3` over snap-staged copy (setuid); wrappers put `/usr/bin` before `$SNAP/usr/bin`.
- Stop staging ``fuse3`` in the snap; host ``fuse3`` is required.
- Auto-enable ``user_allow_other`` in ``/etc/fuse.conf`` when agent runs as root; clearer mount errors + ``var/log/juicefs-mount.log``.

### Version

- Package version **2.3.5**.

## 2.3.4 — Storage create PermissionError after sudo OpenFGA

### Storage / snap

- Map legacy ``/opt/meshdrive/...`` data paths onto ``$ROOT`` (``$SNAP_COMMON`` on snap).
- Skip chown-to-``meshdrive`` under snap (sudo addon install was leaving unwritable trees).
- Clearer errors + ``ensure_writable_data_tree`` before format; TUI data-path placeholder no longer suggests ``/opt/meshdrive``.

### Version

- Package version **2.3.4**.

## 2.3.3 — OpenFGA tar EPERM under snap

### Snap / OpenFGA

- Fetch extracts **only** the `openfga` binary (skips `assets/migrations/*.sql`) — full unpack hit `operation not permitted` under snap.
- Snap build ships `openfga` next to juicefs/filebrowser; install reuses it when present.

### Version

- Package version **2.3.3**.

## 2.3.2 — Snap addons + Filebrowser URL

### Snap / addons

- **OpenFGA** on snap starts as a background process (no `meshdrive-openfga.service`) so install no longer sticks at 90%.
- **MCP** install is snap-aware: uses relocatable `python-packages` (no venv), ships `[mcp]` in the snap build, writes a working `bin/meshdrive-mcp` wrapper.
- Overlay models / packaging resolved from `$SNAP/opt/meshdrive` when needed.

### Filebrowser

- Display URL falls back to `http://127.0.0.1:8080` when `meshdrive.local` does not resolve (avoids browser “can't be reached” after login).

### Version

- Package version **2.3.2**.

## 2.3.1 — TUI storage create / agent HTTP resilience

### Agent / TUI

- Agent always returns JSON on API errors (no silent TCP close → `RemoteDisconnected`).
- Storage create validates JuiceFS + dirs and surfaces format/timeout errors.
- TUI client maps `RemoteDisconnected` to a clear agent/journal hint; longer timeout for format/mount.

### Version

- Package version **2.3.1**.

## 2.3.0 — MCP API tokens (security)

### MCP credentials

- Install-time **API token** (`md_…`) created by `meshdrive addons install mcp` — not a Filebrowser or LDAP user.
- Argon2id hash in `$ROOT/etc/mcp_credentials.yaml` (0600); plaintext only in `$ROOT/var/mcp-token-once.txt` until consumed.
- CLI: `meshdrive mcp credentials status|show|rotate|ensure`.
- **SSE/HTTP** MCP requires `Authorization: Bearer <token>` (or `X-MeshDrive-Token`).
- **stdio** remains local-process trust (no HTTP auth).
- Default OpenFGA subject remains `agent:mcp`.

### Version

- Package version **2.3.0** (security enhancement, not a patch).

## 2.2.5 — agent bind EACCES (snap)

### Snap / agent

- Bind control API on **`127.0.0.1`** only (`localhost` / `::1` remapped) to avoid errno 13 under snap.
- Wrappers set `MESHDRIVE_CONTROL_HOST=127.0.0.1`.
- Apps declare `network` + `network-bind` plugs (needed if confinement is strict).
- Clearer journal hint when bind fails: reinstall with `--classic`.

### Version

- Package version **2.2.5**.

## 2.2.4 — agent start harden + multi-arch snap

### Snap / agent

- Data root prefers **`$SNAP_COMMON`** (not `/opt/meshdrive` layout) so a leftover host `/opt/meshdrive` from `.deb` cannot break the agent.
- Agent no longer exits if `prepare_runtime` fails; still binds `:12700` when possible.
- Install/configure hooks seed `$SNAP_COMMON` and `snapctl start --enable meshdrive.agent`.
- `architectures`: amd64 + arm64 in the same `snapcraft.yaml`.
- `fetch-binaries.sh` downloads JuiceFS/Filebrowser (and addons) for amd64 and arm64.

### Version

- Package version **2.2.4**.

## 2.2.3 — snap filebrowser.db / log paths

### Snap paths

- Data root under snap is **`/opt/meshdrive`** (layout → `$SNAP_COMMON`), not `$SNAP` or `$SNAP_DATA`.
- Agent `prepare_runtime()` rewrites `config.yaml` / `filebrowser.json` database+root+logs onto that root and inits `var/filebrowser.db` if missing.
- Wrappers set `HOME` / `XDG_*` under `$MESHDRIVE_ROOT/var` so Filebrowser cannot fall back into `/snap/meshdrive/<rev>/…`.
- Install/configure hooks create DB under the layout path.

### Version

- Package version **2.2.3**.

## 2.2.2 — snap agent lifecycle

### Snap / agent

- Install/configure hooks seed `$SNAP_COMMON/etc` and `snapctl start --enable meshdrive.agent`.
- Agent app: `install-mode: enable`, `restart-condition: always`.
- Under snap, mount/Filebrowser use in-process management (host `meshdrive-*.service` units are not installed).
- Doctor checks `http://127.0.0.1:12700/health`; TUI shows snap start hint.
- CLI: `meshdrive agent status|start|stop|restart`.

### Version

- Package version **2.2.2**.

## 2.2.1 — snap doctor / binary paths

### Snap / doctor

- Binary lookup prefers `$SNAP/opt/meshdrive/bin` (JuiceFS, Filebrowser); data root remains `$SNAP_COMMON`.
- Doctor treats snap apps / `$SNAP/bin` wrappers as CLI present; checks `python-packages` instead of `venv` under snap.
- Snap build **fails** if `fetch-binaries.sh` does not produce juicefs + filebrowser (no more silent `|| true`).
- Wrappers prepend `$SNAP/opt/meshdrive/bin` to `PATH`; apps `addons` and `mcp` added.

### Version

- Package version **2.2.1**.

## 2.2.0 — user ↔ bucket ACL + TUI assign

### Access control

- Many-to-many **user ↔ JuiceFS bucket** via `storage_access` in `auth.yaml`.
- Filebrowser **portals** under `$ROOT/var/portals/<user>/` (symlinks to allowed mounts).
- Agent APIs: `POST /users/{u}/storage_access`, `GET|POST /storage/{name}/users`.
- Docs: [`docs/storage-acl.md`](docs/storage-acl.md).

### TUI

- **Users → Assign buckets** (multi-checkbox).
- **Storage → Assign users** (multi-checkbox).
- Add user can select buckets at create time.
- Storage table shows member usernames; users table column renamed to Buckets.

### Version

- Package version **2.2.0**.

### Snap build (fix)

- `override-build` uses `$CRAFT_PART_SRC` for `overlay/`, `src/`, `packaging/` (LXD build CWD is not the project tree).
- Part `source: .` (project root). Do **not** use `source: ..` when `snapcraft.yaml` is under `snap/` — that pulls the monorepo parent and omits `overlay/`.
- Vendored fallback configs in `snap/local/opt/meshdrive/` when LXD omits untracked `overlay/`.
- `.craftignore` — do not exclude `overlay/`, `src/`, `packaging/`, `snap/local/`.

## 2.1.0 — identity, MCP buckets, license HTTPS scaffolding

### Snap

- Fixed classic snap wrappers that baked the **build-host** path
  (`…/parts/meshdrive/install/opt/meshdrive/venv/bin/meshdrive`) into `meshdrive-wrapper`.
  Wrappers now use `$SNAP` + `python -m meshdrive.*` and rewrite venv shebangs.

### MCP

- `list_storage_backends` returns JuiceFS **buckets** (configured mounts) with `bucket`, mount, and usage fields.
- `list_directory` with no path (or install root / `mnt`) lists **buckets only**, not the full `/opt/meshdrive` tree.
- `read_file` / `write_file` / `get_file_info` / path listing require paths under a JuiceFS mount (`assert_storage_path`).

### Identity (free → paid)

- Documented **hybrid** upgrade: keep local usernames; allocate LDAP `uidNumber`; dual-UID homes via symlink.
- Scripts under `scripts/ldap/`:
  - `generate_org_ldif.py` — workbook.local org skeleton
  - `export_local_users.py` — `auth.yaml` → LDIF + `identity_map.yaml`
  - `link_homes.py` — `/home/users/<uidNumber>` → local home
- Design guide: [`docs/identity-upgrade.md`](docs/identity-upgrade.md)

### License (online)

- Control plane: **`authelia-fb-2.0/`** — Authelia + OpenLDAP + `license-api` + `identity-api` (`/v1/provision`).
- Device `license.activate()` calls `MESHDRIVE_LICENSE_URL` when set (moved out of `meshdrive-2.0/server/`).
- Device LDAP helpers remain under `scripts/ldap/` (export + link homes).

### Filebrowser / homes

- `storage/homes.py` — private homes + setgid shared folders + symlink-into-scope helper.
- Filebrowser `add_filebrowser_user(..., scope=)` and `set_filebrowser_scope()`.

### Version

- Package version **2.1.0**.

## 2.0.0

- Local-first JuiceFS agent, TUI, Filebrowser, free MCP/OpenFGA/OTEL add-ons, paid WireGuard/VIX/SSSD/cluster gates.
