# Pinned binaries & upgrade plan

MeshDrive ships **pinned** Linux amd64 binaries for JuiceFS and Filebrowser. Versions are fixed at install time so all users get the same tested stack.

## Current pinned versions (MeshDrive 2.0.0)

| Component | Version | Source | Install path |
|-----------|---------|--------|--------------|
| **JuiceFS** | **v1.4.1** | [juicedata/juicefs v1.4.1](https://github.com/juicedata/juicefs/releases/tag/v1.4.1) | `$ROOT/bin/juicefs` |
| **Filebrowser** | **v2.63.23** | [filebrowser releases](https://github.com/filebrowser/filebrowser/releases/tag/v2.63.23) | `$ROOT/bin/filebrowser` |

> **Note:** Upstream File Browser announced archival (last planned line ~v2.63.x). MeshDrive pins the latest stable release for security/bugfixes. Longer term we may vendor a fork or replace the UI; see upgrade plan below.

Defaults are set in:

- [`packaging/fetch-binaries.sh`](../packaging/fetch-binaries.sh) — `MESHDRIVE_JUICEFS_VERSION` / `MESHDRIVE_FILEBROWSER_VERSION`
- [`src/meshdrive/constants.py`](../src/meshdrive/constants.py) — `PINNED_JUICEFS_VERSION` / `PINNED_FILEBROWSER_VERSION`

Verify on a host:

```bash
/opt/meshdrive/bin/juicefs version
/opt/meshdrive/bin/filebrowser version
meshdrive doctor -v
```

---

## Upgrade policy

| Rule | Detail |
|------|--------|
| Pin by default | New installs always get the versions above unless env overrides |
| Do not auto-upgrade | `fetch-binaries.sh` skips download if the binary already exists |
| Upgrade is intentional | Operators (or MeshDrive release notes) bump the pin, then re-fetch |
| Test before bump | Run [TESTING.md](TESTING.md) A + storage mount + Filebrowser smoke |
| Data safety | JuiceFS metadata/data stay under `$ROOT`; replacing the binary does not wipe volumes |

---

## Plan to upgrade later

### Phase 1 — Track upstream (ongoing)

- [ ] Watch JuiceFS and Filebrowser release notes for security fixes
- [ ] Keep a short changelog entry in MeshDrive when pins change
- [ ] Prefer patch/minor bumps within the same major when possible

### Phase 2 — Controlled bump (per MeshDrive release)

1. Update defaults in `packaging/fetch-binaries.sh` and `constants.py`
2. Update this doc table and [storage.md](storage.md)
3. On a test VM:
   ```bash
   # Force re-download (remove old binaries first)
   sudo rm -f /opt/meshdrive/bin/juicefs /opt/meshdrive/bin/filebrowser
   sudo MESHDRIVE_JUICEFS_VERSION=x.y.z MESHDRIVE_FILEBROWSER_VERSION=a.b.c \
     bash /opt/meshdrive/packaging/fetch-binaries.sh /opt/meshdrive
   sudo systemctl restart meshdrive-agent 'meshdrive-mount@*' meshdrive-filebrowser
   meshdrive doctor
   ```
4. Confirm existing mounts still work; Filebrowser login still works
5. Ship new MeshDrive package (snap/deb) with the new pins

### Phase 3 — In-product upgrade (future)

Optional later features (not required for 2.0.0):

- `meshdrive binaries status` — show installed vs pinned
- `meshdrive binaries upgrade [--juicefs x.y.z] [--filebrowser a.b.c]` — backup old binary, fetch, restart units
- Snap/deb postinst only upgrades when package version increases

### Rollback

```bash
# Keep previous binary as juicefs.bak before upgrading
sudo mv /opt/meshdrive/bin/juicefs /opt/meshdrive/bin/juicefs.bak
# ... failed upgrade ...
sudo mv /opt/meshdrive/bin/juicefs.bak /opt/meshdrive/bin/juicefs
sudo systemctl restart 'meshdrive-mount@*'
```

Same pattern for `filebrowser`.

---

## Env overrides (dev / early adopters)

Without changing package defaults:

```bash
sudo MESHDRIVE_JUICEFS_VERSION=1.4.1 \
  MESHDRIVE_FILEBROWSER_VERSION=2.63.23 \
  bash packaging/fetch-binaries.sh /opt/meshdrive juicefs filebrowser
```

Remove existing binaries first if you need a re-download (script skips when `$ROOT/bin/juicefs` already exists).

---

## Compatibility notes

- **JuiceFS:** Format/mount options used by MeshDrive (`--storage file`, `--capacity`, `allow_other`) must remain supported in the target version.
- **Filebrowser:** Config path `-c $ROOT/etc/filebrowser.json` and users DB must remain compatible; major Filebrowser upgrades may need a config migration checklist.
- **Existing volumes:** Soft capacity set at `format` time lives in JuiceFS metadata; changing the binary does not reset capacity. To change capacity later, use JuiceFS config/quota tools (document per-version CLI).
