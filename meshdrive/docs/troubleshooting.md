# Troubleshooting

Common MeshDrive 2.0 issues and where to look.

## Diagnostic commands

Run these first after any install problem:

```bash
meshdrive doctor
meshdrive doctor --verbose
meshdrive status
sudo systemctl status meshdrive-agent --no-pager
cat /opt/meshdrive/var/state.json    # or $SNAP_COMMON/var/state.json
curl -sS http://127.0.0.1:12700/health
```

---

## CLI / PATH

| Symptom | Cause | Fix |
|---------|-------|-----|
| `meshdrive: command not found` | Postinst/setup not run or PATH missing `/usr/local/bin` | Re-run `setup-runtime.sh` or reinstall; check `meshdrive doctor` |
| Symlinks exist but command fails | Broken venv or incomplete pip install | `sudo /opt/meshdrive/packaging/setup-runtime.sh` |
| Wrong install root | `MESHDRIVE_ROOT` set incorrectly | Unset or point to correct path; snap uses `$SNAP_COMMON` |

---

## Agent / TUI

| Symptom | Cause | Fix |
|---------|-------|-----|
| TUI: agent not running | Service stopped or failed | `sudo systemctl start meshdrive-agent` |
| Connection refused :12700 | Agent not listening | `journalctl -u meshdrive-agent -b` |
| Stale dashboard | state.json not updating | Restart agent; `curl /health` |

---

## Storage / JuiceFS

| Symptom | Cause | Fix |
|---------|-------|-----|
| Mount fails | FUSE not loaded / snap fusermount | `sudo apt-get install -y fuse3`; `sudo modprobe fuse`; enable `user_allow_other` in `/etc/fuse.conf`; rebuild **2.3.5+** (host fusermount PATH) |
| Permission denied on mount | Data path missing or wrong owner | Create data path; ensure writable |
| Mount OK but empty in Filebrowser | FB Bolt DB root stale / not `$ROOT/mnt` | Rebuild **2.3.7+**; or: stop FB, `filebrowser config set -d …/filebrowser.db --root /opt/meshdrive/mnt`, start FB |
| Filebrowser usage bar ignores bucket size | Root was `$ROOT/mnt` (host disk); capacity needs remount | Rebuild **2.3.8+**; or set root to mount + remount (see below) |
| Login then `lstat …/mnt/NAME/opt` | Root and scope both absolute `/opt/meshdrive/...` (joined) | Rebuild **2.3.9+**; workaround below |
| MCP install OK but nothing on :9000 (deb) | Unit not copied/enabled | Rebuild **2.3.7+**; `sudo systemctl enable --now meshdrive-mcp`; `curl -sS http://127.0.0.1:9000/ready` |
| MCP **401** without token | Expected for SSE | Send `Authorization: Bearer …` from `meshdrive mcp credentials show` |
| MCP **500/503** + `Permission denied: …/mcp_credentials.yaml` | File owned by root or unit marked `/etc` read-only | See below (fixed in **2.3.10**) |
| `juicefs: command not found` | Binary fetch failed | `bash /opt/meshdrive/packaging/fetch-binaries.sh /opt/meshdrive` |

### MCP credentials Permission denied (deb)

`meshdrive-mcp.service` runs as user **`meshdrive`**. If the token file was created with `sudo`, it can be `root:root` mode `0600`, so every Bearer request fails. Older units also marked `/opt/meshdrive/etc` **read-only**, which breaks argon2 rehash writes.

**Immediate fix (no rebuild):**

```bash
sudo chown meshdrive:meshdrive /opt/meshdrive/etc /opt/meshdrive/etc/mcp_credentials.yaml
sudo chmod 750 /opt/meshdrive/etc
sudo chmod 600 /opt/meshdrive/etc/mcp_credentials.yaml
# Refresh unit (2.3.10+ overlay) or edit ReadWritePaths to include etc:
sudo cp /opt/meshdrive/systemd/meshdrive-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now meshdrive-mcp
curl -sS http://127.0.0.1:9000/ready
# With token:
TOKEN=$(sudo meshdrive mcp credentials show 2>/dev/null | head -1)
curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9000/ready
```

After reboot, if MCP is down: `sudo systemctl enable --now meshdrive-mcp`.

Logs:

```bash
journalctl -u 'meshdrive-mount@*' -b --no-pager
/opt/meshdrive/bin/juicefs status /opt/meshdrive/mnt/primary
```

---

## Filebrowser

| Symptom | Cause | Fix |
|---------|-------|-----|
| Port 8080 in use | Another service bound | Change port in TUI Settings or `config.yaml` |
| 403 / empty UI | Mount not up or wrong root | Mount storage first; check `filebrowser.json` root |
| Invalid credentials | User in MeshDrive but not synced to Filebrowser DB; short password (&lt;12); or DB lock while service running | See recovery below |
| Cannot log in | No users / wrong password | Check `var/bootstrap-password.txt` or create user in TUI |
| Login works, then “can't be reached” | Opened via `meshdrive.local` which does not resolve on that client | Use `http://127.0.0.1:8080` on the host, or LAN IP / Avahi (see below) |
| OpenFGA not healthy | Missing `openfga migrate` or unit/process not running | `.deb`: `journalctl -u meshdrive-openfga`; **snap**: `tail -f $SNAP_COMMON/var/log/openfga.log` then re-run `meshdrive addons install openfga` |

```bash
journalctl -u meshdrive-filebrowser -b --no-pager
curl -sS http://127.0.0.1:8080/
curl -sS http://meshdrive.local:8080/   # after hostname helper / mDNS

# Who exists in Filebrowser (stop service first — BoltDB single writer):
sudo systemctl stop meshdrive-filebrowser
sudo -u meshdrive /opt/meshdrive/bin/filebrowser users ls -d /opt/meshdrive/var/filebrowser.db
```

### Access on the LAN (`meshdrive.local`)

**Better suggestion than only `/etc/hosts`:** use **Avahi/mDNS** so other devices resolve the name without editing hosts on each client.

| Approach | Scope | Notes |
|----------|--------|--------|
| **mDNS** — hostname `meshdrive` + `avahi-daemon` | Whole LAN | Preferred for phones / other PCs |
| **`ensure-local-hostname.sh`** | This machine | Writes IPv4+IPv6 into `/etc/hosts` |
| Raw LAN IP | Always | Fallback |

```bash
sudo apt-get install -y avahi-daemon
sudo hostnamectl set-hostname meshdrive          # → meshdrive.local via mDNS
sudo /opt/meshdrive/packaging/ensure-local-hostname.sh

# Empty address = listen on 0.0.0.0 and [::] (dual-stack)
sudo cp /opt/meshdrive/systemd/meshdrive-filebrowser.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart meshdrive-filebrowser
ss -ltnup | grep 8080
```

Keep **agent / MCP / OpenFGA on 127.0.0.1**. For Filebrowser on LAN, restrict with firewall if needed (`ufw allow from 192.168.0.0/16 to any port 8080`). Loopback-only: set `filebrowser.address: "127.0.0.1"` in `config.yaml`.

### Recovery: invalid credentials after creating a user

MeshDrive stores users in `etc/auth.yaml`; Filebrowser login uses **`var/filebrowser.db`**. Sync can fail if the password was under **12 characters**, or if Filebrowser was running (database locked) when the user was added.

Reset the Filebrowser password for an existing MeshDrive username:

```bash
sudo systemctl stop meshdrive-filebrowser
sudo -u meshdrive /opt/meshdrive/bin/filebrowser users update YOUR_USER \
  -p 'YourPassword12+' \
  -d /opt/meshdrive/var/filebrowser.db
# If user is missing from Filebrowser:
sudo -u meshdrive /opt/meshdrive/bin/filebrowser users add YOUR_USER \
  'YourPassword12+' -d /opt/meshdrive/var/filebrowser.db --perm.admin
sudo systemctl start meshdrive-filebrowser
```

Bootstrap admin (first start, no users yet):

```bash
sudo cat /opt/meshdrive/var/bootstrap-password.txt
# login as admin with that password
```

---

## Add-ons

| Symptom | Cause | Fix |
|---------|-------|-----|
| Paid addon rejected | No license | `meshdrive license activate --token …` |
| MCP import error | `[mcp]` extra not installed | `meshdrive addons install mcp` |
| `Server has no attribute list_tools` | `mcp` 2.x installed (API break) | Pin `mcp>=1.2.0,<2` and reinstall: `/opt/meshdrive/venv/bin/pip install 'mcp>=1.2.0,<2'` |
| OpenFGA bootstrap failed | Binary up but API not ready | Start unit, retry install |
| OTEL no files | Telemetry disabled in settings | Enable in TUI Settings |

```bash
meshdrive addons list
journalctl -u meshdrive-mcp -u meshdrive-openfga -u meshdrive-otel -b
```

---

## WireGuard (paid)

| Symptom | Cause | Fix |
|---------|-------|-----|
| License error on WG commands | Free tier | Activate license + install wireguard addon |
| `wg-quick not found` | Bootstrap not run | `sudo meshdrive wireguard bootstrap` |
| No handshake | Firewall / wrong endpoint | Verify hub IP, UDP 51820, peer config |
| LDAP unreachable | WG down or DNS | `wg show`; ping hub; check nft rules |

```bash
sudo wg show
sudo journalctl -u wg-quick@wg0 -b
meshdrive wireguard status
```

---

## Snap-specific

| Symptom | Cause | Fix |
|---------|-------|-----|
| TUI: `RemoteDisconnected` on Add storage | Agent crashed mid-request (often juicefs format) | `journalctl -u snap.meshdrive.agent.service -b --no-pager \| tail -80`; ensure juicefs works: `$SNAP/opt/meshdrive/bin/juicefs version` |
| `Permission denied` on `:12700` (errno 13) | Snap not classic, or bound as `localhost`/IPv6 | Reinstall with `--classic`; `snap info meshdrive \| grep confinement` must say classic; bind is `127.0.0.1` |
| Agent not running / TUI offline | Snap daemon not started | `sudo snap start meshdrive.agent` (unit: `snap.meshdrive.agent.service` — **not** `meshdrive-agent`) |
| `Unit meshdrive-agent.service not found` | Expected on snap | Use `sudo snap start meshdrive.agent` |
| `filebrowser.db` missing / wrong path | Paths under `$SNAP` or `$SNAP_DATA` | Expect `/opt/meshdrive/var/filebrowser.db` (→ `$SNAP_COMMON`); rebuild 2.2.3+ or `sudo snap restart meshdrive.agent` |
| Data not in `/opt/meshdrive` | Expected — snap uses `$SNAP_COMMON` via layout | Use `/var/snap/meshdrive/common` or `/opt/meshdrive` inside snap |
| FUSE/WG issues | Classic snap still needs host fuse | Install host `fuse3`; run WG with sudo on host |
| Command not on PATH | Snap apps not aliased | `snap run meshdrive.doctor` |
| MCP install fails | Pre-2.3.2 tried host venv/`pip` | Rebuild **2.3.2+** snap (ships `[mcp]`); then `snap run meshdrive.addons install mcp` |
| OpenFGA stuck at ~90% | No host systemd unit under snap; process never started | Rebuild **2.3.2+**; `snap run meshdrive.addons install openfga`; log: `$SNAP_COMMON/var/log/openfga.log` |
| OpenFGA tar `assets/… operation not permitted` | Full release unpack blocked under snap | Rebuild **2.3.3+** (binary-only extract + shipped openfga); retry install |
| Storage create `PermissionError` after sudo OpenFGA | Data path `/opt/meshdrive/...` or root-owned dirs after sudo | Rebuild **2.3.4+**; leave Data path **blank**; or `sudo chown -R root:root /var/snap/meshdrive/common` |
| JuiceFS mount fails (create OK) | Snap PATH used staged `fusermount3` (no setuid) or missing `user_allow_other` | Host: `sudo apt-get install -y fuse3`; enable `user_allow_other`; rebuild **2.3.5+**; log: `$SNAP_COMMON/var/log/juicefs-mount.log` |
| Filebrowser via `meshdrive.local` fails | Name not in hosts / no mDNS on client | Prefer `http://127.0.0.1:8080` or LAN IP; install Avahi for LAN name |

---

## VIX (paid)

| Symptom | Cause | Fix |
|---------|-------|-----|
| Binary missing | Not built | Run `packaging/build-vix.sh` on Linux |
| Health check fails | Gateway not started | `systemctl status meshdrive-vix-gateway` |
| FUSE mount fails | WG down or bad backend JSON | Check `etc/vix-fuse-backends.json` uses inner WG IPs |

---

## Log locations

| Component | Log |
|-----------|-----|
| Agent | `journalctl -u meshdrive-agent` |
| Mount | `journalctl -u meshdrive-mount@NAME` |
| Filebrowser | `journalctl -u meshdrive-filebrowser` |
| MCP / OpenFGA / OTEL | respective `meshdrive-*.service` units |
| Agent file log | `$ROOT/var/log/agent.log` (if configured) |
| Runtime state | `$ROOT/var/state.json` |

---

## Reset (destructive)

Remove install root and systemd units — see [installation.md](installation.md#uninstall).

JuiceFS data on external disks is **not** removed.

---

## Getting help

When reporting issues, include:

```bash
meshdrive doctor --json
meshdrive license status
uname -a
```

And relevant `journalctl` excerpts for failing units.
