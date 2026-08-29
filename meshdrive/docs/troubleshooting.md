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
| Mount fails | FUSE not loaded | `sudo modprobe fuse`; check `/etc/fuse.conf` has `user_allow_other` |
| Permission denied on mount | Data path missing or wrong owner | Create data path; ensure writable |
| Mount OK but empty in Filebrowser | `allow_other` missing | Enable `user_allow_other` in fuse.conf; remount |
| `juicefs: command not found` | Binary fetch failed | `bash /opt/meshdrive/packaging/fetch-binaries.sh /opt/meshdrive` |

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
| Cannot log in | No users / wrong password | Check `var/bootstrap-password.txt` or create user in TUI |

```bash
journalctl -u meshdrive-filebrowser -b --no-pager
curl -sS http://127.0.0.1:8080/
```

---

## Add-ons

| Symptom | Cause | Fix |
|---------|-------|-----|
| Paid addon rejected | No license | `meshdrive license activate --token …` |
| MCP import error | `[mcp]` extra not installed | `meshdrive addons install mcp` |
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
| Data not in `/opt/meshdrive` | Expected — snap uses `$SNAP_COMMON` | Use `/var/snap/meshdrive/common` |
| FUSE/WG issues | Classic snap still needs host fuse | Install host `fuse3`; run WG with sudo on host |
| Command not on PATH | Snap apps not aliased | `snap run meshdrive.doctor` |

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
