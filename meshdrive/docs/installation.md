# Installation

MeshDrive 2.0 supports four install paths. **Snap is recommended for end users**; Flatpak suits desktop Linux distros; `.deb` and `install.sh` suit developers and enterprise deployments.

## Requirements

- **OS:** Debian or Ubuntu (amd64 or arm64) for Snap/`.deb`; any Flatpak-capable Linux for Flatpak
- **Init:** systemd (Snap/`.deb`); Flatpak runs the agent via `flatpak run`
- **Kernel:** FUSE (`fuse3` or `fuse`)
- **Python:** 3.10+ (venv created automatically on install; bundled in Flatpak)
- **Tools:** `curl`, `ca-certificates`, `tar` (host tools for Snap/`.deb` builds)
- **Disk:** ~1 GB for binaries, venv, and cache (data disks are separate)

First install needs outbound HTTPS for PyPI and GitHub releases (JuiceFS **v1.4.1**, Filebrowser **v2.63.23**). After that, **free tier** operation does not require the internet.

---

## Option A — Snap (recommended)

Classic confinement is used so FUSE, WireGuard, and nftables work without strict snap plugs.

### Build

```bash
cd meshdrive   # package root (parent of snap/), not only snap/
# Ensure LXD + group: sudo usermod -aG lxd "$USER" && newgrp lxd

# LXD only packs what is on disk / not craft-ignored. Commit src, packaging,
# overlay (or rely on snap/local fallback), pyproject.toml:
#   git add src packaging overlay snap pyproject.toml README.md
#   git status   # confirm overlay or snap/local is present

snapcraft clean --use-lxd
# Same yaml supports both arches; build on matching host (or use remote-build):
snapcraft pack --use-lxd --build-for=amd64
# snapcraft pack --use-lxd --build-for=arm64
# snapcraft remote-build   # Launchpad can build amd64 + arm64 from this recipe
# or:
snapcraft pack --destructive-mode --build-for=amd64
```

`override-build` reads `$CRAFT_PART_SRC` and falls back to `snap/local/opt/meshdrive` for configs if `overlay/` was omitted from the LXD pack.

### Install

```bash
# Local/unsigned builds need --dangerous; this snap is classic confinement.
# Store "beta" channel still needs classic confinement approval from Snap Store.
sudo snap install --dangerous --classic ./meshdrive_2.2.4_amd64.snap
sudo snap start meshdrive.agent
snap run meshdrive.doctor
snap run meshdrive.tui
curl -sS http://127.0.0.1:12700/health
```

After install, wrappers must use `$SNAP/usr/bin/python3 -m meshdrive.cli` with
`PYTHONPATH=$SNAP/opt/meshdrive/python-packages` (relocatable; no build-time venv).
JuiceFS / Filebrowser ship under `$SNAP/opt/meshdrive/bin` (not `$SNAP_COMMON/bin`).
Doctor accepts snap apps (`meshdrive.tui`, `$SNAP/bin/*-wrapper`).

Quick check:

```bash
head -20 /snap/meshdrive/current/bin/meshdrive-wrapper
ls /snap/meshdrive/current/opt/meshdrive/python-packages/meshdrive
ls /snap/meshdrive/current/opt/meshdrive/bin/{juicefs,filebrowser}
snap run meshdrive --help
```

### Data location

All state lives under **`/var/snap/meshdrive/common/`** (`$SNAP_COMMON` — preferred data root).
Shipped binaries and Python code live under **`/snap/meshdrive/current/opt/meshdrive/`**.

Wrappers set `MESHDRIVE_ROOT=$SNAP_COMMON`. Filebrowser DB and logs:

- DB: `/var/snap/meshdrive/common/var/filebrowser.db`
- Logs: `/var/snap/meshdrive/common/var/log/`

### Snap apps

| App | Command |
|-----|---------|
| CLI | `snap run meshdrive` |
| Doctor | `snap run meshdrive.doctor` |
| TUI | `snap run meshdrive.tui` |
| Agent | `snap run meshdrive.agent` (daemon — auto-start via install hook) |
| Addons | `snap run meshdrive.addons` |
| MCP | `snap run meshdrive.mcp` |

If the TUI says **Agent offline** (snap has **no** `meshdrive-agent.service`):

```bash
sudo snap start meshdrive.agent
# equivalent systemd unit name:
sudo systemctl start snap.meshdrive.agent.service
sudo systemctl status snap.meshdrive.agent.service --no-pager

snap run meshdrive.doctor
curl -sS http://127.0.0.1:12700/health
journalctl -u snap.meshdrive.agent.service -b --no-pager | tail -50
```

---

## Option B — Flatpak (desktop / community)

Manifest and AppStream metadata live under [`flatpak/`](../flatpak/). App ID: **`in.vistrix.MeshDrive`**.

### Build

```bash
# once: Flatpak SDK + flathub remote (see flatpak/README.md)
cd meshdrive-2.0
./flatpak/update-binary-sources.sh   # fills JuiceFS/Filebrowser sha256
flatpak-builder --user --install --force-clean .flatpak-build \
  flatpak/in.vistrix.MeshDrive.yaml
```

### Bundle for community upload

```bash
mkdir -p dist
flatpak build-bundle \
  ~/.local/share/flatpak/repo \
  dist/meshdrive-2.0.0-x86_64.flatpak \
  in.vistrix.MeshDrive
```

Distribute `dist/meshdrive-2.0.0-x86_64.flatpak` via GitHub Releases or community mirrors. Users install with:

```bash
flatpak install --user ./meshdrive-2.0.0-x86_64.flatpak
flatpak run in.vistrix.MeshDrive
```

### Data location

**`~/.var/app/in.vistrix.MeshDrive/data/meshdrive`** (`MESHDRIVE_ROOT`).

Full systemd host units are not installed by Flatpak — start the agent with `flatpak run --command=meshdrive-agent in.vistrix.MeshDrive`. Details and Flathub submission: [flatpak/README.md](../flatpak/README.md).

---

## Option C — Debian package

### Build

Requires [nfpm](https://github.com/goreleaser/nfpm):

```bash
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
cd meshdrive-2.0/packaging
mkdir -p ../dist
nfpm pkg -f nfpm.yaml --target ../dist/meshdrive_2.0.0_amd64.deb
```

### Install

```bash
sudo apt-get install -y fuse3 python3 python3-venv python3-pip curl ca-certificates
sudo dpkg -i meshdrive_2.0.0_amd64.deb
sudo apt-get install -f -y
```

Postinst runs `packaging/setup-runtime.sh`, which:

- Creates user/group `meshdrive`
- Builds venv and `pip install`s the package
- Downloads JuiceFS and Filebrowser
- Symlinks `/usr/local/bin/meshdrive`, `meshdrive-tui`, `meshdrive-agent`, `meshdrive-addons`
- Enables and starts `meshdrive-agent.service`

**Storage is not mounted automatically** — configure via TUI first.

### Verify

```bash
which meshdrive meshdrive-tui meshdrive-agent meshdrive-addons
meshdrive doctor
meshdrive status
sudo systemctl status meshdrive-agent
```

---

## Option D — install.sh (from git)

```bash
cd meshdrive-2.0
sudo ./packaging/install.sh              # core only
sudo ./packaging/install.sh addons       # mcp + openfga + otel
sudo ./packaging/install.sh mcp          # single addon (installs core if missing)
```

Equivalent to Option C but without dpkg; useful when iterating on the tree.

---

## Optional: meshdrive group

Add your login to the `meshdrive` group to manage some units without root (postinst does this for `SUDO_USER` when present):

```bash
sudo usermod -aG meshdrive "$USER"
# log out and back in
```

---

## First run

```bash
meshdrive-tui
# Flatpak: flatpak run in.vistrix.MeshDrive
```

1. **Storage** — Add backend `primary`, choose data path, mount
2. **Dashboard** — Confirm JuiceFS mounted, start Filebrowser
3. Open `http://127.0.0.1:8080` — bootstrap admin password in `$ROOT/var/bootstrap-password.txt` if no users exist

If the agent is down:

```bash
sudo systemctl start meshdrive-agent
# Flatpak: flatpak run --command=meshdrive-agent in.vistrix.MeshDrive
```

---

## Paid tier (after install)

```bash
meshdrive license activate --token "$MESHDRIVE_TOKEN"
meshdrive addons install wireguard
sudo meshdrive wireguard bootstrap
sudo meshdrive wireguard apply --file /path/to/wg0.conf
sudo meshdrive wireguard up
```

See [licensing.md](licensing.md), [wireguard.md](wireguard.md), and [paid-cluster.md](paid-cluster.md).

---

## Uninstall

### Snap

```bash
sudo snap remove meshdrive
sudo rm -rf /var/snap/meshdrive
```

### Flatpak

```bash
flatpak uninstall in.vistrix.MeshDrive
rm -rf ~/.var/app/in.vistrix.MeshDrive   # optional data wipe
```

### Deb / install.sh

```bash
sudo systemctl stop meshdrive-agent meshdrive-filebrowser \
  meshdrive-mcp meshdrive-openfga meshdrive-otel \
  meshdrive-vix-gateway meshdrive-vix-fuse 'meshdrive-mount@*' wg-quick@wg0 2>/dev/null || true

sudo systemctl disable meshdrive-agent meshdrive-filebrowser \
  meshdrive-mcp meshdrive-openfga meshdrive-otel \
  meshdrive-vix-gateway meshdrive-vix-fuse 2>/dev/null || true

sudo dpkg -r meshdrive 2>/dev/null || sudo rm -rf /opt/meshdrive

sudo rm -f /etc/systemd/system/meshdrive-*.service \
           /etc/sudoers.d/meshdrive \
           /usr/local/bin/meshdrive*

sudo userdel meshdrive 2>/dev/null || true
sudo systemctl daemon-reload
```

JuiceFS **data directories outside `$ROOT`** are never deleted automatically.

---

## Next steps

- [CLI reference](cli-reference.md)
- [Configuration](configuration.md)
- [Testing checklist](TESTING.md)
- [Flatpak packaging](../flatpak/README.md)
