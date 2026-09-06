# Installation

MeshDrive 2.0 supports four install paths. **Snap is recommended for end users**; Flatpak suits desktop Linux distros; `.deb` and `install.sh` suit developers and enterprise deployments.

## Requirements

- **OS:** Debian or Ubuntu (amd64) for Snap/`.deb`; any Flatpak-capable Linux for Flatpak
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
cd meshdrive-2.0/snap
# Ensure LXD + group: sudo usermod -aG lxd "$USER" && newgrp lxd
snapcraft pack --use-lxd
# or on a dedicated build VM:
snapcraft pack --destructive-mode
```

### Install

```bash
sudo snap install --dangerous meshdrive_2.1.0_amd64.snap
snap run meshdrive.doctor
snap run meshdrive.tui
```

After install, wrappers must call `$SNAP/opt/meshdrive/venv/...` — never a builder path like `/home/.../parts/meshdrive/install/...`. If you see that error, rebuild with current `snap/snapcraft.yaml` (2.1.0+).

### Data location

All state lives under **`/var/snap/meshdrive/common/`**, mirroring the `/opt/meshdrive` layout (`etc/`, `var/`, `bin/`, `mnt/`).

Snap sets `MESHDRIVE_ROOT=$SNAP_COMMON` in app wrappers.

### Snap apps

| App | Command |
|-----|---------|
| CLI | `snap run meshdrive` |
| Doctor | `snap run meshdrive.doctor` |
| TUI | `snap run meshdrive.tui` |
| Agent | `snap run meshdrive.agent` (daemon) |

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
