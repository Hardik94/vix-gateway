# Flatpak packaging (MeshDrive 2.0)

App ID: **`in.vistrix.MeshDrive`**

Flatpak is an optional install path for desktop Linux (Fedora, Ubuntu, BharatOS, etc.).  
Snap remains the primary end-user path; `.deb` remains best for systemd-heavy servers.

## What is in this folder

| File | Purpose |
|------|---------|
| `in.vistrix.MeshDrive.yaml` | Flatpak Builder manifest |
| `in.vistrix.MeshDrive.metainfo.xml` | AppStream metadata (Flathub / GNOME Software) |
| `in.vistrix.MeshDrive.desktop` | Desktop launcher (TUI) |
| `in.vistrix.MeshDrive.svg` | App icon |
| `meshdrive-wrapper.sh` | Runtime entry: sets `MESHDRIVE_ROOT`, seeds configs |
| `update-binary-sources.sh` | Downloads pinned binaries and writes sha256 into the manifest |

## Prerequisites

```bash
# Ubuntu / Debian
sudo apt-get install -y flatpak flatpak-builder curl
flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install -y flathub org.freedesktop.Platform//24.08 org.freedesktop.Sdk//24.08
```

## Build

From the **`meshdrive-2.0/`** directory:

```bash
chmod +x flatpak/update-binary-sources.sh flatpak/meshdrive-wrapper.sh
./flatpak/update-binary-sources.sh   # required once (fills JuiceFS/Filebrowser hashes)

flatpak-builder --user --install --force-clean .flatpak-build \
  flatpak/in.vistrix.MeshDrive.yaml
```

## Run

```bash
flatpak run in.vistrix.MeshDrive                  # TUI (default)
flatpak run --command=meshdrive in.vistrix.MeshDrive doctor
flatpak run --command=meshdrive in.vistrix.MeshDrive status
flatpak run --command=meshdrive-agent in.vistrix.MeshDrive
```

## Data location

| Item | Path |
|------|------|
| State root | `~/.var/app/in.vistrix.MeshDrive/data/meshdrive` (`$MESHDRIVE_ROOT`) |
| Config | `$MESHDRIVE_ROOT/etc/` |
| Mounts | `$MESHDRIVE_ROOT/mnt/<backend>/` |

Same layout as Snap/`/opt/meshdrive`, under the Flatpak data dir.

## Create an installable `.flatpak` (community upload)

After a successful `--install` build:

```bash
mkdir -p dist
flatpak build-bundle \
  ~/.local/share/flatpak/repo \
  dist/meshdrive-2.0.0-x86_64.flatpak \
  in.vistrix.MeshDrive

# Users install with:
flatpak install --user dist/meshdrive-2.0.0-x86_64.flatpak
# or:
flatpak install --user ./meshdrive-2.0.0-x86_64.flatpak
```

Upload **`dist/meshdrive-2.0.0-x86_64.flatpak`** to:

- GitHub Releases
- Community Discord / Telegram / forum
- BharatOS / college mirror drop folders

## Flathub (community) submission

1. Fork [flathub/flathub](https://github.com/flathub/flathub) and open a PR that requests a new app (or follow current Flathub “new app” process).
2. Create a dedicated packaging repo: `flathub/in.vistrix.MeshDrive` containing this manifest (often without the full monorepo — use a git `source` pointing at a MeshDrive release tag).
3. Replace pip `--share=network` modules with **pinned** Python sources from [`flatpak-builder-tools` pip generator](https://github.com/flatpak/flatpak-builder-tools) before Flathub CI (no network in build).
4. Confirm AppStream (`metainfo.xml`), icon (≥128px), and screenshots.
5. Fix `project_license` in metainfo to match the published license.
6. After merge, users install with:

```bash
flatpak install flathub in.vistrix.MeshDrive
```

### Permissions note for reviewers

MeshDrive needs **`--device=all`** (FUSE) and host filesystem access for user-chosen data disks. Document this clearly in the Flathub listing. Host systemd units are **not** installed by the Flatpak; the in-sandbox agent is started via `flatpak run --command=meshdrive-agent`.

## Limitations vs Snap / `.deb`

| Capability | Flatpak | Snap (classic) | `.deb` |
|------------|---------|----------------|--------|
| TUI / CLI | Yes | Yes | Yes |
| FUSE JuiceFS | Yes (with device access) | Yes | Yes |
| Host systemd units | No (run agent via flatpak) | Daemon app | Yes |
| WireGuard / nftables | Limited by sandbox | Classic | Full |

Prefer Snap/`.deb` for always-on agents and paid WireGuard mesh on servers.

## Uninstall

```bash
flatpak uninstall in.vistrix.MeshDrive
# optional wipe of user data:
rm -rf ~/.var/app/in.vistrix.MeshDrive
```
