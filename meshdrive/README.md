# MeshDrive 2.0

**Local-first Linux storage** with a terminal UI, loopback web access, optional AI tools, and license-gated remote connectivity over WireGuard.

MeshDrive keeps your files on **local disks by default** (JuiceFS + SQLite metadata). Paid features add hub-spoke VPN, LDAP, remote object storage, and QUIC gateways — all over WireGuard, not ZeroTier or public cloud endpoints.

---

## Features

- **Local JuiceFS** — SQLite metadata, `file://` object store, FUSE mounts under one install root
- JuiceFS **v1.4.1** + Filebrowser **v2.63.23** (loopback web UI on `127.0.0.1:8080`)
- **Textual TUI** — storage size, users, and add-ons
- **Unified CLI** — `meshdrive status`, `doctor`, `license`, `addons`, `wireguard`, `cluster`
- **Free add-ons** — MCP (AI tools), OpenFGA (authorization), OpenTelemetry (local files)
- **Paid add-ons** — WireGuard client, SSSD/LDAP, remote JuiceFS cluster, VIX QUIC gateway/FUSE
- **Isolation** — config, secrets, and MCP file access stay under `$ROOT`; no `$HOME/.config/meshdrive`

## Quick start

```bash
# After snap or .deb install
meshdrive doctor
meshdrive-tui
```

Add storage in the TUI → mount → open `http://127.0.0.1:8080`.

## Marketing & GTM

Go-to-market plans for Snap, BharatOS, and free→paid growth: **[marketing/](marketing/README.md)** (plan of action, positioning, channels, messaging kit).

## Documentation

| Guide | Description |
|-------|-------------|
| **[Documentation index](docs/README.md)** | Full doc tree — start here |
| [Architecture](docs/architecture.md) | Components, data flow, directory layout |
| [Installation](docs/installation.md) | Snap, Flatpak, `.deb`, developer install |
| [Storage](docs/storage.md) | JuiceFS backends, capacity, multi-volume Filebrowser |
| [Pinned binaries](docs/binaries.md) | JuiceFS/Filebrowser versions and upgrade plan |
| [CLI reference](docs/cli-reference.md) | All commands and environment variables |
| [Configuration](docs/configuration.md) | YAML files and settings |
| [Add-ons](docs/addons.md) | MCP, OpenFGA, OTEL, WireGuard, VIX |
| [Licensing](docs/licensing.md) | Free vs paid tier |
| [WireGuard](docs/wireguard.md) | Paid VPN client setup |
| [Paid cluster](docs/paid-cluster.md) | LDAP + remote JuiceFS + VIX |
| [Agent API](docs/agent-api.md) | Loopback JSON API |
| [MCP](docs/mcp.md) | AI editor integration |
| [MCP clients](docs/mcp-clients.md) | Cursor, Claude Code, Open WebUI, Hermes |
| [Development](docs/development.md) | Hacking on the Python package |
| [Testing](docs/TESTING.md) | Regression and lab checklist |
| [Troubleshooting](docs/troubleshooting.md) | Common failures |

## Tiers at a glance

| | Free | Paid (license token) |
|---|------|----------------------|
| Storage | SQLite on device | + remote TiKV/MinIO over WG |
| Identity | Local users | + SSSD → LDAP over WG |
| Network | Loopback only | WireGuard hub-spoke |
| VIX | — | QUIC gateway + FUSE |
| ZeroTier | **Not supported** | **Not supported** |

```bash
meshdrive license activate --token "$MESHDRIVE_TOKEN"
meshdrive addons install wireguard
sudo meshdrive wireguard bootstrap && sudo meshdrive wireguard apply --file wg0.conf
```

## Install

| Method | Audience | Command |
|--------|----------|---------|
| **Snap** | End users | `snapcraft pack` → `snap install --dangerous meshdrive_*.snap` |
| **Flatpak** | Desktop / community | `flatpak-builder` → `meshdrive-*.flatpak` or Flathub |
| **`.deb`** | Dev / enterprise | `nfpm pkg` → `dpkg -i meshdrive_*.deb` |
| **`install.sh`** | Git checkout | `sudo ./packaging/install.sh` |

Details: [installation.md](docs/installation.md), [flatpak/README.md](flatpak/README.md).

**Requirements:** Ubuntu/Debian amd64 (Snap/`.deb`), or any Flatpak host; FUSE; Python 3.10+ (bundled in Flatpak).

## Project layout

```
meshdrive-2.0/
  src/meshdrive/       # Python agent, TUI, CLI, addons
  overlay/             # configs + systemd shipped to disk
  packaging/           # deb install, binary fetch, VIX build
  snap/                # snapcraft.yaml (classic)
  flatpak/             # Flatpak manifest + AppStream (community / Flathub)
  docs/                # full documentation
```

## vs MeshDrive 2.1.0

Do **not** install alongside [`package/meshdrive-dev-local/`](../package/meshdrive-dev-local/) (`meshdrive-agent`). That legacy package uses ZeroTier + remote TiKV from first boot. MeshDrive 2.0 is local-first with optional WireGuard remote.

## License

Copyright © Vistrix Labs. Product licensing for paid tier features is separate from repository distribution — see [licensing.md](docs/licensing.md) for on-device activation.

## Version

**2.2.1** — snap doctor/binary paths; JuiceFS+Filebrowser under `$SNAP`.
**2.2.0** — user↔bucket ACL, Filebrowser portals, TUI assign users/buckets.
