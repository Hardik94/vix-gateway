# MeshDrive 2.0 Documentation

MeshDrive 2.0 is a **local-first** Linux storage agent: JuiceFS on local disks, a Textual TUI for setup, Filebrowser on loopback, and optional modules for AI tools, authorization, telemetry, and (with a license) remote connectivity over WireGuard.

## Start here

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Components, data flow, directory layout, isolation model |
| [Installation](installation.md) | Snap, Flatpak, `.deb`, and developer installs |
| [Storage](storage.md) | JuiceFS backends, capacity, multi-volume Filebrowser |
| [User ↔ bucket ACL](storage-acl.md) | Many-to-many assign, portals, TUI (2.2) |
| [Pinned binaries](binaries.md) | JuiceFS/Filebrowser versions and upgrade plan |
| [CLI reference](cli-reference.md) | `meshdrive` commands and entry points |
| [Configuration](configuration.md) | `config.yaml`, `license.yaml`, `cluster.yaml`, environment |
| [Add-ons](addons.md) | Free and paid optional modules |
| [Licensing](licensing.md) | Free vs paid tier, activation, feature gating |
| [Identity upgrade](identity-upgrade.md) | Free→paid LDAP hybrid, private homes, shares (2.1) |
| [Control plane (Authelia/LDAP)](../../authelia-fb-2.0/README.md) | Server-side Authelia + OpenLDAP + license + provision |
| [Changelog](../CHANGELOG.md) | Release notes |
| [WireGuard client](wireguard.md) | Hub-spoke VPN setup (paid) |
| [Paid cluster](paid-cluster.md) | SSSD/LDAP, remote JuiceFS, VIX gateway/FUSE |
| [Agent API](agent-api.md) | Loopback JSON control API used by the TUI |
| [MCP integration](mcp.md) | AI tool server, path isolation, OpenFGA |
| [MCP clients](mcp-clients.md) | Connect Cursor, Claude Code, Open WebUI, Hermes |
| [Development](development.md) | Hacking on the Python package without a full install |
| [Testing](TESTING.md) | Regression, snap, WireGuard lab, isolation checks |
| [Troubleshooting](troubleshooting.md) | Common failures and log locations |

## Marketing (growth)

Product docs above; go-to-market lives in **[../marketing/](../marketing/README.md)** — plan of action, positioning, free vs paid, competitors, Snap/BharatOS channels, messaging kit, metrics.

## Quick reference

```bash
meshdrive doctor          # verify install
meshdrive status          # backends + agent
meshdrive-tui             # interactive setup
meshdrive addons list     # optional modules
```

**Install root**

| Packaging | Path |
|-----------|------|
| `.deb` / git install | `/opt/meshdrive` |
| Snap | `/var/snap/meshdrive/common` (`$SNAP_COMMON`) |
| Flatpak | `~/.var/app/in.vistrix.MeshDrive/data/meshdrive` |

**Loopback services (defaults)**

| Service | Address |
|---------|---------|
| Agent API | `http://127.0.0.1:12700` |
| Filebrowser | `http://127.0.0.1:8080` |
| OpenFGA | `http://127.0.0.1:8081` |
| MCP (SSE) | `http://127.0.0.1:9000` |
| VIX gateway | `https://127.0.0.1:9443` |

## Product tiers

| | Free | Paid (license token) |
|---|------|----------------------|
| Storage | SQLite + local `file://` | + remote TiKV/MinIO **over WireGuard** |
| Users | Local `auth.yaml` | + SSSD → LDAP over WG |
| Network | Loopback only | WireGuard hub-spoke client |
| VIX | — | QUIC gateway + FUSE |
| ZeroTier | Not supported | Not supported |

See [licensing.md](licensing.md) for activation and [addons.md](addons.md) for install commands.

## Repository layout

```
meshdrive-2.0/
  README.md                 # project overview (start here on GitHub)
  pyproject.toml
  src/meshdrive/            # Python package (agent, TUI, CLI, addons)
  overlay/opt/meshdrive/    # shipped configs, systemd units, WG templates
  packaging/                # install.sh, nfpm, binary fetch, VIX build
  snap/snapcraft.yaml       # classic snap (primary user install)
  flatpak/                  # Flatpak manifest + AppStream (community / Flathub)
  docs/                     # this documentation tree
```

## Related repos in this monorepo

- [`infra/wireguard-hub-spoke/`](../infra/wireguard-hub-spoke/) — hub-side peer generation and nft rules
- [`vix_package/`](../vix_package/) — C++ QUIC gateway and FUSE (paid addon source)
- [`package/meshdrive-dev-local/`](../package/meshdrive-dev-local/) — **deprecated** 2.1.0 (ZeroTier + remote TiKV); do not install alongside 2.0
