# Development

Guide for working on MeshDrive 2.0 from a git checkout without building a `.deb` or snap.

## Repository structure

```
meshdrive-2.0/
  pyproject.toml              # package metadata, entry points
  src/meshdrive/
    agent/                    # daemon, loopback API, health, systemd helpers
    tui/                      # Textual UI
    cli/                      # unified meshdrive CLI + doctor
    storage/                  # JuiceFS, Filebrowser, mount
    auth/                     # local auth.yaml users
    addons/                   # install.py, openfga helper
    license.py                # tier gating
    wireguard/                # paid WG client commands
    cluster/                  # paid cluster configure
    mcp/                      # MCP tool server
    config.py                 # YAML load/save/merge
    constants.py              # paths, SNAP_COMMON resolution
    paths.py                  # MCP isolation checks
  overlay/opt/meshdrive/      # shipped etc/, systemd/, share/
  packaging/                  # install.sh, nfpm, fetch-binaries.sh, build-vix.sh
  snap/snapcraft.yaml
  docs/                       # documentation
```

## Local Python environment

```bash
cd meshdrive-2.0
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[mcp]"    # optional MCP extra for development
```

## Dev install root

Use a directory inside the repo — never `/opt/meshdrive` during dev unless intentional:

```bash
export MESHDRIVE_ROOT="$PWD/devroot"
mkdir -p "$MESHDRIVE_ROOT"/{etc,var/{log,cache,meta,data,telemetry,openfga},mnt,bin}
cp overlay/opt/meshdrive/etc/config.yaml overlay/opt/meshdrive/etc/auth.yaml "$MESHDRIVE_ROOT/etc/"
```

## Running components

Terminal 1 — agent:

```bash
export MESHDRIVE_ROOT="$PWD/devroot"
meshdrive-agent
```

Terminal 2 — TUI:

```bash
export MESHDRIVE_ROOT="$PWD/devroot"
meshdrive-tui
```

CLI:

```bash
meshdrive doctor
meshdrive status
```

## Linux binaries

JuiceFS and Filebrowser binaries are **linux amd64**. On macOS you can develop the agent/TUI/CLI but storage mount will show components as missing.

On Linux dev machine:

```bash
bash packaging/fetch-binaries.sh "$MESHDRIVE_ROOT"
```

## Full tree install (Linux)

Equivalent to production layout:

```bash
sudo ./packaging/install.sh
sudo ./packaging/install.sh mcp
```

Uses `/opt/meshdrive` and systemd.

## Building packages

**Deb:**

```bash
cd packaging
nfpm pkg -f nfpm.yaml --target ../dist/meshdrive_2.0.0_amd64.deb
```

**Snap:**

```bash
cd meshdrive-2.0
snapcraft --use-lxd
```

**VIX binaries (Linux, cmake + Rust for quiche):**

```bash
bash packaging/build-vix.sh /opt/meshdrive all
```

See [`vix_package/cpp_gateway/README.md`](../../vix_package/cpp_gateway/README.md).

## Code conventions

- All config/state under `$ROOT` — use `meshdrive.constants.ROOT`, not hardcoded `/opt/meshdrive` in new code
- MCP paths must go through `meshdrive.paths.assert_allowed`
- Paid features must call `meshdrive.license.require_addon` or `addon_allowed`
- Agent API stays loopback-only
- Prefer extending `addons/install.py` for new optional modules

## Syntax check

```bash
python3 -m compileall -q src
```

## Testing

See [TESTING.md](TESTING.md) for VM-based regression (deb, snap, WireGuard lab).

Quick API smoke test with agent running:

```bash
curl -sS http://127.0.0.1:12700/health | python3 -m json.tool
```

## Entry points (pyproject.toml)

| Script | Module |
|--------|--------|
| `meshdrive` | `meshdrive.cli.__main__:main` |
| `meshdrive-agent` | `meshdrive.agent.__main__:main` |
| `meshdrive-tui` | `meshdrive.tui.__main__:main` |
| `meshdrive-addons` | `meshdrive.addons.__main__:main` |
| `meshdrive-mcp` | `meshdrive.mcp.__main__:main` |
| `meshdrive-mount` | `meshdrive.storage.mount:main` |

## Related monorepo paths

- WireGuard hub: `infra/wireguard-hub-spoke/`
- VIX C++ sources: `vix_package/cpp_gateway/`, `vix_package/cpp_fuse/`
- Legacy 2.1.0 (do not extend): `package/meshdrive-dev-local/`
