# Contributing

Thank you for contributing to MeshDrive 2.0.

## Before you start

- Read [docs/architecture.md](docs/architecture.md) for the system overview
- Read [docs/development.md](docs/development.md) for local setup
- Keep all config/state under the install root (`$MESHDRIVE_ROOT` / `/opt/meshdrive`)
- Paid features must go through `meshdrive.license` gating
- MCP file access must use `meshdrive.paths.assert_allowed`

## Development workflow

```bash
cd meshdrive-2.0
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[mcp]"
export MESHDRIVE_ROOT="$PWD/devroot"
# prepare devroot — see docs/development.md
meshdrive-agent   # terminal 1
meshdrive-tui     # terminal 2
```

```bash
python3 -m compileall -q src
```

## Pull requests

- Focused diffs — one concern per PR when possible
- Match existing code style and naming
- Update documentation in `docs/` when behavior changes
- Linux VM testing for packaging, FUSE, WireGuard — see [docs/TESTING.md](docs/TESTING.md)

## Monorepo note

This package lives in the `shabdabhav` monorepo alongside:

- `infra/wireguard-hub-spoke/` — WireGuard hub tooling
- `vix_package/` — VIX C++ gateway/FUSE sources

If publishing `meshdrive-2.0` as a standalone GitHub repo, vendor or submodule those dependencies as needed.

## Questions

Open a GitHub issue with `meshdrive doctor --json` output and relevant `journalctl` logs.
