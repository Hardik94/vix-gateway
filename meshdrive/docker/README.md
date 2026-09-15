# Docker — MeshDrive from GitHub `.deb` (no source in the image)

Run MeshDrive on a Mac or any Docker host by **downloading the published Ubuntu
package** from GitHub Releases, then starting the agent in a container.

**Release used by default:** [Meshdrive v2.3.1](https://github.com/Hardik94/vix-gateway/releases/tag/v2.3.1)  
**Asset:** `meshdrive_2.3.1_amd64.deb`

This does **not** copy `meshdrive-2.0/src` into the image — only the release `.deb`.

## Requirements

| Item | Notes |
|------|--------|
| Docker Desktop / Engine | On Apple Silicon, image is `linux/amd64` (emulation) |
| Internet at **build** time | `curl` downloads the `.deb`; postinst fetches JuiceFS/Filebrowser + pip |
| FUSE | Compose uses `privileged` + `/dev/fuse` for JuiceFS mounts |

## Quick start

```bash
cd meshdrive-2.0/docker
cp .env.example .env   # optional
docker compose up --build
```

Wait until healthy, then:

```bash
curl -sS http://127.0.0.1:12700/health
docker exec -it meshdrive meshdrive doctor
docker exec -it meshdrive meshdrive-tui    # interactive TUI
```

Stop:

```bash
docker compose down
```

## What gets installed

1. Base: `ubuntu:24.04` + `fuse3`, `python3`, `curl`, …
2. `curl` → `https://github.com/Hardik94/vix-gateway/releases/download/v2.3.1/meshdrive_2.3.1_amd64.deb`
3. `dpkg -i` → `/opt/meshdrive` (postinst runs `setup-runtime.sh`; skips systemd when not present)
4. Entrypoint starts **`meshdrive-agent`** in the foreground (no systemd in the container)

## Ports

| Port | Service |
|------|---------|
| `12700` | Agent control API |
| `8080` | Filebrowser (after you create/mount storage in the TUI) |
| `9000` | MCP SSE (if you install the mcp addon) |

`MESHDRIVE_CONTROL_HOST=0.0.0.0` so published ports work from the Mac host. Use only on trusted lab networks.

## Optional MCP / OpenFGA

```bash
# in .env or shell
export MESHDRIVE_INSTALL_MCP=1
docker compose up --build
```

Or after start:

```bash
docker exec -it meshdrive meshdrive addons install mcp
docker exec -it meshdrive meshdrive addons install openfga
```

## Pin another release

```bash
export MESHDRIVE_VERSION=v2.3.1
export MESHDRIVE_DEB_VERSION=2.3.1
docker compose build --build-arg MESHDRIVE_VERSION=$MESHDRIVE_VERSION \
  --build-arg MESHDRIVE_DEB_VERSION=$MESHDRIVE_DEB_VERSION
```

Or override the full URL:

```bash
docker build -t meshdrive:2.3.1 \
  --build-arg DEB_URL=https://github.com/Hardik94/vix-gateway/releases/download/v2.3.1/meshdrive_2.3.1_amd64.deb \
  .
```

## Data persistence

Compose volumes:

- `meshdrive-var` → `/opt/meshdrive/var`
- `meshdrive-mnt` → `/opt/meshdrive/mnt`
- `meshdrive-etc` → `/opt/meshdrive/etc` (config / auth)

First boot with an empty `etc` volume may need default files from the package;
if the agent complains about missing config, recreate without the etc volume once
or copy from a fresh container:

```bash
docker run --rm meshdrive:2.3.1 tar -C /opt/meshdrive/etc -cf - . \
  | docker exec -i meshdrive tar -C /opt/meshdrive/etc -xf -
```

## Isolation benchmark (from your Mac, against the container)

The Python benchmark lives in the **git checkout** (not required inside the image).
Against a live agent you still use fixture mode on the host, or exec into a
dev tree. For “does the .deb agent answer?”:

```bash
curl -sS http://127.0.0.1:12700/health
```

## Limits vs bare-metal Ubuntu

- **No systemd** — mounts/addons that expect `systemctl` may need process-mode
  fallbacks (same as snap-style process starts for some addons).
- **FUSE in Docker** can be flaky on Docker Desktop; if mount fails, try
  Linux VM / cloud with the same `.deb`, or `privileged: true` (already set).
- **amd64-only** package — Apple Silicon runs via QEMU emulation (slower).

## Files

| File | Role |
|------|------|
| `Dockerfile` | Ubuntu 24.04 + download/install `.deb` |
| `entrypoint.sh` | Start `meshdrive-agent` |
| `docker-compose.yml` | Ports, FUSE, volumes |
| `.env.example` | Version / port knobs |
