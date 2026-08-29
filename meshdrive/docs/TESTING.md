# MeshDrive 2.0 — Test plan

Step-by-step verification for `.deb`, snap, license gating, WireGuard lab, VIX, and isolation.

> **See also:** [Documentation index](README.md) · [Installation](installation.md) · [Troubleshooting](troubleshooting.md)

## Prerequisites

- Clean Ubuntu 22.04 or 24.04 VM (amd64), systemd, outbound HTTPS
- For WireGuard lab: hub VM with peer generated via `infra/wireguard-hub-spoke/scripts/gen-peer.sh`

Dev license token (non-strict builds): `test-paid-token-dev`

---

## A. Deb regression (Phase 0)

```bash
cd meshdrive-2.0/packaging && nfpm pkg -f nfpm.yaml --target ../dist/meshdrive_2.0.0_amd64.deb
sudo dpkg -i ../dist/meshdrive_2.0.0_amd64.deb

which meshdrive meshdrive-tui meshdrive-addons meshdrive-agent
meshdrive doctor
meshdrive status
sudo systemctl status meshdrive-agent
meshdrive addons list
meshdrive-tui   # Storage tab → add backend → mount → Filebrowser
curl -sS http://127.0.0.1:12700/health
curl -sS http://127.0.0.1:8080/     # after Filebrowser start
```

**Pass:** all four binaries on PATH; `meshdrive doctor` reports no missing CLI; TUI completes first storage wizard.

---

## B. Free-tier snap smoke

```bash
cd meshdrive-2.0/snap
snapcraft pack --use-lxd   # or --destructive-mode on CI VM
sudo snap install --dangerous meshdrive_2.0.0_amd64.snap

snap run meshdrive.doctor
snap run meshdrive.tui
meshdrive addons install mcp        # should work without license
meshdrive addons install wireguard  # must fail with license error
```

**Pass:** free addon installs; paid addon rejected with clear message.

---

## B2. Flatpak smoke (desktop / community bundle)

```bash
cd meshdrive-2.0
./flatpak/update-binary-sources.sh
flatpak-builder --user --install --force-clean .flatpak-build \
  flatpak/in.vistrix.MeshDrive.yaml
flatpak run --command=meshdrive in.vistrix.MeshDrive doctor
flatpak run in.vistrix.MeshDrive   # TUI

mkdir -p dist
flatpak build-bundle ~/.local/share/flatpak/repo \
  dist/meshdrive-2.0.0-x86_64.flatpak in.vistrix.MeshDrive
```

**Pass:** doctor OK; TUI opens; bundle installs on a second machine with `flatpak install --user ./meshdrive-*.flatpak`.

## C. License activation (mock)

```bash
meshdrive license activate --token "test-paid-token-dev"
meshdrive license status            # tier=paid
meshdrive addons install wireguard  # now allowed
```

---

## D. WireGuard lab (SIT)

Prerequisites: hub VM; client config from `gen-peer.sh` with SIT ranges (`10.200.22.0/24`).

```bash
meshdrive license activate --token "test-paid-token-dev"
sudo meshdrive wireguard bootstrap
sudo meshdrive wireguard apply --file ./customer-wg0.conf
sudo meshdrive wireguard up
meshdrive wireguard status
ping -c2 10.200.22.1
nc -zv ldap.internal.example 389
```

**Pass:** `wg show` OK; hub DNS resolves; LDAP port reachable over WG.

Hub-side peer generation (ops):

```bash
./infra/wireguard-hub-spoke/scripts/gen-peer.sh \
  --hub-pub "$(cat hub.pub)" \
  --endpoint HUB_PUBLIC_IP:51820 \
  --v4 10.200.22.10 \
  --v6 fde4:c0ff:ee22::10 \
  --allowed-ips-v4 10.200.22.0/24 \
  --allowed-ips-v6 fde4:c0ff:ee22::/64 \
  --dns 10.200.22.1 \
  --name customer-001
```

---

## E. VIX gateway local

```bash
meshdrive license activate --token "test-paid-token-dev"
meshdrive addons install vix-gateway
curl --http3-only -k https://127.0.0.1:9443/health || curl -k https://127.0.0.1:9443/health
```

Note: binaries require `packaging/build-vix.sh` on a Linux host with cmake/Rust.

---

## F. Paid full stack (staging)

```bash
meshdrive license activate --token "test-paid-token-dev"
sudo meshdrive addons install sssd-ldap remote-cluster
sudo meshdrive cluster configure \
  --ldap-url ldap://ldap.internal.example \
  --ldap-base dc=meshdrive,dc=local \
  --metadata-url tikv://10.200.22.3:2379/volume
meshdrive addons install vix-fuse
```

**Pass:** SSSD config present; remote backend in `config.yaml`; FUSE unit configured.

---

## G. Isolation checks

```bash
test ! -d "$HOME/.config/meshdrive" && echo "OK: no home config"
# MCP read_file on /etc/passwd → denied (when MCP installed)
# MCP read_file under /opt/meshdrive/mnt/primary/... → allowed
```

Snap installs use `$SNAP_COMMON` (e.g. `/var/snap/meshdrive/common`) instead of `/opt/meshdrive`; same subtree layout.

---

## CI notes

- `nfpm pkg` and Python syntax checks run on any OS
- `snapcraft pack` requires Ubuntu + LXD or destructive mode
- `flatpak-builder` requires Flatpak SDK 24.08 + `./flatpak/update-binary-sources.sh`
- VIX build (`packaging/build-vix.sh`) requires Linux + cmake
- WireGuard integration tests are manual against SIT hub
