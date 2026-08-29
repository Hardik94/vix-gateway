# WireGuard client (paid)

MeshDrive integrates the hub-spoke WireGuard design from [`infra/wireguard-hub-spoke/`](../../infra/wireguard-hub-spoke/) as a **paid client module**. It does not replace hub-side operations — peers are generated on the hub, clients apply configs locally.

## Prerequisites

1. Paid license activated: `meshdrive license activate --token …`
2. WireGuard add-on installed: `meshdrive addons install wireguard`
3. Hub operator generated a client config (see below)

## Client workflow

```bash
# 1) OS packages (once per machine)
sudo meshdrive wireguard bootstrap

# 2) Apply hub-generated config
sudo meshdrive wireguard apply --file /path/to/wg0.conf

# 3) Start tunnel
sudo meshdrive wireguard up

# 4) Verify
meshdrive wireguard status
ping -c2 10.200.22.1
nc -zv ldap.internal.example 389
```

## Commands

| Command | Root required | Description |
|---------|---------------|-------------|
| `wireguard bootstrap` | Yes | Runs `bootstrap-wg-debian.sh client` from hub-spoke infra |
| `wireguard apply --file PATH` | Yes | Copies config to `/etc/wireguard/wg0.conf` (mode 600), patches nft template, enables unit |
| `wireguard up` | Yes | `systemctl enable --now wg-quick@wg0` |
| `wireguard down` | Yes | Stops `wg-quick@wg0` |
| `wireguard status` | No | Runs `wg show`, prints state file, pings hub |

Optional flags on `apply`:

- `--v4` / `--v6` — override inner addresses for nftables template (auto-detected from `Address=` in wg0.conf when omitted)

## What `apply` does

1. Validates paid license
2. Copies `wg0.conf` → `/etc/wireguard/wg0.conf` (0600)
3. Patches `THIS_V4` / `THIS_V6` in nftables template
4. Writes `/etc/nftables.d/meshdrive-wg-client.nft` and runs `nft -f`
5. Saves state to `$ROOT/var/wireguard/state.json`
6. Enables `wg-quick@wg0.service`

**Private keys never enter git** — configs come from the hub control plane or secure transfer.

## Shipped templates

Under `$ROOT/share/wireguard/`:

| File | Purpose |
|------|---------|
| `wg0.conf.template` | Spoke peer template (placeholders for keys/IPs) |
| `nft-client.nft` | Client firewall rules (SIT: `10.200.22.0/24`) |
| `environment-ip-plan.md` | Copied from hub-spoke docs when available |

Install-time staging: `packaging/stage-wireguard.sh`.

## SIT IP plan

Staging/integration environment uses:

- IPv4 overlay: `10.200.22.0/24`
- Hub: `10.200.22.1`
- LDAP VM: `10.200.22.2`
- Spoke example: `10.200.22.10`

Full plan: [`infra/wireguard-hub-spoke/docs/environment-ip-plan.md`](../../infra/wireguard-hub-spoke/docs/environment-ip-plan.md).

## Hub-side peer generation (ops)

Run on the **hub**, not the client:

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

Deliver the rendered `wg0.conf` to the customer securely.

## nftables rules

Client nft template restricts WireGuard interface traffic:

- **Input:** established connections; TCP 9000/636 from overlay (JuiceFS/LDAPS peer traffic)
- **Output:** DNS to hub; LDAP 389/636 to LDAP VM; overlay peer ports

Addresses are patched at apply time to match the spoke's inner IPs.

## Snap note

Classic snap delegates WireGuard to the **host** network stack. `bootstrap` and `apply` still write to `/etc/wireguard/` on the host — run with `sudo snap run meshdrive -- wireguard …` or use the host-installed CLI wrapper.

## Troubleshooting

| Issue | Check |
|-------|-------|
| `require_addon` error | `meshdrive license status` — tier must be `paid` |
| `wg-quick not found` | Run `sudo meshdrive wireguard bootstrap` |
| No handshake | Hub endpoint/firewall, correct `Endpoint=` in config |
| LDAP unreachable | WG up, hub DNS (`10.200.22.1`), nft rules applied |
| Permission denied on apply | Use `sudo` |

Logs:

```bash
sudo journalctl -u wg-quick@wg0 -b --no-pager
sudo wg show
cat /opt/meshdrive/var/wireguard/state.json
```

## Next steps

After WireGuard is up, configure paid cluster features: [paid-cluster.md](paid-cluster.md).
