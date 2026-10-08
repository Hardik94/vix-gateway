# Licensing

MeshDrive 2.0 uses a **free local tier** and a **paid tier** unlocked by a license token. Paid features are enforced in the addon installer, CLI, WireGuard module, and cluster wizard.

There is **no** remote TiKV, shared MinIO, or ZeroTier on free installs.

## Tiers

| Capability | Free | Paid |
|------------|------|------|
| Local JuiceFS (sqlite) | Yes | Yes |
| Filebrowser (loopback) | Yes | Yes |
| Local users | Yes | Yes |
| MCP, OpenFGA, OTEL | Optional | Optional |
| WireGuard client | No | Yes |
| SSSD → LDAP over WG | No | Yes |
| Remote JuiceFS (TiKV/MinIO over WG) | No | Yes |
| VIX gateway + FUSE | No | Yes |

## License file

Path: **`$ROOT/etc/license.yaml`**

Created by activation. Stores tier, feature list, activation timestamp, and **token hash** — never the raw token.

Example:

```yaml
tier: paid
token_hash: "a1b2c3…"
activated_at: "2026-08-24T18:30:00+00:00"
features:
  - wireguard
  - vix_gateway
  - vix_fuse
  - sssd
  - remote_cluster
```

## Activation

```bash
meshdrive license activate --token "MESHDRIVE_…"
meshdrive license status
```

JSON output from `license status`:

```json
{
  "tier": "paid",
  "features": ["wireguard", "vix_gateway", "vix_fuse", "sssd", "remote_cluster"],
  "activated_at": "2026-08-24T18:30:00+00:00",
  "license_path": "/opt/meshdrive/etc/license.yaml"
}
```

Agent API equivalent:

```bash
curl -sS -X POST http://127.0.0.1:12700/license/activate \
  -H 'Content-Type: application/json' \
  -d '{"token":"MESHDRIVE_…"}'
```

## Feature → add-on mapping

| Feature key | Add-on CLI name |
|-------------|-----------------|
| `wireguard` | `wireguard` |
| `vix_gateway` | `vix-gateway` |
| `vix_fuse` | `vix-fuse` |
| `sssd` | `sssd-ldap` |
| `remote_cluster` | `remote-cluster` |

Free add-ons (`mcp`, `openfga`, `otel`) are never gated.

## Validation (implementation)

Logic in `src/meshdrive/license.py`:

0. **Online (preferred when configured):** if `MESHDRIVE_LICENSE_URL` is set, `POST` the token to the license service (`server/license/`). On success, store returned `tier` / `features` / `org_id` / `expires_at`.
1. **Dev tokens** (disabled when `MESHDRIVE_LICENSE_STRICT=1`):
   - `test-paid-token-dev`
   - `MESHDRIVE_PAID_DEV`
2. **Prefix tokens:** `MESHDRIVE_PAID_*` grants full paid feature set (non-strict builds accept unknown suffixes for staging)
3. **HMAC token:** HMAC-SHA256 of `"paid"` with `MESHDRIVE_LICENSE_SECRET`, truncated to 32 hex chars
4. **Strict mode:** unknown tokens rejected when `MESHDRIVE_LICENSE_STRICT=1`

Online entitlement service (control plane, not on the device): see [`../../authelia-fb-2.0/license/`](../../authelia-fb-2.0/license/) (docker service `license-api`).

```bash
export MESHDRIVE_LICENSE_STRICT=1
export MESHDRIVE_LICENSE_URL=https://filebrowser.workbook.local/v1/license/validate
meshdrive license activate --token "$TOKEN"
```

Production deployments should set:

```bash
export MESHDRIVE_LICENSE_SECRET="<long-random-secret>"
export MESHDRIVE_LICENSE_STRICT=1
```

## Gating behavior

When a paid add-on is requested without a valid license:

```bash
$ meshdrive addons install wireguard
Error: addon 'wireguard' requires a paid license (meshdrive license activate --token ...)
```

The TUI Add-ons tab shows **🔒 Paid — meshdrive license activate --token …** for locked rows.

WireGuard commands (`bootstrap`, `apply`, `up`, …) call `require_addon("wireguard")` and fail similarly.

## Testing

Use dev token in lab/CI (documented in [TESTING.md](TESTING.md)):

```bash
meshdrive license activate --token "test-paid-token-dev"
meshdrive addons install wireguard   # succeeds
```

## Future: online entitlement

The current implementation validates **offline** (HMAC/dev tokens). An optional online ping to an entitlement server can be added later without changing the on-disk `license.yaml` format.
