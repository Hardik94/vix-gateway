# Privacy Policy — MeshDrive MCP (local connector)

**Last updated:** 2026-03-15  
**Product:** MeshDrive local MCP server (`meshdrive-mcp`)  
**Scope:** Local / self-hosted connector (Claude Code, Cursor, and future Claude Connectors)

This text is intended for Connectors Directory `privacy_policies` and a README
“Privacy Policy” section. Replace contact URLs before submission.

## Summary

MeshDrive is a **local-first** storage agent. The MCP server runs on **your
machine** (typically `127.0.0.1`). It does **not** upload your files to
MeshDrive cloud by default. AI clients (Claude, Cursor, etc.) only receive
file contents that **you** allow the model to request through MCP tools, and
only for paths inside configured **JuiceFS storage buckets**.

## Data MeshDrive processes

| Data | Where it lives | Shared with Anthropic / Claude? |
|------|----------------|----------------------------------|
| Files under JuiceFS mounts | Your disk / `$MESHDRIVE_ROOT` | Only if the AI client sends tool results to the model provider |
| `auth.yaml` / license / config | `$MESHDRIVE_ROOT/etc` | **Not** exposed via MCP file tools |
| MCP bearer tokens | Local credentials file | Not sent to MeshDrive SaaS; you paste into the client |
| Optional OpenTelemetry | Local files / your collector | Off by default; see config |
| Optional paid WireGuard / LDAP | Your control plane | Separate product surface |

## What we do not do (local MCP)

- We do not require a MeshDrive account for free local MCP.
- We do not scrape your home directory; MCP file tools are limited to storage
  bucket mounts under the MeshDrive isolation policy.
- We do not sell personal data.

## Third parties

When you use Claude.ai, Claude Code, Cursor, or another MCP host, **that
host’s** privacy policy applies to prompts and tool results they transmit to
model APIs. MeshDrive cannot prevent a connected LLM product from sending
tool output to its cloud. Use local models or disable MCP if that is unacceptable.

## Security controls

- Path isolation (`assert_storage_path`)
- Optional OpenFGA authorization (`agent:mcp` / per-token subject)
- Loopback-oriented MCP SSE bind (`127.0.0.1`) by default

See `benchmark/docs/methodology.md` for how unauthorized access is tested.

## Contact

- Security / privacy: **security@example.com** (replace before publish)
- Project docs: repository `meshdrive-2.0/docs/`

## Changes

We may update this policy as Connectors transport/auth evolves. Material
changes will bump the date above and the connector manifest version.
