# Publishing MeshDrive to Claude’s Connectors Directory

Two paths exist today:

| Path | Status for MeshDrive | Notes |
|------|----------------------|--------|
| **Claude Code CLI (local stdio)** | **Works now** | `claude mcp add meshdrive -- …/meshdrive-mcp` |
| **Claude.ai / Desktop Connectors Directory** | **Not ready** | Needs Streamable HTTP + OAuth/DCR + annotations + privacy |

This doc is the gap analysis and checklist so packaging and the security
benchmark can proceed in parallel.

## Works today — local Claude Code

```bash
# After: meshdrive addons install mcp
claude mcp add meshdrive \
  --env MESHDRIVE_ROOT=/opt/meshdrive \
  -- /opt/meshdrive/bin/meshdrive-mcp
```

Snap:

```bash
claude mcp add meshdrive \
  --env MESHDRIVE_ROOT=/var/snap/meshdrive/common \
  -- snap run meshdrive.mcp
```

Details: [docs/mcp-clients.md](../../docs/mcp-clients.md).

---

## Connectors Directory — requirements vs MeshDrive

| Requirement | Spec | MeshDrive today | Work to ship |
|-------------|------|-----------------|--------------|
| **Transport** | **Streamable HTTP** (legacy HTTP+SSE deprecated) | stdio + **SSE** (`MESHDRIVE_MCP_TRANSPORT=sse` on `:9000`) | Add MCP **Streamable HTTP** endpoint; keep stdio for CLI |
| **Authentication** | **OAuth 2.0** + DCR + refresh | Bearer **MCP token** (`mcp credentials`) | Add OAuth authorization server or integrate IdP (e.g. Authelia); Dynamic Client Registration |
| **Tool annotations** | `title`, `readOnlyHint`, `destructiveHint`, … | Tools have name + description only | Extend `TOOL_SCHEMAS` / MCP `Tool` annotations in `mcp/server.py` |
| **Max tool result** | ~150k characters | Unbounded `read_file` | Cap / truncate with clear error |
| **Timeout** | 300s | No explicit client timeout contract | Document + avoid long blocking ops |
| **Security review** | Anthropic standards | Isolation + optional OpenFGA; bench in `benchmark/` | Publish ASR=0 results; threat model |
| **Test credentials** | Reviewer account | Local token via `meshdrive mcp credentials` | Hosted demo tenant or scripted fixture + token |
| **Public documentation** | Blog / help article by publish date | This benchmark + mcp docs | Public post linking methodology + results |
| **Public GitHub** | Required for plugins | Repo policy is yours | Ensure MeshDrive MCP sources are linkable |
| **Privacy policy** | README section + `privacy_policies` in manifest | Draft: [privacy-policy.md](privacy-policy.md) | Add README section; fill `manifest.json` |

### Draft manifest

See [../manifest/manifest.json.example](../manifest/manifest.json.example).

### Suggested engineering order

1. Tool annotations + result size limit (low risk, helps all clients).
2. Streamable HTTP transport alongside SSE.
3. OAuth 2.0 + DCR (hardest; Authelia / control-plane can issue tokens).
4. Hosted review environment + Connectors submission form.
5. Public blog: isolation architecture + `benchmark/results` ASR tables.

---

## Security narrative for reviewers

- **Enforcement point:** MCP server process on loopback, not the LLM.
- **Deny by default:** paths must resolve under a configured JuiceFS **mount**;
  install tree (`etc/`, `var/`) is not browsable via file tools.
- **Optional OpenFGA:** `agent:mcp` (or per-token subject) must have
  `reader`/`writer` on `storage_backend:*`.
- **Evidence:** run `benchmark/runner/run_isolation_bench.py --fixture` and
  attach JSON/MD (goal: **0% ASR**).

Do **not** claim Directory listing until Streamable HTTP + OAuth are done.
Do claim **local Claude Code / Cursor stdio** with isolation + published bench.
