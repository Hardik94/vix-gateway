# Benchmark methodology — unauthorized request blocking

## Goal

Prove MeshDrive MCP enforces **least privilege at the filesystem boundary**
(`assert_storage_path` / OpenFGA), not via prompt filters. Target:

| Metric | Target |
|--------|--------|
| Attack success rate (ASR) | **0%** |
| Blocked unauthorized rate | **100%** |
| False positive rate (FPR) | **~0%** on allowed in-bucket ops |
| Deny-path overhead | typically **&lt; 5 ms** in fixture runs (informational) |

## Control plane under test

```text
LLM / Claude / Cursor
        │  MCP tools/call
        ▼
 meshdrive-mcp  ──►  _authorize()  ──►  OpenFGA (optional)
        │                 │
        │                 └─ reader|writer on storage_backend:*
        ▼
 assert_storage_path()  ── path must be under a JuiceFS mount
        ▼
 filesystem op
```

The LLM never calls OpenFGA. MCP checks OpenFGA (if installed), then isolation.

## Scenario sources (adapted)

| Source | How we use it |
|--------|----------------|
| **AuthBench** | Sensitive / cross-boundary tasks → `unauthorized.json` categories `secret_exfiltration`, `privilege_escalation` |
| **SandboxEscapeBench** | Traversal, absolute paths, host writes → `path_traversal`, `sandbox_escape` |
| **Agent Safety Eval** | Secret exfil + privilege escalation tool names → forbidden MCP tools |

We do **not** claim to run the full upstream suites unchanged. We map their
threat classes onto MeshDrive’s concrete deny surface.

## How to run

### Fixture (no JuiceFS, CI-safe)

```bash
cd meshdrive-2.0
PYTHONPATH=src python3 benchmark/runner/run_isolation_bench.py \
  --fixture \
  --out benchmark/results/run.json \
  --markdown benchmark/results/run.md
```

Exit code `0` = pass (ASR 0%, FPR 0%).

### Live install

```bash
export MESHDRIVE_ROOT=/opt/meshdrive   # snap: $SNAP_COMMON
# Ensure at least one backend is mounted (TUI → Storage)
PYTHONPATH=src python3 benchmark/runner/run_isolation_bench.py \
  --out benchmark/results/live-$(hostname)-$(date +%Y%m%d).json \
  --markdown benchmark/results/live-$(hostname)-$(date +%Y%m%d).md
```

Cases with `"requires_mount": true` are skipped if no mount exists (recorded in
`skipped_requires_mount`).

## Publishing results

1. Commit **methodology** + **scenario JSON** (this tree).
2. Store dated JSON/MD under `benchmark/results/` (live runs are gitignored by
   default; keep `baseline-fixture.json` as a checked-in sample).
3. Summarize ASR / FPR / latency in a blog or README section — this supports
   Claude Connectors “public documentation” and security review.

Use [results/TEMPLATE.md](../results/TEMPLATE.md) for human-readable write-ups.

## OpenFGA (optional second gate)

When `meshdrive addons install openfga` has bootstrapped:

- Subject defaults to `agent:mcp` (SSE tokens may map to another subject).
- Write tools need `writer` on `storage_backend:<name>`; reads need `reader`.
- Meta tools skip OpenFGA (`health_check`, `get_version`, `list_storage_backends`).

A future `--check-openfga` mode can revoke tuples and assert deny; today the
isolation bench is the primary ASR measurement and does not require OpenFGA.

## What this does *not* cover

- Prompt injection that tricks the *model* into calling only allowed tools
  with attacker-chosen in-bucket paths (data poisoning inside the bucket).
- Network egress from the host.
- Claude.ai remote Connectors OAuth (see [claude-connectors.md](claude-connectors.md)).

Those belong in separate threat models; this benchmark focuses on **boundary
enforcement** when a tool call already includes a hostile path or forbidden tool name.
