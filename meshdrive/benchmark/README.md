# MeshDrive security & connectors benchmark

This directory documents how MeshDrive MCP enforces **filesystem-boundary** controls, how to **measure unauthorized request blocking**, and what is still required to publish MeshDrive to **Claude’s Connectors Directory**.

```text
benchmark/
├── README.md                 ← you are here
├── docs/
│   ├── methodology.md        ← metrics, scenario design, how to run
│   ├── claude-connectors.md  ← Connectors Directory checklist vs MeshDrive gaps
│   └── privacy-policy.md     ← local-connector privacy text (submission)
├── scenarios/
│   ├── unauthorized.json     ← escape / traversal / sensitive paths (must BLOCK)
│   └── allowed.json          ← in-bucket ops (must ALLOW)
├── runner/
│   └── run_isolation_bench.py
├── manifest/
│   └── manifest.json.example ← draft connector manifest fields
└── results/                  ← committed templates + gitignored live runs
    ├── TEMPLATE.md
    ├── baseline-fixture.json ← sample output from --fixture (CI-safe)
    └── .gitignore
```

## Quick start (CI-safe fixture)

No live JuiceFS mount required — the runner builds a temporary MeshDrive root:

```bash
cd meshdrive-2.0
PYTHONPATH=src python3 benchmark/runner/run_isolation_bench.py \
  --fixture \
  --out benchmark/results/run-$(date +%Y%m%d-%H%M%S).json \
  --markdown benchmark/results/run-$(date +%Y%m%d-%H%M%S).md
```

Requires MeshDrive deps on `PYTHONPATH` (at least `PyYAML`). Example:

```bash
python3 -m venv .venv-bench && .venv-bench/bin/pip install pyyaml
PYTHONPATH=src .venv-bench/bin/python benchmark/runner/run_isolation_bench.py --fixture
```

Against a real install:

```bash
export MESHDRIVE_ROOT=/opt/meshdrive   # or $SNAP_COMMON
PYTHONPATH=src python3 benchmark/runner/run_isolation_bench.py \
  --scenarios-dir benchmark/scenarios \
  --out benchmark/results/live.json
```

## What is measured

| Metric | Goal |
|--------|------|
| **Blocked unauthorized** | 100% of `unauthorized.json` cases raise `PermissionError` (or equivalent deny) |
| **Attack success rate (ASR)** | **0%** — no path outside JuiceFS buckets succeeds |
| **False positive rate** | Near **0%** on `allowed.json` when a bucket mount exists |
| **Overhead** | p50 / p95 latency of deny and allow paths (ms) |

OpenFGA is optional: when installed, the same runner can pass `--check-openfga` to assert `reader`/`writer` checks (see [methodology](docs/methodology.md)).

## Dual workstream

1. **Connectors packaging** — Streamable HTTP, OAuth/DCR, tool annotations, privacy policy, public docs → [claude-connectors.md](docs/claude-connectors.md)
2. **Security benchmark** — filesystem isolation + OpenFGA → this runner + published results

Local Claude Code today (stdio, no Directory listing required):

```bash
claude mcp add meshdrive --env MESHDRIVE_ROOT=/opt/meshdrive -- /opt/meshdrive/bin/meshdrive-mcp
```

See also: [docs/mcp.md](../docs/mcp.md), [docs/mcp-clients.md](../docs/mcp-clients.md).
