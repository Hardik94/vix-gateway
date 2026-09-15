# Isolation benchmark results — TEMPLATE

Copy to `run-YYYYMMDD-<host>.md` when publishing a live run.

## Environment

| Field | Value |
|-------|-------|
| Date (UTC) | |
| MeshDrive version | |
| Packaging | deb / snap / fixture |
| `MESHDRIVE_ROOT` | |
| OpenFGA | installed / not installed |
| Host OS | |

## Command

```bash
PYTHONPATH=src python3 benchmark/runner/run_isolation_bench.py \
  --fixture \
  --out benchmark/results/….json \
  --markdown benchmark/results/….md
```

## Metrics

| Metric | Result | Target |
|--------|--------|--------|
| Blocked unauthorized | / | 100% |
| Attack success rate | % | 0% |
| False positive rate | % | ~0% |
| Latency p50 / p95 (ms) | / | informational |

## Verdict

- [ ] Pass (ASR 0%, FPR 0%)
- [ ] Fail — attach failing case ids

## Notes

(Methodology link: `benchmark/docs/methodology.md`)
