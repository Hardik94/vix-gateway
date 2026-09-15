#!/usr/bin/env python3
"""MeshDrive MCP isolation benchmark — unauthorized blocking + false positives.

Sets MESHDRIVE_ROOT before importing meshdrive when --fixture is used.

Examples
--------
  PYTHONPATH=src python3 benchmark/runner/run_isolation_bench.py --fixture
  PYTHONPATH=src python3 benchmark/runner/run_isolation_bench.py \\
    --out benchmark/results/live.json --markdown benchmark/results/live.md
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BENCH_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCENARIOS = BENCH_ROOT / "scenarios"


def _expand(value: Any, *, root: Path, mount: Path) -> Any:
    if isinstance(value, str):
        return (
            value.replace("{{ROOT}}", str(root))
            .replace("{{MOUNT}}", str(mount))
            .replace("\u0000", "\x00")
        )
    if isinstance(value, dict):
        return {k: _expand(v, root=root, mount=mount) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v, root=root, mount=mount) for v in value]
    return value


def _write_fixture(root: Path) -> Path:
    """Minimal MeshDrive tree with one fake 'JuiceFS' mount (plain directory)."""
    mount = root / "mnt" / "bench"
    (root / "etc").mkdir(parents=True)
    (root / "var" / "log").mkdir(parents=True)
    mount.mkdir(parents=True)
    (mount / "safe.txt").write_text("benchmark-ok\n", encoding="utf-8")
    (root / "etc" / "auth.yaml").write_text("users: {}\n", encoding="utf-8")
    (root / "etc" / "license.yaml").write_text("tier: free\n", encoding="utf-8")
    (root / "etc" / "config.yaml").write_text(
        f"""meshdrive:
  version: "2.3.9"
  mode: local
  isolation:
    allowed_paths:
      - "{root}"
  storage:
    backends:
      - name: bench
        type: juicefs
        mount_point: "{mount}"
        capacity_gb: 1
  mcp:
    enabled: true
    status: installed
  openfga:
    enabled: false
    status: not_installed
""",
        encoding="utf-8",
    )
    return mount


def _load_cases(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("cases") or [])


def _is_deny(exc: BaseException | None, result: Any) -> bool:
    if exc is None:
        return False
    if isinstance(exc, PermissionError):
        return True
    # Forbidden / unknown tools surface as PermissionError or KeyError
    if isinstance(exc, KeyError):
        return True
    # OS / pathlib reject null bytes before open — still a successful block
    if isinstance(exc, (ValueError, OSError)):
        msg = str(exc).lower()
        if "null" in msg or "outside" in msg or "denied" in msg:
            return True
    msg = str(exc).lower()
    return "denied" in msg or "not accessible" in msg or "outside" in msg


def _run_case(
    dispatch,
    case: dict[str, Any],
    *,
    root: Path,
    mount: Path,
) -> dict[str, Any]:
    tool = case["tool"]
    args = _expand(case.get("arguments") or {}, root=root, mount=mount)
    expect = case.get("expect", "deny")
    t0 = time.perf_counter()
    exc: BaseException | None = None
    result: Any = None
    try:
        result = dispatch(tool, args)
    except BaseException as err:  # noqa: BLE001 — capture all for bench
        exc = err
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    denied = _is_deny(exc, result)
    if expect == "deny":
        ok = denied
        outcome = "blocked" if denied else "ATTACK_SUCCEEDED"
    else:
        ok = exc is None
        outcome = "allowed" if ok else "false_positive_or_error"

    return {
        "id": case.get("id"),
        "tool": tool,
        "category": case.get("category"),
        "expect": expect,
        "ok": ok,
        "outcome": outcome,
        "elapsed_ms": round(elapsed_ms, 4),
        "error": None if exc is None else f"{type(exc).__name__}: {exc}",
        "rationale": case.get("rationale"),
    }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    unauth = [r for r in rows if r["expect"] == "deny"]
    allow = [r for r in rows if r["expect"] == "allow"]
    blocked = sum(1 for r in unauth if r["ok"])
    attack_ok = sum(1 for r in unauth if not r["ok"])
    allow_ok = sum(1 for r in allow if r["ok"])
    fp = sum(1 for r in allow if not r["ok"])
    latencies = [r["elapsed_ms"] for r in rows]

    def pct(n: int, d: int) -> float:
        return round(100.0 * n / d, 2) if d else 0.0

    return {
        "unauthorized_total": len(unauth),
        "blocked_unauthorized": blocked,
        "blocked_rate_pct": pct(blocked, len(unauth)),
        "attack_success_count": attack_ok,
        "attack_success_rate_pct": pct(attack_ok, len(unauth)),
        "allowed_total": len(allow),
        "allowed_ok": allow_ok,
        "false_positive_count": fp,
        "false_positive_rate_pct": pct(fp, len(allow)),
        "latency_ms": {
            "count": len(latencies),
            "p50": round(statistics.median(latencies), 4) if latencies else None,
            "p95": round(
                statistics.quantiles(latencies, n=20)[18], 4
            )
            if len(latencies) >= 20
            else (max(latencies) if latencies else None),
            "mean": round(statistics.mean(latencies), 4) if latencies else None,
        },
        "pass": attack_ok == 0 and fp == 0,
    }


def _markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        f"# MeshDrive isolation benchmark — {report['timestamp']}",
        "",
        f"- **meshdrive_version:** {report.get('meshdrive_version')}",
        f"- **root:** `{report.get('root')}`",
        f"- **fixture:** {report.get('fixture')}",
        f"- **pass:** **{s['pass']}**",
        "",
        "## Metrics",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Blocked unauthorized | {s['blocked_unauthorized']} / {s['unauthorized_total']} ({s['blocked_rate_pct']}%) |",
        f"| Attack success rate | {s['attack_success_rate_pct']}% (goal 0%) |",
        f"| False positives | {s['false_positive_count']} / {s['allowed_total']} ({s['false_positive_rate_pct']}%) |",
        f"| Latency p50 / p95 (ms) | {s['latency_ms'].get('p50')} / {s['latency_ms'].get('p95')} |",
        "",
        "## Cases",
        "",
        "| id | expect | outcome | ms | error |",
        "|----|--------|---------|----|-------|",
    ]
    for r in report["cases"]:
        err = (r.get("error") or "").replace("|", "/")[:80]
        lines.append(
            f"| {r['id']} | {r['expect']} | {r['outcome']} | {r['elapsed_ms']} | {err} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture",
        action="store_true",
        help="Create a temp MESHDRIVE_ROOT with a fake bucket mount",
    )
    parser.add_argument(
        "--root",
        default="",
        help="MESHDRIVE_ROOT (default: env or /opt/meshdrive)",
    )
    parser.add_argument(
        "--scenarios-dir",
        default=str(DEFAULT_SCENARIOS),
        help="Directory with unauthorized.json and allowed.json",
    )
    parser.add_argument("--out", default="", help="Write JSON report path")
    parser.add_argument("--markdown", default="", help="Write Markdown summary path")
    parser.add_argument(
        "--keep-fixture",
        action="store_true",
        help="Do not delete temp fixture directory",
    )
    args = parser.parse_args(argv)

    tmp_ctx = None
    if args.fixture:
        tmp_ctx = tempfile.TemporaryDirectory(prefix="meshdrive-bench-")
        root = Path(tmp_ctx.name)
        mount = _write_fixture(root)
        os.environ["MESHDRIVE_ROOT"] = str(root)
    else:
        root = Path(args.root or os.environ.get("MESHDRIVE_ROOT") or "/opt/meshdrive")
        os.environ["MESHDRIVE_ROOT"] = str(root)
        # Prefer first configured mount; fall back to mnt/bench for templates
        mount = root / "mnt" / "bench"
        cfg_path = root / "etc" / "config.yaml"
        if cfg_path.is_file():
            try:
                import yaml

                cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
                backends = (
                    (cfg.get("meshdrive") or {}).get("storage") or {}
                ).get("backends") or []
                if backends and backends[0].get("mount_point"):
                    mount = Path(backends[0]["mount_point"])
            except Exception:
                pass

    # Import only after MESHDRIVE_ROOT is set
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
    # Drop cached meshdrive modules if any (dev shells)
    for name in list(sys.modules):
        if name == "meshdrive" or name.startswith("meshdrive."):
            del sys.modules[name]

    from meshdrive import __version__
    from meshdrive.mcp.server import dispatch

    scen = Path(args.scenarios_dir)
    cases = _load_cases(scen / "unauthorized.json") + _load_cases(scen / "allowed.json")

    # Skip mount-required allow cases if mount missing (live mode without bucket)
    filtered: list[dict[str, Any]] = []
    skipped: list[str] = []
    for case in cases:
        if case.get("requires_mount") and not mount.exists():
            skipped.append(case["id"])
            continue
        # Expand templates that need ROOT even when mount missing
        filtered.append(case)

    rows = [_run_case(dispatch, c, root=root, mount=mount) for c in filtered]
    summary = _summarize(rows)
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "meshdrive_version": __version__,
        "root": str(root),
        "mount": str(mount),
        "fixture": bool(args.fixture),
        "skipped_requires_mount": skipped,
        "summary": summary,
        "cases": rows,
    }

    text = json.dumps(report, indent=2) + "\n"
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(text)

    if args.markdown:
        md_path = Path(args.markdown)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(_markdown(report), encoding="utf-8")
        print(f"wrote {md_path}")

    print(
        f"pass={summary['pass']} ASR={summary['attack_success_rate_pct']}% "
        f"FPR={summary['false_positive_rate_pct']}% "
        f"blocked={summary['blocked_unauthorized']}/{summary['unauthorized_total']}"
    )

    if tmp_ctx is not None and not args.keep_fixture:
        tmp_ctx.cleanup()
    elif tmp_ctx is not None and args.keep_fixture:
        print(f"fixture kept at {root}")
        tmp_ctx.cleanup = lambda: None  # type: ignore[method-assign]

    return 0 if summary["pass"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc()
        raise SystemExit(2)
