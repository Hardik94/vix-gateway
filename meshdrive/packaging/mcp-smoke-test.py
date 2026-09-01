#!/usr/bin/env python3
"""Smoke-test MeshDrive MCP (stdio or SSE): list tools + call health_check.

Usage (on the MeshDrive host or a LAN client that can reach SSE):

  # SSE (same as Open WebUI / Hermes URL mode)
  /opt/meshdrive/venv/bin/python packaging/mcp-smoke-test.py \\
    --url http://127.0.0.1:9000/sse

  # stdio (same as Cursor / Hermes command mode)
  /opt/meshdrive/venv/bin/python packaging/mcp-smoke-test.py --stdio

Exit 0 = tools listed and health_check succeeded.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys


async def _run_sse(url: str) -> int:
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    print(f"[smoke] connecting SSE {url}")
    async with sse_client(url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = [t.name for t in listed.tools]
            print(f"[smoke] tools ({len(names)}): {', '.join(names)}")
            required = {
                "health_check",
                "list_storage_backends",
                "list_directory",
                "read_file",
                "write_file",
                "get_file_info",
                "get_storage_stats",
                "get_version",
            }
            missing = sorted(required - set(names))
            if missing:
                print(f"[smoke] FAIL missing tools: {missing}", file=sys.stderr)
                return 2
            result = await session.call_tool("health_check", {})
            texts = []
            for block in result.content:
                texts.append(getattr(block, "text", str(block)))
            payload = "\n".join(texts)
            print(f"[smoke] health_check => {payload}")
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                data = {}
            if result.isError or data.get("error"):
                print(f"[smoke] FAIL health_check error: {payload}", file=sys.stderr)
                return 3
            if not data.get("ok", True) and "error" in payload.lower():
                print(f"[smoke] FAIL unexpected health payload", file=sys.stderr)
                return 3
            backends = await session.call_tool("list_storage_backends", {})
            btext = "\n".join(getattr(b, "text", str(b)) for b in backends.content)
            print(f"[smoke] list_storage_backends => {btext[:500]}")
            print("[smoke] PASS — MCP protocol + tools work; if Open WebUI/Hermes chat still fails, the LLM/client is not issuing tool calls.")
            return 0


async def _run_stdio() -> int:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    cmd = os.environ.get("MESHDRIVE_MCP_BIN", "/opt/meshdrive/bin/meshdrive-mcp")
    root = os.environ.get("MESHDRIVE_ROOT", "/opt/meshdrive")
    params = StdioServerParameters(
        command=cmd,
        args=[],
        env={
            "MESHDRIVE_ROOT": root,
            "MESHDRIVE_MCP_TRANSPORT": "stdio",
            "PYTHONUNBUFFERED": "1",
        },
    )
    print(f"[smoke] connecting stdio {cmd}")
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = [t.name for t in listed.tools]
            print(f"[smoke] tools ({len(names)}): {', '.join(names)}")
            result = await session.call_tool("health_check", {})
            texts = [getattr(b, "text", str(b)) for b in result.content]
            print(f"[smoke] health_check => {texts}")
            if result.isError:
                return 3
            print("[smoke] PASS")
            return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="MeshDrive MCP smoke test")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--url", help="SSE URL, e.g. http://127.0.0.1:9000/sse")
    g.add_argument("--stdio", action="store_true", help="Spawn local meshdrive-mcp via stdio")
    args = parser.parse_args()
    try:
        import mcp  # noqa: F401
    except ImportError:
        print("Install mcp in this venv: pip install 'mcp>=1.2.0,<2'", file=sys.stderr)
        return 1
    try:
        if args.stdio:
            return asyncio.run(_run_stdio())
        return asyncio.run(_run_sse(args.url))
    except Exception as exc:
        print(f"[smoke] FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
