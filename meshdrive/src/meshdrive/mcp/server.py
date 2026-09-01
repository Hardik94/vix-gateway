"""MCP stdio/SSE server. File tools stay inside /opt/meshdrive. No user admin tools."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from meshdrive import __version__
from meshdrive.config import backends, load_config, root
from meshdrive.constants import ROOT
from meshdrive.paths import assert_allowed, is_path_allowed
from meshdrive.storage.juicefs import disk_stats, is_mounted

FORBIDDEN = frozenset(
    {
        "create_user",
        "delete_user",
        "change_permissions",
        "system_config",
        "auth.add_user",
        "auth.users",
    }
)

MCP_USER = "agent:mcp"

# Meta tools — no OpenFGA object; isolation still enforced in handlers when paths are used.
OPENFGA_SKIP = frozenset({"health_check", "get_version", "list_storage_backends"})


def _tool_permission(name: str) -> str:
    writes = {"write_file", "create_directory", "move_file", "delete_file", "mount_backend"}
    return "writer" if name in writes else "reader"


def _backend_for_path(path: str) -> str | None:
    """Return storage backend name if path is under that backend's mount_point."""
    try:
        target = Path(path).expanduser().resolve()
    except OSError:
        return None
    for item in backends():
        mount = item.get("mount_point") or ""
        if not mount:
            continue
        try:
            target.relative_to(Path(mount).resolve())
            name = item.get("name")
            return str(name) if name else None
        except (ValueError, OSError):
            continue
    return None


def _authorize(name: str, arguments: dict[str, Any]) -> None:
    if name in FORBIDDEN:
        raise PermissionError("function is not accessible via MCP")
    if name in OPENFGA_SKIP:
        return
    try:
        from meshdrive.addons import openfga
    except Exception:
        return
    if not openfga.available():
        return

    relation = _tool_permission(name)
    backend_name = arguments.get("backend_name")
    path = arguments.get("path")

    # Prefer storage_backend checks — that is what bootstrap grants (agent:mcp reader/writer).
    if backend_name and not path:
        object_id = f"storage_backend:{backend_name}"
    elif path:
        backend = _backend_for_path(str(path))
        if backend:
            object_id = f"storage_backend:{backend}"
        else:
            # Path under ROOT but not a mounted backend: isolation only (no FGA object).
            assert_allowed(path)
            return
    else:
        return

    if not openfga.check(MCP_USER, relation, object_id):
        raise PermissionError(f"OpenFGA denied {relation} on {object_id}")


def list_storage_backends() -> list[dict[str, Any]]:
    cfg = load_config()
    rows = []
    for item in backends(cfg):
        mount = item.get("mount_point") or ""
        stats = disk_stats(mount) if mount else {}
        rows.append(
            {
                "name": item.get("name"),
                "mount_point": mount,
                "mounted": is_mounted(mount) if mount else False,
                "usage_percent": stats.get("usage_percent"),
                "free_bytes": stats.get("free_bytes"),
            }
        )
    return rows


def get_storage_stats(backend_name: str) -> dict[str, Any]:
    for item in backends():
        if item.get("name") == backend_name:
            return disk_stats(item.get("mount_point") or item.get("data_path") or ROOT)
    raise KeyError(f"unknown backend {backend_name!r}")


def read_file(path: str, encoding: str = "utf-8") -> dict[str, Any]:
    target = assert_allowed(path)
    if not target.is_file():
        raise FileNotFoundError(str(target))
    data = target.read_text(encoding=encoding)
    return {"path": str(target), "size": len(data), "content": data}


def write_file(path: str, content: str) -> dict[str, Any]:
    target = assert_allowed(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {"path": str(target), "size": len(content)}


def list_directory(path: str) -> dict[str, Any]:
    target = assert_allowed(path)
    if not target.is_dir():
        raise NotADirectoryError(str(target))
    entries = []
    for child in sorted(target.iterdir()):
        if not is_path_allowed(child):
            continue
        entries.append(
            {
                "name": child.name,
                "path": str(child),
                "type": "dir" if child.is_dir() else "file",
            }
        )
    return {"path": str(target), "entries": entries}


def get_file_info(path: str) -> dict[str, Any]:
    target = assert_allowed(path)
    if not target.exists():
        raise FileNotFoundError(str(target))
    st = target.stat()
    return {
        "path": str(target),
        "type": "dir" if target.is_dir() else "file",
        "size": st.st_size,
        "mtime": int(st.st_mtime),
    }


def health_check() -> dict[str, Any]:
    md = root()
    return {
        "ok": True,
        "version": __version__,
        "root": str(ROOT),
        "mcp": md.get("mcp", {}).get("status"),
        "openfga": md.get("openfga", {}).get("status"),
    }


HANDLERS = {
    "list_storage_backends": lambda args: list_storage_backends(),
    "get_storage_stats": lambda args: get_storage_stats(args["backend_name"]),
    "read_file": lambda args: read_file(args["path"], args.get("encoding", "utf-8")),
    "write_file": lambda args: write_file(args["path"], args["content"]),
    "list_directory": lambda args: list_directory(args["path"]),
    "get_file_info": lambda args: get_file_info(args["path"]),
    "health_check": lambda args: health_check(),
    "get_version": lambda args: {"version": __version__},
}

TOOL_SCHEMAS = {
    "list_storage_backends": ("List configured JuiceFS backends", {}),
    "get_storage_stats": (
        "Disk stats for a storage backend",
        {"backend_name": {"type": "string"}},
        ["backend_name"],
    ),
    "read_file": (
        "Read a UTF-8 file inside /opt/meshdrive",
        {"path": {"type": "string"}, "encoding": {"type": "string"}},
        ["path"],
    ),
    "write_file": (
        "Write a UTF-8 file inside /opt/meshdrive",
        {"path": {"type": "string"}, "content": {"type": "string"}},
        ["path", "content"],
    ),
    "list_directory": (
        "List a directory inside /opt/meshdrive",
        {"path": {"type": "string"}},
        ["path"],
    ),
    "get_file_info": (
        "Stat a file or directory inside /opt/meshdrive",
        {"path": {"type": "string"}},
        ["path"],
    ),
    "health_check": ("MeshDrive MCP health", {}),
    "get_version": ("MeshDrive version", {}),
}


def dispatch(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    args = arguments or {}
    _authorize(name, args)
    if name not in HANDLERS:
        raise KeyError(f"unknown tool {name}")
    return HANDLERS[name](args)


def _tools():
    from mcp.types import Tool

    tools = []
    for name, spec in TOOL_SCHEMAS.items():
        description = spec[0]
        props = spec[1] if len(spec) > 1 else {}
        required = list(spec[2]) if len(spec) > 2 else []
        tools.append(
            Tool(
                name=name,
                description=description,
                inputSchema={
                    "type": "object",
                    "properties": props,
                    "required": required,
                },
            )
        )
    return tools


async def _run_stdio() -> None:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent
    import logging

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log = logging.getLogger("meshdrive.mcp")
    server = Server("meshdrive-mcp")

    @server.list_tools()
    async def handle_list_tools():
        tools = _tools()
        log.info("ListToolsRequest -> %s tools", len(tools))
        return tools

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):
        log.info("CallToolRequest name=%s args_keys=%s", name, sorted((arguments or {}).keys()))
        try:
            result = dispatch(name, arguments)
            payload = json.dumps(result, default=str)
            log.info("CallToolResult name=%s ok bytes=%s", name, len(payload))
        except Exception as exc:
            log.exception("CallToolResult name=%s error=%s", name, exc)
            payload = json.dumps({"error": str(exc)})
        return [TextContent(type="text", text=payload)]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


async def _run_sse() -> None:
    from mcp.server import Server
    from mcp.server.sse import SseServerTransport
    from mcp.types import TextContent
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    import logging
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log = logging.getLogger("meshdrive.mcp")

    host = os.environ.get("MESHDRIVE_MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("MESHDRIVE_MCP_PORT", "9000"))
    sse = SseServerTransport("/messages/")
    server = Server("meshdrive-mcp")

    @server.list_tools()
    async def handle_list_tools():
        tools = _tools()
        log.info("ListToolsRequest -> %s tools", len(tools))
        return tools

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):
        log.info("CallToolRequest name=%s args_keys=%s", name, sorted((arguments or {}).keys()))
        try:
            result = dispatch(name, arguments)
            payload = json.dumps(result, default=str)
            log.info("CallToolResult name=%s ok bytes=%s", name, len(payload))
        except Exception as exc:
            log.exception("CallToolResult name=%s error=%s", name, exc)
            payload = json.dumps({"error": str(exc)})
        return [TextContent(type="text", text=payload)]

    async def handle_sse(request):
        log.info("SSE connect from %s", request.client)
        async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
            await server.run(streams[0], streams[1], server.create_initialization_options())

    async def handle_ready(_request):
        return JSONResponse(
            {
                "ok": True,
                "transport": "sse",
                "sse": "/sse",
                "messages": "/messages/",
                "tools": list(TOOL_SCHEMAS.keys()),
                "note": "GET /sse only; POST client messages to /messages/?session_id=…",
            }
        )

    app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse, methods=["GET"]),
            Route("/ready", endpoint=handle_ready, methods=["GET"]),
            Mount("/messages/", app=sse.handle_post_message),
        ]
    )
    log.info("MeshDrive MCP SSE listening on http://%s:%s/sse", host, port)
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    await uvicorn.Server(config).serve()


def main() -> int:
    import asyncio

    transport = os.environ.get("MESHDRIVE_MCP_TRANSPORT", "stdio").lower()
    try:
        import mcp  # noqa: F401
        from importlib.metadata import PackageNotFoundError, version

        try:
            ver = version("mcp")
            major = int(ver.split(".", 1)[0])
        except (PackageNotFoundError, ValueError, IndexError):
            major = 0
        if major >= 2:
            print(
                "Unsupported mcp package version "
                f"{ver!r}: MeshDrive requires mcp>=1.2.0,<2 "
                "(SDK 2.x removed Server.list_tools). Fix with:\n"
                "  /opt/meshdrive/venv/bin/pip install 'mcp>=1.2.0,<2'\n"
                "  meshdrive addons install mcp",
                flush=True,
            )
            return 1
    except ImportError:
        print(
            "MCP add-on is not installed. Run: sudo meshdrive-addons install mcp",
            flush=True,
        )
        return 1
    if transport == "sse":
        asyncio.run(_run_sse())
    else:
        asyncio.run(_run_stdio())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
