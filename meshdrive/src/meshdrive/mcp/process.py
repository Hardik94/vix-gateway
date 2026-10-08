"""Background MCP SSE process (snap / no host systemd unit)."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from meshdrive.constants import BIN, ROOT, VAR

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000


def mcp_pid_path() -> Path:
    return VAR / "mcp.pid"


def mcp_log_path() -> Path:
    return VAR / "log" / "mcp-sse.log"


def mcp_listen_host() -> str:
    return os.environ.get("MESHDRIVE_MCP_HOST", DEFAULT_HOST)


def mcp_listen_port() -> int:
    return int(os.environ.get("MESHDRIVE_MCP_PORT", str(DEFAULT_PORT)))


def mcp_sse_url() -> str:
    return f"http://{mcp_listen_host()}:{mcp_listen_port()}/sse"


def which_mcp_wrapper() -> Path | None:
    snap = os.environ.get("SNAP")
    candidates = [
        BIN / "meshdrive-mcp",
        Path(snap) / "bin" / "meshdrive-mcp-wrapper" if snap else None,
        Path(snap) / "opt" / "meshdrive" / "bin" / "meshdrive-mcp" if snap else None,
    ]
    for cand in candidates:
        if cand and cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def mcp_process_running() -> bool:
    pid_path = mcp_pid_path()
    if not pid_path.is_file():
        return False
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def mcp_port_open(host: str | None = None, port: int | None = None) -> bool:
    import socket

    h = host or mcp_listen_host()
    p = port if port is not None else mcp_listen_port()
    try:
        with socket.create_connection((h, p), timeout=0.4):
            return True
    except OSError:
        return False


def stop_mcp_sse_process() -> None:
    pid_path = mcp_pid_path()
    if not pid_path.is_file():
        return
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        try:
            pid_path.unlink()
        except OSError:
            pass
        return
    try:
        os.kill(pid, 15)
    except OSError:
        pass
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            break
        time.sleep(0.2)
    else:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
    try:
        pid_path.unlink()
    except OSError:
        pass


def start_mcp_sse_process() -> None:
    """Start MCP in SSE mode on 127.0.0.1:9000 (snap path)."""
    if mcp_process_running() and mcp_port_open():
        return
    if mcp_process_running():
        stop_mcp_sse_process()
    wrapper = which_mcp_wrapper()
    if not wrapper:
        raise RuntimeError(
            "meshdrive-mcp wrapper missing — re-run: meshdrive addons install mcp"
        )
    log = mcp_log_path()
    log.parent.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "MESHDRIVE_ROOT": str(ROOT),
        "MESHDRIVE_MCP_TRANSPORT": "sse",
        "MESHDRIVE_MCP_HOST": mcp_listen_host(),
        "MESHDRIVE_MCP_PORT": str(mcp_listen_port()),
        "PYTHONUNBUFFERED": "1",
    }
    with log.open("ab") as logf:
        proc = subprocess.Popen(
            [str(wrapper)],
            stdout=logf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=env,
            cwd=str(ROOT),
        )
    mcp_pid_path().write_text(f"{proc.pid}\n", encoding="utf-8")
    deadline = time.time() + 15.0
    while time.time() < deadline:
        if proc.poll() is not None:
            tail = ""
            try:
                tail = log.read_text(encoding="utf-8", errors="replace")[-800:]
            except OSError:
                pass
            raise RuntimeError(
                f"MCP SSE process exited early (code={proc.returncode}). "
                f"Check {log}" + (f"\n{tail}" if tail else "")
            )
        if mcp_port_open():
            return
        time.sleep(0.3)
    raise RuntimeError(
        f"MCP SSE did not listen on {mcp_sse_url()} within 15s — check {log}"
    )
