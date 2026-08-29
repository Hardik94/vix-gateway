"""MeshDrive agent daemon: health loop + loopback control API."""

from __future__ import annotations

import signal
import sys
import time

from meshdrive.agent.api import AgentAPI, serve
from meshdrive.constants import CONTROL_HOST, CONTROL_PORT, VERSION, ensure_runtime_dirs
from meshdrive.state import save_state


def main(argv: list[str] | None = None) -> int:
    _ = argv
    ensure_runtime_dirs()
    api = AgentAPI()
    httpd = serve(api)
    stopping = False

    def _stop(signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        httpd.shutdown()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    print(
        f"meshdrive-agent {VERSION} listening on http://{CONTROL_HOST}:{CONTROL_PORT}",
        flush=True,
    )
    try:
        while not stopping:
            api.refresh()
            for _ in range(50):
                if stopping:
                    break
                time.sleep(0.1)
    finally:
        try:
            state = api.refresh()
            state["agent"]["status"] = "stopped"
            save_state(state)
        except OSError:
            pass
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
