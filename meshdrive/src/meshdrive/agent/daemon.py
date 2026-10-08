"""MeshDrive agent daemon: health loop + loopback control API."""

from __future__ import annotations

import signal
import sys
import time
import traceback


def main(argv: list[str] | None = None) -> int:
    _ = argv

    # Import after env is set by the snap wrapper.
    from meshdrive.agent.api import AgentAPI, serve
    from meshdrive.constants import CONTROL_HOST, CONTROL_PORT, VERSION, control_bind_host, ensure_runtime_dirs
    from meshdrive.state import save_state

    bind_host = control_bind_host()

    try:
        from meshdrive.runtime_paths import prepare_runtime

        prepare_runtime()
    except Exception as exc:  # noqa: BLE001 — must not prevent API bind
        print(f"meshdrive-agent: prepare_runtime failed: {exc}", file=sys.stderr, flush=True)
        traceback.print_exc(file=sys.stderr)
        try:
            ensure_runtime_dirs()
        except OSError as mkdir_exc:
            print(f"meshdrive-agent: ensure_runtime_dirs failed: {mkdir_exc}", file=sys.stderr, flush=True)
            return 1

    try:
        api = AgentAPI()
        httpd = serve(api, host=bind_host, port=CONTROL_PORT)
    except OSError as exc:
        print(
            f"meshdrive-agent: cannot listen on http://{bind_host}:{CONTROL_PORT}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        if getattr(exc, "errno", None) == 13 or isinstance(exc, PermissionError):
            print(
                "Hint: snap must be classic (or have network-bind):\n"
                "  snap info meshdrive | grep confinement\n"
                "  sudo snap remove meshdrive\n"
                "  sudo snap install --dangerous --classic ./meshdrive_*.snap\n"
                "  sudo snap start meshdrive.agent\n"
                "Also ensure MESHDRIVE_CONTROL_HOST is 127.0.0.1 (not localhost).",
                file=sys.stderr,
                flush=True,
            )
        return 1

    stopping = False

    def _stop(signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        httpd.shutdown()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    print(
        f"meshdrive-agent {VERSION} listening on http://{bind_host}:{CONTROL_PORT}",
        flush=True,
    )
    try:
        while not stopping:
            try:
                api.refresh()
            except Exception as exc:  # noqa: BLE001 — keep serving
                print(f"meshdrive-agent: refresh error: {exc}", file=sys.stderr, flush=True)
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
