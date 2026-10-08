"""CLI entry: meshdrive-mount <backend-name> — used by meshdrive-mount@.service."""

from __future__ import annotations

import sys
import time

from meshdrive.config import get_backend, load_config
from meshdrive.storage.juicefs import format_backend, is_mounted, mount_backend, which_juicefs


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: meshdrive-mount <backend-name>", file=sys.stderr)
        return 2
    name = args[0]
    cfg = load_config()
    backend = get_backend(name, cfg)
    if not backend:
        print(f"unknown storage backend: {name}", file=sys.stderr)
        return 1
    if not which_juicefs():
        print("juicefs binary not found", file=sys.stderr)
        return 1
    try:
        format_backend(backend)
        proc = mount_backend(backend, foreground=True)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if proc is None:
        # Already mounted; keep the unit alive.
        while is_mounted(backend["mount_point"]):
            time.sleep(30)
        return 0
    return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
