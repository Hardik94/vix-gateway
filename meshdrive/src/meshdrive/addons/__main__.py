"""meshdrive-addons — install optional modules without touching $HOME."""

from __future__ import annotations

import argparse
import sys

from meshdrive.addons.install import INSTALLABLE, FREE_INSTALLABLE, PAID_INSTALLABLE, AddonError, install
from meshdrive.config import addon_status, load_config
from meshdrive.license import status_dict


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="meshdrive-addons",
        description="Install MeshDrive modules into the MeshDrive root (free and paid tiers).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="show add-on status")
    inst = sub.add_parser("install", help="install one or more modules")
    inst.add_argument(
        "names",
        nargs="+",
        help="mcp, openfga, otel (free) or wireguard, vix-gateway, … (paid)",
    )
    args = parser.parse_args(argv)

    if args.cmd == "list":
        lic = status_dict()
        status = addon_status(load_config())
        print(f"license tier: {lic.get('tier', 'free')}")
        for key, info in status.items():
            lock = " [locked]" if info.get("locked") else ""
            print(f"{key:16} {info.get('tier', '?'):5} {info.get('status', '?'):16} {info.get('message', '')}{lock}")
        return 0

    names = args.names
    if names == ["all"] or names == ["addons"]:
        names = list(FREE_INSTALLABLE)
    if names == ["paid"]:
        names = list(PAID_INSTALLABLE)
    try:
        installed = install(names, cb=lambda n, p, m: print(f"[{p:3}%] {n}: {m}", flush=True))
    except AddonError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print("installed:", ", ".join(installed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
