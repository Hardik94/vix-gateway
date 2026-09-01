"""Unified MeshDrive CLI: status, doctor, license, wireguard, addons, cluster."""

from __future__ import annotations

import argparse
import json
import sys

from meshdrive import __version__
from meshdrive.cli import doctor as doctor_mod


def _cmd_status(_args: argparse.Namespace) -> int:
    from meshdrive.agent import client as agent_client
    from meshdrive.config import load_config
    from meshdrive.license import status_dict as license_status

    cfg = load_config()
    md = cfg.get("meshdrive", {})
    lic = license_status()
    print(f"MeshDrive {__version__}  tier={lic['tier']}")
    print(f"  root: {md.get('isolation', {}).get('root_dir', 'unknown')}")
    print(f"  mode: {md.get('mode', 'local')}")
    backends = md.get("storage", {}).get("backends") or []
    print(f"  backends: {len(backends)}")
    for b in backends:
        print(f"    - {b.get('name')}: mount={b.get('mountpoint')} status={b.get('status', 'unknown')}")
    try:
        health = agent_client.health()
        print(f"  agent: ok ({health})")
    except Exception as exc:
        print(f"  agent: unavailable ({exc})")
    return 0


def _cmd_tui(_args: argparse.Namespace) -> int:
    from meshdrive.tui.__main__ import main as tui_main

    return tui_main() or 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    report = doctor_mod.run(verbose=args.verbose)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        doctor_mod.print_report(report)
    return 0 if report.get("ok") else 1


def _cmd_license(args: argparse.Namespace) -> int:
    from meshdrive.license import activate, status_dict

    if args.license_cmd == "activate":
        try:
            data = activate(args.token)
            print(f"License activated: tier={data['tier']} features={data.get('features')}")
            return 0
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
    if args.license_cmd == "status":
        st = status_dict()
        print(json.dumps(st, indent=2))
        return 0
    return 1


def _cmd_addons(args: argparse.Namespace) -> int:
    from meshdrive.addons.install import (
        AddonError,
        addon_tier,
        install as install_addons,
        list_addons,
        uninstall,
    )

    if args.addons_cmd == "list":
        for name in list_addons():
            tier = addon_tier(name)
            print(f"{name}\t{tier}")
        return 0
    if args.addons_cmd == "install":
        try:
            install_addons(args.name)
            print(f"Installed addon: {args.name}")
            return 0
        except (AddonError, PermissionError, RuntimeError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
    if args.addons_cmd == "uninstall":
        try:
            uninstall(args.name)
            print(f"Uninstalled addon: {args.name}")
            return 0
        except (AddonError, RuntimeError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
    return 1


def _cmd_wireguard(args: argparse.Namespace) -> int:
    from meshdrive.wireguard import client as wg

    cmds = {
        "bootstrap": wg.bootstrap,
        "apply": wg.apply,
        "up": wg.up,
        "down": wg.down,
        "status": wg.status,
    }
    fn = cmds.get(args.wg_cmd)
    if not fn:
        return 1
    try:
        return fn(args) or 0
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _cmd_cluster(args: argparse.Namespace) -> int:
    from meshdrive.cluster import configure as cluster

    if args.cluster_cmd == "configure":
        try:
            cluster.run_configure(args)
            return 0
        except (PermissionError, RuntimeError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
    if args.cluster_cmd == "status":
        cluster.print_status()
        return 0
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="meshdrive", description="MeshDrive 2.0 local-first storage")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="Show storage and agent status").set_defaults(func=_cmd_status)
    sub.add_parser("tui", help="Launch terminal UI").set_defaults(func=_cmd_tui)

    p_doc = sub.add_parser("doctor", help="Diagnose install, PATH, and components")
    p_doc.add_argument("-v", "--verbose", action="store_true")
    p_doc.add_argument("--json", action="store_true")
    p_doc.set_defaults(func=_cmd_doctor)

    p_lic = sub.add_parser("license", help="License activation (paid tier)")
    lic_sub = p_lic.add_subparsers(dest="license_cmd", required=True)
    p_act = lic_sub.add_parser("activate", help="Activate paid license with token")
    p_act.add_argument("--token", required=True)
    p_act.set_defaults(func=_cmd_license)
    lic_sub.add_parser("status", help="Show license tier and features").set_defaults(func=_cmd_license)

    p_addons = sub.add_parser("addons", help="Manage optional addons")
    addons_sub = p_addons.add_subparsers(dest="addons_cmd", required=True)
    addons_sub.add_parser("list", help="List installable addons").set_defaults(func=_cmd_addons)
    p_inst = addons_sub.add_parser("install", help="Install an addon")
    p_inst.add_argument("name")
    p_inst.set_defaults(func=_cmd_addons)
    p_un = addons_sub.add_parser("uninstall", help="Uninstall an addon")
    p_un.add_argument("name")
    p_un.set_defaults(func=_cmd_addons)

    p_wg = sub.add_parser("wireguard", help="WireGuard hub-spoke client (paid)")
    wg_sub = p_wg.add_subparsers(dest="wg_cmd", required=True)
    wg_sub.add_parser("bootstrap", help="Install OS WireGuard packages").set_defaults(func=_cmd_wireguard)
    p_apply = wg_sub.add_parser("apply", help="Apply wg0.conf and nft rules")
    p_apply.add_argument("--file", required=True, help="Path to wg0.conf")
    p_apply.add_argument("--v4", help="This host inner IPv4 for nft template")
    p_apply.add_argument("--v6", help="This host inner IPv6 for nft template")
    p_apply.set_defaults(func=_cmd_wireguard)
    wg_sub.add_parser("up", help="Start wg-quick@wg0").set_defaults(func=_cmd_wireguard)
    wg_sub.add_parser("down", help="Stop wg-quick@wg0").set_defaults(func=_cmd_wireguard)
    wg_sub.add_parser("status", help="Show tunnel and reachability").set_defaults(func=_cmd_wireguard)

    p_cl = sub.add_parser("cluster", help="Paid remote cluster (LDAP + remote JuiceFS)")
    cl_sub = p_cl.add_subparsers(dest="cluster_cmd", required=True)
    p_cfg = cl_sub.add_parser("configure", help="Configure SSSD/LDAP and remote backend")
    p_cfg.add_argument("--ldap-url", required=True)
    p_cfg.add_argument("--ldap-base", default="dc=meshdrive,dc=local")
    p_cfg.add_argument("--bind-dn")
    p_cfg.add_argument("--bind-password")
    p_cfg.add_argument("--metadata-url", help="Remote JuiceFS metadata URL (tikv://…)")
    p_cfg.add_argument("--object-endpoint", help="MinIO/S3 endpoint inside WG")
    p_cfg.add_argument("--backend-name", default="remote")
    p_cfg.set_defaults(func=_cmd_cluster)
    cl_sub.add_parser("status", help="Show cluster configuration").set_defaults(func=_cmd_cluster)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
