"""Paid remote cluster: SSSD/LDAP + remote JuiceFS backend."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path
from typing import Any

import yaml

from meshdrive.config import load_config, save_config, upsert_backend
from meshdrive.constants import CLUSTER_PATH, MNT
from meshdrive.license import require_addon


def _require_root() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("cluster configure must run as root (sudo meshdrive cluster configure …)")


def _write_sssd(ldap_url: str, ldap_base: str, bind_dn: str | None, bind_password: str | None) -> None:
    require_addon("sssd-ldap")
    sssd_conf = Path("/etc/sssd/sssd.conf")
    bind_dn = bind_dn or ""
    bind_password = bind_password or ""
    content = f"""[sssd]
services = nss, pam
config_file_version = 2
domains = meshdrive.local

[domain/meshdrive.local]
id_provider = ldap
ldap_uri = {ldap_url}
ldap_search_base = {ldap_base}
"""
    if bind_dn:
        content += f"ldap_default_bind_dn = {bind_dn}\n"
    if bind_password:
        content += f"ldap_default_authtok = {bind_password}\n"
    content += "cache_credentials = True\n"
    sssd_conf.parent.mkdir(parents=True, exist_ok=True)
    sssd_conf.write_text(content, encoding="utf-8")
    sssd_conf.chmod(0o600)
    subprocess.run(["systemctl", "restart", "sssd"], check=False)


def run_configure(args: argparse.Namespace) -> None:
    require_addon("remote-cluster")
    _require_root()

    cluster: dict[str, Any] = {
        "ldap": {
            "url": args.ldap_url,
            "base": args.ldap_base,
            "bind_dn": args.bind_dn,
        },
        "remote_backend": {
            "name": args.backend_name,
            "metadata_url": args.metadata_url,
            "object_endpoint": args.object_endpoint,
        },
    }
    CLUSTER_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CLUSTER_PATH.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(cluster, fh, default_flow_style=False, sort_keys=False)
    try:
        CLUSTER_PATH.chmod(0o600)
    except OSError:
        pass

    _write_sssd(args.ldap_url, args.ldap_base, args.bind_dn, args.bind_password)

    cfg = load_config()
    md = cfg.setdefault("meshdrive", {})
    md["mode"] = "hybrid"
    md.setdefault("auth", {})["backend"] = "sssd"
    md["auth"]["ldap_url"] = args.ldap_url

    if args.metadata_url:
        backend = {
            "name": args.backend_name,
            "type": "juicefs-remote",
            "metadata_url": args.metadata_url,
            "object_endpoint": args.object_endpoint,
            "mountpoint": str(MNT / args.backend_name),
            "status": "configured",
        }
        upsert_backend(backend, cfg)
    else:
        save_config(cfg)

    sssd = md.setdefault("sssd", {})
    sssd.update({"enabled": True, "status": "ready", "progress": 100, "message": "LDAP configured"})
    remote = md.setdefault("remote_cluster", {})
    remote.update({"enabled": True, "status": "ready", "progress": 100, "message": "cluster configured"})
    save_config(cfg)
    print(f"Cluster configured; wrote {CLUSTER_PATH}")


def print_status() -> None:
    if CLUSTER_PATH.is_file():
        print(CLUSTER_PATH.read_text(encoding="utf-8"))
    else:
        print("No cluster configuration (meshdrive cluster configure …)")
    sssd_conf = Path("/etc/sssd/sssd.conf")
    print(f"\nSSSD config: {'present' if sssd_conf.is_file() else 'missing'}")
