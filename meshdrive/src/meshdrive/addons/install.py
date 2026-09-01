"""Install optional modules under MeshDrive root with free/paid tier gating."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from meshdrive.config import backends, load_config, root, save_config
from meshdrive.constants import BIN, ROOT, SHARE, VAR, VIX_FUSE_BIN, VIX_GATEWAY_BIN, ensure_runtime_dirs
from meshdrive.license import addon_allowed, require_addon
from meshdrive.state import load_state, save_state

Progress = Callable[[str, int, str], None]

FREE_INSTALLABLE = ("mcp", "openfga", "otel")
PAID_INSTALLABLE = ("wireguard", "vix-gateway", "vix-fuse", "sssd-ldap", "remote-cluster")
INSTALLABLE = FREE_INSTALLABLE + PAID_INSTALLABLE

ALIAS = {
    "telemetry": "otel",
    "otel": "otel",
    "openfga": "openfga",
    "mcp": "mcp",
    "wireguard": "wireguard",
    "vix_gateway": "vix-gateway",
    "vix-gateway": "vix-gateway",
    "vix_fuse": "vix-fuse",
    "vix-fuse": "vix-fuse",
    "sssd": "sssd-ldap",
    "sssd-ldap": "sssd-ldap",
    "remote_cluster": "remote-cluster",
    "remote-cluster": "remote-cluster",
}

CONFIG_KEY = {
    "mcp": "mcp",
    "openfga": "openfga",
    "otel": "telemetry",
    "wireguard": "wireguard",
    "vix-gateway": "vix_gateway",
    "vix-fuse": "vix_fuse",
    "sssd-ldap": "sssd",
    "remote-cluster": "remote_cluster",
}

UNIT = {
    "mcp": "meshdrive-mcp.service",
    "openfga": "meshdrive-openfga.service",
    "otel": "meshdrive-otel.service",
    "vix-gateway": "meshdrive-vix-gateway.service",
    "vix-fuse": "meshdrive-vix-fuse.service",
}


class AddonError(RuntimeError):
    pass


def addon_tier(name: str) -> str:
    canonical = _canonical(name, check_license=False)
    return "paid" if canonical in PAID_INSTALLABLE else "free"


def list_addons() -> list[str]:
    return list(INSTALLABLE)


def _config_key(name: str) -> str:
    return CONFIG_KEY[_canonical(name)]


def _canonical(name: str, *, check_license: bool = True) -> str:
    mapped = ALIAS.get(name, name)
    if mapped not in INSTALLABLE:
        raise AddonError(f"unknown add-on {name!r}; choose from: {', '.join(INSTALLABLE)}")
    if check_license:
        ok, msg = addon_allowed(mapped)
        if not ok:
            raise PermissionError(msg)
    return mapped


def set_addon_fields(config_key: str, **fields: Any) -> None:
    cfg = load_config()
    md = root(cfg)
    block = md.setdefault(config_key, {})
    block.update(fields)
    save_config(cfg)
    state = load_state()
    addons = state.setdefault("addons", {})
    state_key = "telemetry" if config_key == "telemetry" else config_key
    entry = addons.setdefault(state_key, {})
    if "status" in fields:
        entry["status"] = fields["status"]
    if "progress" in fields:
        entry["progress"] = fields["progress"]
    if "message" in fields:
        entry["message"] = fields["message"]
    save_state(state)


def _progress(name: str, percent: int, message: str, cb: Progress | None) -> None:
    key = _config_key(name)
    status = "ready" if percent >= 100 else "installing"
    if percent < 0:
        status = "error"
        percent = 0
    set_addon_fields(key, status=status, enabled=percent >= 100, progress=max(0, percent), message=message)
    if cb:
        cb(name, percent, message)


def _run(cmd: list[str], timeout: int = 300) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "command failed").strip()
        raise AddonError(err)


def _packaging_dir() -> Path:
    candidates = [ROOT / "packaging", Path(__file__).resolve().parents[3] / "packaging"]
    for path in candidates:
        if (path / "fetch-binaries.sh").is_file():
            return path
    raise AddonError("packaging/fetch-binaries.sh not found")


def _install_unit(unit_file: Path, dest_name: str) -> None:
    if not unit_file.is_file():
        raise AddonError(f"missing unit {unit_file}")
    dest = Path("/etc/systemd/system") / dest_name
    if dest.parent.is_dir():
        shutil.copy2(unit_file, dest)
    systemd_copy = ROOT / "systemd" / dest_name
    systemd_copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(unit_file, systemd_copy)


def _enable_unit(unit: str) -> None:
    from meshdrive.agent import systemd

    if systemd.systemd_available():
        systemd.systemctl("daemon-reload")
        systemd.enable_now(unit)


def _write_wrapper(name: str, target: str) -> None:
    path = BIN / name
    BIN.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\nexec {target} \"$@\"\n", encoding="utf-8")
    path.chmod(0o755)


def _ensure_overlay_file(rel: str) -> None:
    dest = ROOT / rel
    if dest.is_file():
        return
    src = Path(__file__).resolve().parents[3] / "overlay" / "opt" / "meshdrive" / rel
    if src.is_file():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def _overlay_unit(name: str) -> Path:
    return Path(__file__).resolve().parents[3] / "overlay" / "opt" / "meshdrive" / "systemd" / name


def install_mcp(cb: Progress | None = None) -> None:
    ensure_runtime_dirs()
    _progress("mcp", 10, "installing Python MCP extra", cb)
    pkg = ROOT / "pkg"
    venv_pip = ROOT / "venv" / "bin" / "pip"
    if venv_pip.is_file() and (pkg / "pyproject.toml").is_file():
        # Force pin first so a previously installed mcp 2.x is downgraded.
        _run([str(venv_pip), "install", "--upgrade", "mcp>=1.2.0,<2"], timeout=300)
        _run([str(venv_pip), "install", f"{pkg}[mcp]"], timeout=300)
    else:
        # Pin mcp<2: SDK 2.x removed Server.list_tools() decorators used by meshdrive-mcp.
        _run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--upgrade",
                "mcp>=1.2.0,<2",
                "uvicorn",
                "starlette",
            ],
            timeout=300,
        )
    _progress("mcp", 50, "writing isolated MCP wrapper", cb)
    venv_mcp = ROOT / "venv" / "bin" / "meshdrive-mcp"
    if venv_mcp.is_file():
        _write_wrapper("meshdrive-mcp", str(venv_mcp))
    else:
        _write_wrapper("meshdrive-mcp", f"{ROOT / 'venv' / 'bin' / 'python'} -m meshdrive.mcp")
    _ensure_overlay_file("etc/mcp-client.json")
    _progress("mcp", 80, "installing loopback systemd unit", cb)
    unit = _overlay_unit("meshdrive-mcp.service")
    if unit.is_file():
        _install_unit(unit, "meshdrive-mcp.service")
    try:
        _enable_unit(UNIT["mcp"])
    except RuntimeError:
        pass
    _progress("mcp", 100, "ready (stdio + loopback SSE)", cb)


def install_openfga(cb: Progress | None = None) -> None:
    ensure_runtime_dirs()
    og_dir = VAR / "openfga"
    og_dir.mkdir(parents=True, exist_ok=True)
    try:
        import pwd
        import grp

        uid = pwd.getpwnam("meshdrive").pw_uid
        gid = grp.getgrnam("meshdrive").gr_gid
        os.chown(og_dir, uid, gid)
    except (KeyError, OSError, PermissionError):
        pass

    _progress("openfga", 15, "downloading OpenFGA binary", cb)
    fetch = _packaging_dir() / "fetch-binaries.sh"
    _run(["bash", str(fetch), str(ROOT), "openfga"], timeout=180)
    _ensure_overlay_file("etc/openfga-model.json")
    _ensure_overlay_file("etc/openfga-model.fga")

    db_uri = f"file:{og_dir / 'openfga.db'}"
    openfga_bin = BIN / "openfga"
    if not openfga_bin.is_file():
        raise AddonError("openfga binary missing after fetch")

    _progress("openfga", 40, "migrating sqlite schema", cb)
    _run(
        [
            str(openfga_bin),
            "migrate",
            "--datastore-engine",
            "sqlite",
            "--datastore-uri",
            db_uri,
        ],
        timeout=120,
    )
    try:
        import pwd
        import grp

        uid = pwd.getpwnam("meshdrive").pw_uid
        gid = grp.getgrnam("meshdrive").gr_gid
        for path in og_dir.iterdir():
            try:
                os.chown(path, uid, gid)
            except OSError:
                pass
    except (KeyError, OSError, PermissionError):
        pass

    _progress("openfga", 55, "installing loopback systemd unit", cb)
    unit = _overlay_unit("meshdrive-openfga.service")
    if unit.is_file():
        _install_unit(unit, "meshdrive-openfga.service")
    try:
        _enable_unit(UNIT["openfga"])
    except RuntimeError as exc:
        _progress("openfga", 70, f"unit enable failed: {exc}", cb)

    _progress("openfga", 80, "bootstrapping sqlite store", cb)
    from meshdrive.addons import openfga

    try:
        openfga.wait_healthy(timeout=60.0)
        openfga.bootstrap()
        openfga.grant_mcp_access_all_backends()
    except RuntimeError as exc:
        _progress(
            "openfga",
            90,
            f"binary installed; check: journalctl -u meshdrive-openfga -b — {exc}",
            cb,
        )
        set_addon_fields(
            "openfga",
            status="installed",
            enabled=False,
            progress=90,
            message=str(exc),
        )
        return
    _progress("openfga", 100, "ready on 127.0.0.1:8081", cb)


def install_otel(cb: Progress | None = None) -> None:
    ensure_runtime_dirs()
    (VAR / "telemetry").mkdir(parents=True, exist_ok=True)
    _progress("otel", 15, "downloading otelcol-contrib", cb)
    fetch = _packaging_dir() / "fetch-binaries.sh"
    _run(["bash", str(fetch), str(ROOT), "otel"], timeout=180)
    _ensure_overlay_file("etc/otel-collector.yaml")
    _progress("otel", 70, "installing local-only collector unit", cb)
    unit = _overlay_unit("meshdrive-otel.service")
    if unit.is_file():
        _install_unit(unit, "meshdrive-otel.service")
    try:
        _enable_unit(UNIT["otel"])
    except RuntimeError:
        pass
    _progress("otel", 100, "ready (writes var/telemetry only)", cb)


def install_wireguard(cb: Progress | None = None) -> None:
    require_addon("wireguard")
    ensure_runtime_dirs()
    _progress("wireguard", 20, "staging hub-spoke templates", cb)
    wg_share = SHARE / "wireguard"
    wg_share.mkdir(parents=True, exist_ok=True)
    repo = Path(__file__).resolve().parents[4] / "infra" / "wireguard-hub-spoke"
    if repo.is_dir():
        for rel in ("clients/node.template/wg0.conf.template", "scripts/nft-client.nft", "docs/environment-ip-plan.md"):
            src = repo / rel
            if src.is_file():
                dest = wg_share / Path(rel).name
                if rel.endswith("wg0.conf.template"):
                    dest = wg_share / "wg0.conf.template"
                shutil.copy2(src, dest)
    _progress("wireguard", 100, "ready — run: sudo meshdrive wireguard bootstrap && apply", cb)


def install_vix_gateway(cb: Progress | None = None) -> None:
    require_addon("vix-gateway")
    ensure_runtime_dirs()
    _progress("vix-gateway", 10, "checking vix_cpp_gateway binary", cb)
    if not VIX_GATEWAY_BIN.is_file():
        build = _packaging_dir() / "build-vix.sh"
        if build.is_file():
            _run(["bash", str(build), str(ROOT), "gateway"], timeout=900)
    if not VIX_GATEWAY_BIN.is_file():
        raise AddonError("vix_cpp_gateway missing; run packaging/build-vix.sh on a Linux build host")
    _ensure_overlay_file("etc/vix-gateway.env")
    unit = _overlay_unit("meshdrive-vix-gateway.service")
    if unit.is_file():
        _install_unit(unit, "meshdrive-vix-gateway.service")
    try:
        _enable_unit(UNIT["vix-gateway"])
    except RuntimeError:
        pass
    _progress("vix-gateway", 100, "ready on 127.0.0.1:9443", cb)


def install_vix_fuse(cb: Progress | None = None) -> None:
    require_addon("vix-fuse")
    ensure_runtime_dirs()
    _progress("vix-fuse", 10, "checking vix_cpp_fuse binary", cb)
    if not VIX_FUSE_BIN.is_file():
        build = _packaging_dir() / "build-vix.sh"
        if build.is_file():
            _run(["bash", str(build), str(ROOT), "fuse"], timeout=900)
    if not VIX_FUSE_BIN.is_file():
        raise AddonError("vix_cpp_fuse missing; requires vix-gateway and WireGuard for remote mounts")
    _ensure_overlay_file("etc/vix-fuse-backends.json")
    unit = _overlay_unit("meshdrive-vix-fuse.service")
    if unit.is_file():
        _install_unit(unit, "meshdrive-vix-fuse.service")
    _progress("vix-fuse", 100, "ready — configure backends inside WG overlay", cb)


def install_sssd_ldap(cb: Progress | None = None) -> None:
    require_addon("sssd-ldap")
    ensure_runtime_dirs()
    _progress("sssd-ldap", 30, "installing sssd and ldap utils", cb)
    if os.geteuid() == 0 and shutil.which("apt-get"):
        _run(["apt-get", "install", "-y", "sssd", "sssd-ldap", "ldap-utils"], timeout=600)
    _progress("sssd-ldap", 100, "ready — run: sudo meshdrive cluster configure --ldap-url …", cb)


def install_remote_cluster(cb: Progress | None = None) -> None:
    require_addon("remote-cluster")
    ensure_runtime_dirs()
    _progress("remote-cluster", 50, "remote cluster wizard available", cb)
    _progress("remote-cluster", 100, "ready — run: sudo meshdrive cluster configure …", cb)


INSTALLERS = {
    "mcp": install_mcp,
    "openfga": install_openfga,
    "otel": install_otel,
    "wireguard": install_wireguard,
    "vix-gateway": install_vix_gateway,
    "vix-fuse": install_vix_fuse,
    "sssd-ldap": install_sssd_ldap,
    "remote-cluster": install_remote_cluster,
}


def install(names: list[str] | str, cb: Progress | None = None) -> list[str]:
    if isinstance(names, str):
        names = [names]
    done: list[str] = []
    for raw in names:
        name = _canonical(raw)
        try:
            INSTALLERS[name](cb)
            done.append(name)
        except Exception as exc:
            _progress(name, -1, str(exc), cb)
            raise AddonError(f"{name}: {exc}") from exc
    return done


def uninstall(name: str) -> None:
    canonical = _canonical(name, check_license=False)
    key = _config_key(canonical)
    set_addon_fields(key, status="not_installed", enabled=False, progress=0, message="uninstalled")
    unit = UNIT.get(canonical)
    if unit:
        from meshdrive.agent import systemd

        if systemd.systemd_available():
            systemd.stop_unit(unit)
