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
    snap = os.environ.get("SNAP")
    if snap:
        candidates.insert(0, Path(snap) / "opt" / "meshdrive" / "packaging")
    for path in candidates:
        if (path / "fetch-binaries.sh").is_file():
            return path
    raise AddonError("packaging/fetch-binaries.sh not found")


def _snap_runtime() -> bool:
    from meshdrive.agent.systemd import running_under_snap

    return running_under_snap()


def _find_unit_file(name: str) -> Path | None:
    """Resolve a unit file for .deb (ROOT/systemd) or source/snap overlay trees."""
    candidates = [
        ROOT / "systemd" / name,
        Path("/opt/meshdrive/systemd") / name,
    ]
    snap = os.environ.get("SNAP")
    if snap:
        candidates.insert(0, Path(snap) / "opt" / "meshdrive" / "systemd" / name)
    # Dev tree / editable install
    here = Path(__file__).resolve()
    for parents_up in (3, 4, 5):
        if len(here.parents) > parents_up:
            base = here.parents[parents_up]
            candidates.append(base / "overlay" / "opt" / "meshdrive" / "systemd" / name)
            candidates.append(base / "systemd" / name)
    for path in candidates:
        if path.is_file():
            return path
    return None


def _overlay_unit(name: str) -> Path:
    found = _find_unit_file(name)
    return found if found is not None else ROOT / "systemd" / name


def _python_site_dirs() -> list[Path]:
    """Writable + snap-shipped site-packages for relocatable installs."""
    dirs: list[Path] = []
    snap = os.environ.get("SNAP")
    if snap:
        dirs.append(Path(snap) / "opt" / "meshdrive" / "python-packages")
    dirs.append(ROOT / "python-packages")
    return dirs


def _mcp_extra_importable() -> bool:
    """True when the MCP SDK can be imported with our site dirs on PYTHONPATH."""
    env = {**os.environ}
    sites = [str(p) for p in _python_site_dirs() if p.is_dir()]
    if sites:
        env["PYTHONPATH"] = os.pathsep.join(sites + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    proc = subprocess.run(
        [sys.executable, "-c", "import mcp, uvicorn, starlette"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
    )
    return proc.returncode == 0


def _pip_install_mcp_target(site: Path) -> None:
    site.mkdir(parents=True, exist_ok=True)
    # Pin mcp<2: SDK 2.x removed Server.list_tools() decorators used by meshdrive-mcp.
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--upgrade",
            "--target",
            str(site),
            "mcp>=1.2.0,<2",
            "uvicorn>=0.30.0",
            "starlette>=0.38.0",
        ],
        timeout=300,
    )


def _write_mcp_wrapper() -> None:
    """Write bin/meshdrive-mcp that works under snap (no venv) and .deb (venv)."""
    BIN.mkdir(parents=True, exist_ok=True)
    path = BIN / "meshdrive-mcp"
    venv_mcp = ROOT / "venv" / "bin" / "meshdrive-mcp"
    venv_py = ROOT / "venv" / "bin" / "python"
    if venv_mcp.is_file():
        path.write_text(f"#!/bin/sh\nexec {venv_mcp} \"$@\"\n", encoding="utf-8")
        path.chmod(0o755)
        return
    if venv_py.is_file():
        path.write_text(f"#!/bin/sh\nexec {venv_py} -m meshdrive.mcp \"$@\"\n", encoding="utf-8")
        path.chmod(0o755)
        return
    # Snap / relocatable: PYTHONPATH = SNAP_COMMON site + snap-shipped site.
    lines = [
        "#!/bin/sh",
        "set -e",
        'ROOT="${MESHDRIVE_ROOT:-${SNAP_COMMON:-/opt/meshdrive}}"',
        'export MESHDRIVE_ROOT="${ROOT}"',
        'SITE_COMMON="${ROOT}/python-packages"',
        'SITE_SNAP=""',
        'if [ -n "${SNAP:-}" ]; then SITE_SNAP="${SNAP}/opt/meshdrive/python-packages"; fi',
        'PY=""',
        'if [ -n "${SNAP:-}" ] && [ -x "${SNAP}/usr/bin/python3" ]; then PY="${SNAP}/usr/bin/python3"; fi',
        'if [ -z "${PY}" ]; then PY="$(command -v python3)"; fi',
        'PYTHONPATH="${SITE_COMMON}"',
        'if [ -n "${SITE_SNAP}" ]; then PYTHONPATH="${PYTHONPATH}:${SITE_SNAP}"; fi',
        'if [ -n "${PYTHONPATH_EXTRA:-}" ]; then PYTHONPATH="${PYTHONPATH}:${PYTHONPATH_EXTRA}"; fi',
        'export PYTHONPATH',
        'export PATH="${ROOT}/bin:/usr/bin:/bin:${SNAP:+$SNAP/opt/meshdrive/bin:}${PATH:-}"',
        'exec "${PY}" -m meshdrive.mcp "$@"',
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    path.chmod(0o755)


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
    candidates = [
        Path(__file__).resolve().parents[3] / rel,  # snap: $SNAP/opt/meshdrive/<rel>
        Path(__file__).resolve().parents[3] / "overlay" / "opt" / "meshdrive" / rel,
        Path(__file__).resolve().parents[4] / "overlay" / "opt" / "meshdrive" / rel,
    ]
    snap = os.environ.get("SNAP")
    if snap:
        candidates.insert(0, Path(snap) / "opt" / "meshdrive" / rel)
    for src in candidates:
        if src.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
            return


def install_mcp(cb: Progress | None = None) -> None:
    ensure_runtime_dirs()
    _progress("mcp", 10, "installing Python MCP extra", cb)
    pkg = ROOT / "pkg"
    venv_pip = ROOT / "venv" / "bin" / "pip"
    if venv_pip.is_file() and (pkg / "pyproject.toml").is_file():
        # Force pin first so a previously installed mcp 2.x is downgraded.
        _run([str(venv_pip), "install", "--upgrade", "mcp>=1.2.0,<2"], timeout=300)
        _run([str(venv_pip), "install", f"{pkg}[mcp]"], timeout=300)
    elif _mcp_extra_importable():
        _progress("mcp", 30, "MCP SDK already available (snap/site-packages)", cb)
    elif _snap_runtime() or not (ROOT / "venv" / "bin" / "python").is_file():
        # Snap has no writable venv — install extras into relocatable site-packages.
        site = ROOT / "python-packages"
        _progress("mcp", 20, f"pip --target {site}", cb)
        try:
            _pip_install_mcp_target(site)
        except AddonError as exc:
            raise AddonError(
                f"MCP pip install failed under snap/site-packages: {exc}. "
                "Rebuild snap with pkg[mcp] or ensure network + writable $SNAP_COMMON."
            ) from exc
        if not _mcp_extra_importable():
            raise AddonError(
                "MCP packages installed but import still fails — check PYTHONPATH / python3"
            )
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
    _write_mcp_wrapper()
    _ensure_overlay_file("etc/mcp-client.json")
    _progress("mcp", 70, "creating MCP API token (not a Filebrowser user)", cb)
    from meshdrive.constants import MCP_TOKEN_ONCE_PATH
    from meshdrive.mcp import credentials as mcp_creds

    plaintext = mcp_creds.ensure_install_token()
    mcp_creds.ensure_secret_ownership()
    if plaintext:
        _progress(
            "mcp",
            75,
            f"MCP token created — show once: meshdrive mcp credentials show --consume "
            f"(file: {MCP_TOKEN_ONCE_PATH})",
            cb,
        )
    else:
        _progress(
            "mcp",
            75,
            "MCP token already present (rotate: meshdrive mcp credentials rotate)",
            cb,
        )

    from meshdrive.agent import systemd as agent_systemd
    from meshdrive.mcp import process as mcp_proc

    if agent_systemd.use_host_units():
        _progress("mcp", 85, "installing loopback systemd unit", cb)
        unit = _find_unit_file("meshdrive-mcp.service")
        if unit is None:
            raise AddonError(
                "meshdrive-mcp.service not found under /opt/meshdrive/systemd — "
                "reinstall the .deb or copy overlay units"
            )
        _install_unit(unit, "meshdrive-mcp.service")
        try:
            _enable_unit(UNIT["mcp"])
            # Confirm SSE actually listens; fall back to in-process if unit is broken.
            if mcp_proc.mcp_port_open():
                sse_msg = f"SSE {mcp_proc.mcp_sse_url()} via systemd (Bearer token)"
            else:
                # Unit may still be starting; give it a moment.
                import time

                for _ in range(20):
                    if mcp_proc.mcp_port_open():
                        break
                    time.sleep(0.25)
                if mcp_proc.mcp_port_open():
                    sse_msg = f"SSE {mcp_proc.mcp_sse_url()} via systemd (Bearer token)"
                else:
                    _progress("mcp", 90, "systemd unit up but :9000 closed — starting process", cb)
                    mcp_proc.start_mcp_sse_process()
                    sse_msg = f"SSE {mcp_proc.mcp_sse_url()} (process fallback)"
        except RuntimeError as exc:
            _progress("mcp", 90, f"unit enable failed ({exc}); starting SSE process", cb)
            mcp_proc.start_mcp_sse_process()
            sse_msg = f"SSE {mcp_proc.mcp_sse_url()} (process; fix: systemctl status meshdrive-mcp)"
    else:
        _progress("mcp", 85, "starting MCP SSE on 127.0.0.1:9000 (snap)", cb)
        try:
            mcp_proc.start_mcp_sse_process()
            sse_msg = f"SSE {mcp_proc.mcp_sse_url()} (Bearer token)"
        except RuntimeError as exc:
            _progress("mcp", 90, f"SSE start failed: {exc}", cb)
            sse_msg = f"stdio only — SSE failed: {exc}"
    stdio_hint = (
        "snap run meshdrive.mcp"
        if agent_systemd.running_under_snap()
        else "/opt/meshdrive/bin/meshdrive-mcp"
    )
    _progress(
        "mcp",
        100,
        f"ready — stdio: {stdio_hint}; {sse_msg}",
        cb,
    )


def install_openfga(cb: Progress | None = None) -> None:
    ensure_runtime_dirs()
    from meshdrive.runtime_paths import ensure_writable_data_tree

    ensure_writable_data_tree()
    og_dir = VAR / "openfga"
    og_dir.mkdir(parents=True, exist_ok=True)
    # Under snap the agent runs as root; chown to a host "meshdrive" user (after
    # sudo install) often leaves dirs the daemon can no longer write.
    if not _snap_runtime():
        try:
            import pwd
            import grp

            uid = pwd.getpwnam("meshdrive").pw_uid
            gid = grp.getgrnam("meshdrive").gr_gid
            os.chown(og_dir, uid, gid)
        except (KeyError, OSError, PermissionError):
            pass

    _progress("openfga", 15, "resolving OpenFGA binary", cb)
    from meshdrive.addons import openfga

    openfga_bin = openfga.which_openfga()
    if openfga_bin is None:
        _progress("openfga", 20, "downloading OpenFGA binary", cb)
        fetch = _packaging_dir() / "fetch-binaries.sh"
        _run(["bash", str(fetch), str(ROOT), "openfga"], timeout=180)
        openfga_bin = openfga.which_openfga() or (BIN / "openfga")
    else:
        _progress("openfga", 20, f"using {openfga_bin}", cb)
    _ensure_overlay_file("etc/openfga-model.json")
    _ensure_overlay_file("etc/openfga-model.fga")

    if not openfga_bin.is_file():
        raise AddonError("openfga binary missing after fetch")

    db_uri = openfga.openfga_db_uri()
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
    if not _snap_runtime():
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

    from meshdrive.agent import systemd as agent_systemd

    if agent_systemd.use_host_units():
        _progress("openfga", 55, "installing loopback systemd unit", cb)
        unit = _overlay_unit("meshdrive-openfga.service")
        if unit.is_file():
            _install_unit(unit, "meshdrive-openfga.service")
        try:
            _enable_unit(UNIT["openfga"])
        except RuntimeError as exc:
            _progress("openfga", 70, f"unit enable failed: {exc}", cb)
    else:
        _progress("openfga", 55, "starting OpenFGA process (snap — no host unit)", cb)
        try:
            openfga.start_openfga_process()
        except RuntimeError as exc:
            _progress("openfga", 70, f"process start failed: {exc}", cb)
            set_addon_fields(
                "openfga",
                status="error",
                enabled=False,
                progress=70,
                message=str(exc),
            )
            raise AddonError(str(exc)) from exc

    _progress("openfga", 80, "bootstrapping sqlite store", cb)
    try:
        openfga.wait_healthy(timeout=60.0)
        openfga.bootstrap()
        openfga.grant_mcp_access_all_backends()
    except RuntimeError as exc:
        hint = (
            f"binary installed; check: journalctl -u meshdrive-openfga -b — {exc}"
            if agent_systemd.use_host_units()
            else f"binary installed; check: {VAR / 'log' / 'openfga.log'} — {exc}"
        )
        _progress("openfga", 90, hint, cb)
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
