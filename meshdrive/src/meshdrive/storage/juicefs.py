"""JuiceFS format / mount / stats helpers."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from meshdrive.constants import JUICEFS_BIN_CANDIDATES, MNT, VAR


def which_juicefs() -> Path | None:
    for candidate in JUICEFS_BIN_CANDIDATES:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("juicefs")
    return Path(found) if found else None


def juicefs_version(binary: Path | None = None) -> str | None:
    bin_path = binary or which_juicefs()
    if not bin_path:
        return None
    try:
        proc = subprocess.run(
            [str(bin_path), "version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    line = (proc.stdout or proc.stderr or "").strip().splitlines()
    return line[0] if line else None


def fuse_available() -> bool:
    if Path("/dev/fuse").exists():
        return True
    if _host_fusermount() is not None:
        return True
    if shutil.which("fusermount3") or shutil.which("fusermount"):
        return True
    return False


def _host_fusermount() -> Path | None:
    """Prefer host fusermount — snap-staged copies lack setuid and break mounts."""
    for cand in (
        Path("/usr/bin/fusermount3"),
        Path("/bin/fusermount3"),
        Path("/usr/bin/fusermount"),
        Path("/bin/fusermount"),
    ):
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def _mount_env() -> dict[str, str]:
    """PATH that finds host fusermount before any snap-staged copy."""
    env = dict(os.environ)
    snap = os.environ.get("SNAP")
    prefix = ["/usr/bin", "/bin"]
    if snap:
        prefix = [f"{snap}/opt/meshdrive/bin", "/usr/bin", "/bin", f"{snap}/usr/bin"]
    else:
        from meshdrive.constants import PACKAGE_BIN

        prefix = [str(PACKAGE_BIN), "/usr/bin", "/bin"]
    old = env.get("PATH", "/usr/bin:/bin")
    env["PATH"] = os.pathsep.join(prefix + [old])
    return env


def user_allow_other_enabled() -> bool:
    conf = Path("/etc/fuse.conf")
    if not conf.is_file():
        return False
    try:
        text = conf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        if line.strip() == "user_allow_other":
            return True
    return False


def ensure_user_allow_other() -> bool:
    """Enable ``user_allow_other`` in /etc/fuse.conf when running as root.

    Required for JuiceFS ``-o allow_other`` so Filebrowser (non-root) can see mounts.
    """
    if user_allow_other_enabled():
        return True
    if os.geteuid() != 0:
        return False
    conf = Path("/etc/fuse.conf")
    try:
        if conf.is_file():
            text = conf.read_text(encoding="utf-8", errors="replace")
            if "#user_allow_other" in text or "# user_allow_other" in text:
                text = text.replace("#user_allow_other", "user_allow_other")
                text = text.replace("# user_allow_other", "user_allow_other")
            elif "user_allow_other" not in text:
                if not text.endswith("\n"):
                    text += "\n"
                text += "user_allow_other\n"
            conf.write_text(text, encoding="utf-8")
        else:
            conf.write_text("# MeshDrive\nuser_allow_other\n", encoding="utf-8")
    except OSError:
        return False
    return user_allow_other_enabled()


def fuse_preflight() -> None:
    """Raise a clear error before juicefs mount if FUSE cannot work."""
    if not Path("/dev/fuse").exists():
        raise RuntimeError(
            "/dev/fuse missing — install fuse3 and run: sudo modprobe fuse"
        )
    if _host_fusermount() is None and not (
        shutil.which("fusermount3") or shutil.which("fusermount")
    ):
        raise RuntimeError(
            "fusermount3 not found — install host package: sudo apt-get install -y fuse3"
        )


def meta_db_path(metadata_url: str) -> Path | None:
    prefix = "sqlite3://"
    if metadata_url.startswith(prefix):
        return Path(metadata_url[len(prefix) :])
    return None


def is_formatted(metadata_url: str) -> bool:
    db = meta_db_path(metadata_url)
    return bool(db and db.is_file() and db.stat().st_size > 0)


def default_backend(
    name: str,
    data_path: str | None = None,
    *,
    capacity_gb: int | None = None,
) -> dict[str, Any]:
    from meshdrive.runtime_paths import map_legacy_root_path

    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in name.strip())
    if not safe:
        raise ValueError("backend name is required")
    if data_path:
        data = str(map_legacy_root_path(data_path).resolve())
    else:
        data = str((VAR / "data" / safe).resolve())
    meta = (VAR / "meta" / f"{safe}.db").resolve()
    backend: dict[str, Any] = {
        "name": safe,
        "type": "juicefs",
        "metadata_url": f"sqlite3://{meta}",
        "data_path": data,
        "cache_dir": str((VAR / "cache" / safe).resolve()),
        "mount_point": str((MNT / safe).resolve()),
        "formatted": False,
        "options": {"cache_size": 10240, "writeback": True, "compression": "lz4"},
    }
    if capacity_gb is not None and capacity_gb > 0:
        backend["capacity_gb"] = int(capacity_gb)
    return backend


def parse_capacity_gb(raw: Any) -> int | None:
    """Parse user capacity (GB). Empty/0/None means unlimited (no JuiceFS --capacity)."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError("capacity must be a number of gigabytes")
    if isinstance(raw, (int, float)):
        value = int(raw)
    else:
        text = str(raw).strip().lower().replace(" ", "")
        if not text or text in {"0", "unlimited", "none", "-"}:
            return None
        for suffix in ("gib", "gb", "g", "gi"):
            if text.endswith(suffix):
                text = text[: -len(suffix)]
                break
        try:
            value = int(float(text))
        except ValueError as exc:
            raise ValueError("capacity must be a number of gigabytes (e.g. 100 or 100G)") from exc
    if value < 0:
        raise ValueError("capacity cannot be negative")
    if value == 0:
        return None
    return value


def _run(cmd: list[str], timeout: int = 180, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
    )


def format_backend(backend: dict[str, Any], *, binary: Path | None = None) -> None:
    juicefs = binary or which_juicefs()
    if not juicefs:
        raise RuntimeError("juicefs binary not found")
    name = backend["name"]
    metadata_url = backend["metadata_url"]
    data_path = Path(backend["data_path"])
    meta = meta_db_path(metadata_url)
    if meta:
        meta.parent.mkdir(parents=True, exist_ok=True)
    data_path.mkdir(parents=True, exist_ok=True)
    Path(backend.get("cache_dir") or VAR / "cache" / name).mkdir(parents=True, exist_ok=True)
    Path(backend["mount_point"]).mkdir(parents=True, exist_ok=True)
    capacity = parse_capacity_gb(backend.get("capacity_gb"))
    if is_formatted(metadata_url):
        backend["formatted"] = True
        # Volume already exists — still push capacity into JuiceFS metadata so
        # `df` reports the allocated size instead of the default 1.0P.
        apply_capacity(backend, binary=juicefs)
        return
    cmd = [
        str(juicefs),
        "format",
        "--storage",
        "file",
        "--bucket",
        str(data_path),
    ]
    if capacity:
        # JuiceFS --capacity is in GiB; this is what `df` shows as Size.
        cmd.extend(["--capacity", str(capacity)])
        backend["capacity_gb"] = capacity
    cmd.extend([metadata_url, name])
    try:
        proc = _run(cmd, timeout=180)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"juicefs format timed out after {exc.timeout}s for backend {name!r}"
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"failed to exec juicefs ({juicefs}): {exc}") from exc
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "juicefs format failed").strip())
    backend["formatted"] = True
    # Re-apply via config for consistency (idempotent if format already set it).
    apply_capacity(backend, binary=juicefs, remount=False)


def apply_capacity(
    backend: dict[str, Any],
    *,
    binary: Path | None = None,
    remount: bool = True,
) -> None:
    """Set JuiceFS volume capacity (GiB) so mounts report it via statfs/df.

    Without this, JuiceFS defaults to advertising ~1PiB. TUI capacity_gb alone
    does not change what the Ubuntu terminal shows. A live mount usually needs
    a remount before Filebrowser's usage bar reflects the new size.
    """
    capacity = parse_capacity_gb(backend.get("capacity_gb"))
    if not capacity:
        return
    juicefs = binary or which_juicefs()
    if not juicefs:
        raise RuntimeError("juicefs binary not found")
    metadata_url = backend.get("metadata_url")
    if not metadata_url:
        raise ValueError("backend metadata_url is required to set capacity")
    proc = _run(
        [str(juicefs), "config", str(metadata_url), "--capacity", str(capacity)],
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            (proc.stderr or proc.stdout or "juicefs config --capacity failed").strip()
        )
    backend["capacity_gb"] = capacity
    mount_point = str(backend.get("mount_point") or "")
    if remount and mount_point and is_mounted(mount_point):
        env = _mount_env()
        _run([str(juicefs), "umount", mount_point], timeout=30, env=env)
        cache_dir = backend.get("cache_dir") or str(VAR / "cache" / backend["name"])
        Path(cache_dir).mkdir(parents=True, exist_ok=True)
        remount_cmd = [
            str(juicefs),
            "mount",
            str(metadata_url),
            mount_point,
            "-o",
            "allow_other",
            "--cache-dir",
            str(cache_dir),
            "-d",
        ]
        again = _run(remount_cmd, timeout=120, env=env)
        if again.returncode != 0:
            # Capacity is in metadata; mount may still be down — surface softly.
            err = (again.stderr or again.stdout or "remount after capacity failed").strip()
            raise RuntimeError(err)


def is_mounted(mount_point: str | Path) -> bool:
    path = Path(mount_point)
    try:
        return path.is_mount()
    except OSError:
        return False


def mount_backend(backend: dict[str, Any], *, binary: Path | None = None, foreground: bool = True) -> subprocess.Popen[str] | None:
    juicefs = binary or which_juicefs()
    if not juicefs:
        raise RuntimeError("juicefs binary not found")
    fuse_preflight()
    ensure_user_allow_other()
    # Ensure allocated size is in JuiceFS metadata before mount so `df` shows it.
    try:
        apply_capacity(backend, binary=juicefs, remount=False)
    except RuntimeError:
        # Mount should still proceed if config fails (e.g. unlimited / old binary).
        pass
    mount_point = Path(backend["mount_point"])
    mount_point.mkdir(parents=True, exist_ok=True)
    if is_mounted(mount_point):
        return None
    cache_dir = backend.get("cache_dir") or str(VAR / "cache" / backend["name"])
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    env = _mount_env()
    log = VAR / "log" / "juicefs-mount.log"
    log.parent.mkdir(parents=True, exist_ok=True)

    def _cmd(opts: list[str], *, daemon: bool) -> list[str]:
        out = [
            str(juicefs),
            "mount",
            backend["metadata_url"],
            str(mount_point),
            *opts,
            "--cache-dir",
            str(cache_dir),
        ]
        if daemon:
            out.append("-d")
        return out

    def _fail(err: str) -> None:
        hint = ""
        low = err.lower()
        if "fusermount" in low or "fuse" in low or "permission" in low or "not permitted" in low:
            hint = (
                " | snap/FUSE hint: sudo apt-get install -y fuse3; "
                "sudo modprobe fuse; "
                "grep -E '^user_allow_other' /etc/fuse.conf || "
                "echo user_allow_other | sudo tee -a /etc/fuse.conf; "
                "prefer host /usr/bin/fusermount3; "
                f"log: {log}"
            )
        msg = (err + hint).strip()
        try:
            with log.open("a", encoding="utf-8") as fh:
                fh.write(msg + "\n")
        except OSError:
            pass
        raise RuntimeError(msg)

    # Systemd mount unit keeps juicefs in the foreground.
    if foreground:
        proc = subprocess.Popen(
            _cmd(["-o", "allow_other"], daemon=False),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        return proc

    # Snap / in-process: daemonize (-d).
    proc = _run(_cmd(["-o", "allow_other"], daemon=True), timeout=120, env=env)
    if proc.returncode == 0:
        return None
    err = (proc.stderr or proc.stdout or "juicefs mount failed").strip()
    if "allow_other" in err.lower() or "user_allow_other" in err.lower():
        ensure_user_allow_other()
        proc = _run(_cmd(["-o", "allow_other"], daemon=True), timeout=120, env=env)
        if proc.returncode == 0:
            return None
        err = (proc.stderr or proc.stdout or err).strip()
        # Last resort: mount without allow_other (Filebrowser may need remount later).
        proc2 = _run(_cmd([], daemon=True), timeout=120, env=env)
        if proc2.returncode == 0:
            try:
                log.write_text(
                    "mounted without allow_other — enable user_allow_other in /etc/fuse.conf "
                    "for non-root Filebrowser access\n",
                    encoding="utf-8",
                )
            except OSError:
                pass
            return None
        err = (proc2.stderr or proc2.stdout or err).strip()
    _fail(err)
    return None


def wipe_backend_data(backend: dict[str, Any]) -> None:
    """Remove local metadata, object data, cache, and mount directory."""
    backend_type = backend.get("type") or "juicefs"
    if backend_type != "juicefs":
        return
    targets: list[Path] = []
    meta = meta_db_path(str(backend.get("metadata_url") or ""))
    if meta:
        targets.append(meta)
    for key in ("data_path", "cache_dir", "mount_point"):
        raw = backend.get(key)
        if raw:
            targets.append(Path(raw))
    for target in targets:
        if not target.exists():
            continue
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink(missing_ok=True)


def unmount_backend(backend: dict[str, Any], *, binary: Path | None = None) -> None:
    juicefs = binary or which_juicefs()
    mount_point = str(backend["mount_point"])
    env = _mount_env()
    if juicefs:
        proc = _run([str(juicefs), "umount", mount_point], timeout=30, env=env)
        if proc.returncode == 0:
            return
    host = _host_fusermount()
    if host:
        proc = _run([str(host), "-u", mount_point], timeout=30, env=env)
        if proc.returncode == 0:
            return
    for tool in ("fusermount3", "fusermount"):
        exe = shutil.which(tool)
        if exe:
            proc = _run([exe, "-u", mount_point], timeout=30, env=env)
            if proc.returncode == 0:
                return
    raise RuntimeError(f"failed to unmount {mount_point}")


def preferred_filebrowser_root() -> str:
    """Server ``--root`` — always ``$ROOT/mnt`` (parent of JuiceFS mounts).

    Do **not** set root to ``$ROOT/mnt/<bucket>``. Filebrowser treats user
    ``--scope`` as relative to root when both are absolute paths under
    ``/opt/...``, which produces errors like::

        lstat /opt/meshdrive/mnt/fifth/opt: no such file or directory

    Capacity / usage bar: use ``preferred_admin_scope()`` (user scope = mount).
    """
    from meshdrive.constants import MNT

    return str(MNT)


def preferred_admin_scope() -> str:
    """Admin Filebrowser scope: sole mounted bucket (usage bar), else ``.``."""
    from meshdrive.config import backends

    mounted: list[str] = []
    for item in backends():
        mp = str(item.get("mount_point") or item.get("mountpoint") or "").strip()
        if mp and is_mounted(mp):
            mounted.append(mp)
    if len(mounted) == 1:
        return mounted[0]
    return "."


def normalize_filebrowser_scope(scope: str | None, *, server_root: str) -> str:
    """Scope for ``users update --scope`` — never root+/opt/... join bugs.

    Absolute paths equal to the server root become ``.``. Paths under the root
    become relative. Paths outside the root stay absolute (portals).
    """
    root_p = Path(server_root).expanduser()
    try:
        root_r = root_p.resolve()
    except OSError:
        root_r = root_p
    if not scope or str(scope).strip() in {".", "/", "./"}:
        return "."
    raw = str(scope).strip()
    scope_p = Path(raw).expanduser()
    try:
        scope_r = scope_p.resolve()
    except OSError:
        scope_r = scope_p
    if scope_r == root_r:
        return "."
    try:
        rel = scope_r.relative_to(root_r)
        text = rel.as_posix()
        return "." if text in {"", "."} else text
    except ValueError:
        return str(scope_r)


def disk_stats(path: str | Path, *, capacity_gb: int | None = None) -> dict[str, Any]:
    """Return usage for a path. When capacity_gb is set, total/free follow that quota
    (matches JuiceFS --capacity / what `df` should show after config)."""
    target = Path(path)
    if not target.exists():
        return {
            "path": str(target),
            "exists": False,
            "mounted": False,
            "total_bytes": 0,
            "used_bytes": 0,
            "free_bytes": 0,
            "usage_percent": 0,
        }
    usage = shutil.disk_usage(target)
    used = usage.total - usage.free
    total = usage.total
    free = usage.free
    cap = parse_capacity_gb(capacity_gb)
    if cap:
        # Prefer configured JuiceFS capacity over the default 1PiB advertising.
        total = int(cap) * (1024**3)
        free = max(0, total - used)
    percent = int(round((used / total) * 100)) if total else 0
    return {
        "path": str(target),
        "exists": True,
        "mounted": is_mounted(target),
        "total_bytes": total,
        "used_bytes": used,
        "free_bytes": free,
        "usage_percent": percent,
    }
