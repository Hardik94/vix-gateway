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
    if shutil.which("fusermount3") or shutil.which("fusermount"):
        return True
    return False


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
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in name.strip())
    if not safe:
        raise ValueError("backend name is required")
    data = str(Path(data_path).resolve()) if data_path else str((VAR / "data" / safe).resolve())
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


def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


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
    if is_formatted(metadata_url):
        backend["formatted"] = True
        return
    cmd = [
        str(juicefs),
        "format",
        "--storage",
        "file",
        "--bucket",
        str(data_path),
    ]
    capacity = parse_capacity_gb(backend.get("capacity_gb"))
    if capacity:
        # JuiceFS --capacity is in GiB (soft quota for the volume).
        cmd.extend(["--capacity", str(capacity)])
        backend["capacity_gb"] = capacity
    cmd.extend([metadata_url, name])
    proc = _run(cmd)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "juicefs format failed").strip())
    backend["formatted"] = True


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
    mount_point = Path(backend["mount_point"])
    mount_point.mkdir(parents=True, exist_ok=True)
    if is_mounted(mount_point):
        return None
    cache_dir = backend.get("cache_dir") or str(VAR / "cache" / backend["name"])
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    cmd = [
        str(juicefs),
        "mount",
        backend["metadata_url"],
        str(mount_point),
        "-o",
        "allow_other",
        "--cache-dir",
        str(cache_dir),
    ]
    if not foreground:
        cmd.append("-d")
        proc = _run(cmd)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "juicefs mount failed").strip())
        return None
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


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
    if juicefs:
        proc = _run([str(juicefs), "umount", mount_point], timeout=30)
        if proc.returncode == 0:
            return
    for tool in ("fusermount3", "fusermount"):
        exe = shutil.which(tool)
        if exe:
            proc = _run([exe, "-u", mount_point], timeout=30)
            if proc.returncode == 0:
                return
    raise RuntimeError(f"failed to unmount {mount_point}")


def disk_stats(path: str | Path) -> dict[str, Any]:
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
    percent = int(round((used / usage.total) * 100)) if usage.total else 0
    return {
        "path": str(target),
        "exists": True,
        "mounted": is_mounted(target),
        "total_bytes": usage.total,
        "used_bytes": used,
        "free_bytes": usage.free,
        "usage_percent": percent,
    }
