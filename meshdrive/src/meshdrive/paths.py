"""Keep MeshDrive config and MCP file access inside /opt/meshdrive."""

from __future__ import annotations

from pathlib import Path

from meshdrive.constants import ROOT


def isolation_roots() -> list[Path]:
    """Directories MCP and add-ons may read/write. Never the user's home."""
    try:
        from meshdrive.config import load_config, root

        md = root(load_config())
        iso = md.get("isolation") or {}
        raw = iso.get("allowed_paths") or [str(ROOT)]
    except Exception:
        raw = [str(ROOT)]
    roots: list[Path] = []
    for item in raw:
        try:
            roots.append(Path(item).expanduser().resolve())
        except OSError:
            continue
    if not roots:
        roots = [ROOT.resolve()]
    return roots


def storage_mount_roots() -> list[Path]:
    """Configured JuiceFS mount points (storage buckets) that agents may browse."""
    try:
        from meshdrive.config import backends

        mounts: list[Path] = []
        for item in backends():
            mount = item.get("mount_point") or item.get("mountpoint") or ""
            if not mount:
                continue
            try:
                mounts.append(Path(mount).expanduser().resolve())
            except OSError:
                continue
        return mounts
    except Exception:
        return []


def is_path_allowed(path: str | Path) -> bool:
    try:
        target = Path(path).expanduser().resolve()
    except OSError:
        return False
    for allowed in isolation_roots():
        try:
            target.relative_to(allowed)
            return True
        except ValueError:
            continue
    return False


def is_storage_path(path: str | Path) -> bool:
    """True if path is under a configured JuiceFS mount (storage bucket)."""
    try:
        target = Path(path).expanduser().resolve()
    except OSError:
        return False
    for mount in storage_mount_roots():
        try:
            target.relative_to(mount)
            return True
        except ValueError:
            continue
    return False


def assert_allowed(path: str | Path) -> Path:
    target = Path(path).expanduser().resolve()
    if not is_path_allowed(target):
        raise PermissionError(
            f"path is outside MeshDrive isolation ({ROOT}): {target}"
        )
    return target


def assert_storage_path(path: str | Path) -> Path:
    """Require path under a JuiceFS storage bucket mount (not bare ROOT/etc/var)."""
    target = assert_allowed(path)
    if not is_storage_path(target):
        mounts = ", ".join(str(m) for m in storage_mount_roots()) or "(none configured)"
        raise PermissionError(
            f"path is outside JuiceFS storage buckets; use a mount under: {mounts}"
        )
    return target


def relative_object_id(path: str | Path) -> str:
    """OpenFGA object id for a file, rooted at MESHDRIVE_ROOT."""
    target = Path(path).expanduser().resolve()
    try:
        rel = target.relative_to(ROOT.resolve())
        return f"file:{rel.as_posix()}"
    except ValueError:
        return f"file:{target.as_posix()}"
