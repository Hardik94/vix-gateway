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


def assert_allowed(path: str | Path) -> Path:
    target = Path(path).expanduser().resolve()
    if not is_path_allowed(target):
        raise PermissionError(
            f"path is outside MeshDrive isolation ({ROOT}): {target}"
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
