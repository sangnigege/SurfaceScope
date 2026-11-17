"""Temporary directory selection without working-directory side effects."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

PROBE_PREFIX = ".surfacescope-write-"


class TemporaryDirectoryError(RuntimeError):
    """Raised when no writable temporary directory is available."""


def _resolved(path: Path) -> Path | None:
    try:
        return path.expanduser().resolve()
    except (OSError, RuntimeError):
        return None


def _inside_any(path: Path, parents: Iterable[Path]) -> bool:
    for parent in parents:
        resolved = _resolved(parent)
        if resolved is not None and (path == resolved or resolved in path.parents):
            return True
    return False


def _writable(path: Path) -> bool:
    probe = path / f"{PROBE_PREFIX}{os.getpid()}-{os.urandom(4).hex()}"
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"")
        probe.unlink()
    except (OSError, UnicodeError, ValueError):
        return False
    return True


def _default_candidates() -> list[Path]:
    candidates = [Path(tempfile.gettempdir())]
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(Path(local_app_data) / "Temp")
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        candidates.append(Path(user_profile) / "AppData" / "Local" / "Temp")
    system_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR")
    if system_root:
        candidates.append(Path(system_root) / "Temp")
    candidates.append(Path.home() / ".cache" / "surfacescope" / "tmp")
    if os.name != "nt":
        candidates.extend((Path("/tmp"), Path("/var/tmp")))
    if os.environ.get("SURFACESCOPE_ALLOW_CWD_PARENT_TMP") == "1":
        # Opt-in escape hatch for restricted environments where every standard temp
        # location is unwritable. Off by default so a project's parent directory never
        # collects `surfacescope-*` directories by accident.
        candidates.append(Path.cwd().parent)
    return candidates


def select_temp_parent(
    *,
    exclude: Iterable[str | Path] = (),
    candidates: Iterable[str | Path] | None = None,
) -> Path:
    """Return the first writable candidate that is not inside ``exclude``.

    ``tempfile.gettempdir()`` may silently fall back to the current working
    directory on older Python builds or restricted Windows profiles. Callers
    that promise a clean CWD must exclude it explicitly; this helper never
    trusts the default blindly.
    """

    excluded = [Path(item).expanduser().resolve() for item in exclude]
    seen: set[Path] = set()
    for item in candidates if candidates is not None else _default_candidates():
        resolved = _resolved(Path(item))
        if resolved is None or resolved in seen:
            continue
        seen.add(resolved)
        if _inside_any(resolved, excluded):
            continue
        if _writable(resolved):
            return resolved
    raise TemporaryDirectoryError(
        "no writable temporary directory outside the excluded paths; "
        "set an explicit --artifact-root or configure the system TEMP directory"
    )


def make_temp_dir(
    prefix: str = "surfacescope-",
    *,
    exclude: Iterable[str | Path] = (),
    candidates: Iterable[str | Path] | None = None,
) -> Path:
    """Create a unique temporary directory under a safe parent."""

    parent = select_temp_parent(exclude=exclude, candidates=candidates)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
