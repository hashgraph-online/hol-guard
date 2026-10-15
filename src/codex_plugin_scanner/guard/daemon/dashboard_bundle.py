"""The dashboard bundle a running daemon serves.

An in-place package upgrade replaces the bundle on disk while the old daemon
keeps running its old code. Serving files straight from disk would then pair
the new dashboard with the old daemon's API, and an open tab would mix old and
new chunks. The daemon pins ``index.html`` and ``assets/`` when it starts, so
it always serves the dashboard that matches the code it is running.
"""

from __future__ import annotations

import threading
from pathlib import Path

_PINNED_ROOTS = ("index.html", "assets")

_lock = threading.Lock()
_pinned: dict[Path, dict[str, bytes]] = {}


def _read_bundle(static_dir: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for root_name in _PINNED_ROOTS:
        root = static_dir / root_name
        candidates = [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file())
        for path in candidates:
            files[path.relative_to(static_dir).as_posix()] = path.read_bytes()
    return files


def pin_dashboard_bundle(static_dir: Path) -> None:
    """Read the bundle into memory once per process. Later calls keep the first copy."""

    with _lock:
        if static_dir not in _pinned:
            _pinned[static_dir] = _read_bundle(static_dir)


def is_pinned_path(relative_path: str) -> bool:
    return relative_path in _PINNED_ROOTS or relative_path.startswith(f"{_PINNED_ROOTS[1]}/")


def pinned_dashboard_file(static_dir: Path, relative_path: str) -> bytes | None:
    """Return the pinned bytes for ``relative_path``, or ``None`` when it is not in the bundle.

    Lookups are exact matches against the pinned file names, so a path that
    escapes the static directory can never match.
    """

    with _lock:
        bundle = _pinned.get(static_dir)
    if bundle is None:
        pin_dashboard_bundle(static_dir)
        with _lock:
            bundle = _pinned[static_dir]
    return bundle.get(relative_path)
