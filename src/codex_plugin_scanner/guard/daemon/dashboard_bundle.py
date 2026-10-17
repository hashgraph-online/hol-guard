"""The dashboard bundle a running daemon serves.

An in-place package upgrade replaces the bundle on disk while the old daemon
keeps running its old code. Serving files straight from disk would then pair
the new dashboard with the old daemon's API, and an open tab would mix old and
new chunks. The daemon pins ``index.html`` and ``assets/`` when it starts, so
it always serves the dashboard that matches the code it is running.

A tab opened before the restart still runs the old bundle against the new
daemon. The daemon fingerprints its pinned bundle and stamps it on the shell
and on every response, so that tab can tell it is stale and reload itself
instead of rendering the new API with old code.
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path

_PINNED_ROOTS = ("index.html", "assets")
DASHBOARD_BUILD_HEADER = "X-Guard-Dashboard-Build"
_BUILD_META_NAME = "guard-dashboard-build"

_lock = threading.Lock()
_pinned: dict[Path, dict[str, bytes]] = {}
_build_ids: dict[Path, str | None] = {}


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


def dashboard_build_id(static_dir: Path) -> str | None:
    """Fingerprint of the pinned bundle, or ``None`` when no dashboard is bundled."""

    with _lock:
        if static_dir in _build_ids:
            return _build_ids[static_dir]
    pinned_dashboard_file(static_dir, "index.html")
    with _lock:
        bundle = _pinned[static_dir]
        if not bundle:
            build_id = None
        else:
            digest = hashlib.sha256()
            for name in sorted(bundle):
                digest.update(name.encode("utf-8"))
                digest.update(b"\0")
                digest.update(hashlib.sha256(bundle[name]).digest())
            build_id = digest.hexdigest()[:20]
        return _build_ids.setdefault(static_dir, build_id)


def stamp_dashboard_build(index_html: bytes, build_id: str | None) -> bytes:
    """Add the build fingerprint to the dashboard shell so the page knows which bundle it runs."""

    if build_id is None or b"</head>" not in index_html:
        return index_html
    meta = f'<meta name="{_BUILD_META_NAME}" content="{build_id}" />'.encode("ascii")
    return index_html.replace(b"</head>", meta + b"</head>", 1)
