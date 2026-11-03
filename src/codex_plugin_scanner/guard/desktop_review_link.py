"""The HOL Guard Desktop link for a pending approval request.

Mirrors ``rust/crates/guard-runtime/src/desktop_review_link.rs``: HOL Guard
Desktop registers the ``hol-guard-desktop:`` URL scheme and writes
``desktop-deep-link.json`` to the Guard home it manages. The marker only says
whether to offer the link; a marker whose app is gone offers nothing.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

DESKTOP_LINK_SCHEME = "hol-guard-desktop"
_MARKER_FILE = "desktop-deep-link.json"
_MARKER_MAX_BYTES = 4 * 1024
_MARKER_VERSION = 1
_REQUESTS_ROUTE = "requests"
_REQUEST_ID = re.compile(r"[0-9a-f]{32}")


def _private_marker_text(path: Path) -> str | None:
    try:
        status = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(status.st_mode) or status.st_size > _MARKER_MAX_BYTES:
        return None
    if os.name == "posix" and (status.st_mode & 0o077 or status.st_uid != os.getuid()):
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def desktop_opens_requests(guard_home: Path) -> bool:
    """Whether Desktop's marker in ``guard_home`` says it opens request links."""

    text = _private_marker_text(guard_home / _MARKER_FILE)
    if text is None:
        return False
    try:
        marker = json.loads(text)
    except ValueError:
        return False
    if not isinstance(marker, dict):
        return False
    routes = marker.get("routes")
    app_path = marker.get("app_path")
    return (
        marker.get("version") == _MARKER_VERSION
        and marker.get("scheme") == DESKTOP_LINK_SCHEME
        and isinstance(routes, list)
        and _REQUESTS_ROUTE in routes
        and isinstance(app_path, str)
        and bool(app_path)
        and Path(app_path).exists()
    )


def desktop_request_url(request_id: str) -> str | None:
    """``hol-guard-desktop://requests/<id>`` for a queue-shaped request id."""

    if _REQUEST_ID.fullmatch(request_id) is None:
        return None
    return f"{DESKTOP_LINK_SCHEME}://{_REQUESTS_ROUTE}/{request_id}"


def desktop_review_url(guard_home: Path, request_id: str) -> str | None:
    """The Desktop link for ``request_id`` when Desktop in ``guard_home`` opens it."""

    url = desktop_request_url(request_id)
    if url is None or not desktop_opens_requests(guard_home):
        return None
    return url
