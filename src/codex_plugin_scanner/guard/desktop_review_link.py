"""The HOL Guard Desktop link for a pending approval request.

Mirrors ``rust/crates/guard-runtime/src/desktop_review_link.rs``: HOL Guard
Desktop registers the ``hol-guard-desktop:`` URL scheme and writes
``desktop-deep-link.json`` to the Guard home it manages. The marker only says
whether to offer the link; a marker whose app is gone offers nothing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .private_file_io import read_private_regular_text

DESKTOP_LINK_SCHEME = "hol-guard-desktop"
_MARKER_FILE = "desktop-deep-link.json"
_MARKER_MAX_BYTES = 4 * 1024
_MARKER_VERSION = 1
_REQUESTS_ROUTE = "requests"
_REQUEST_ID = re.compile(r"[0-9a-f]{32}")


def desktop_opens_requests(guard_home: Path) -> bool:
    """Whether Desktop's marker in ``guard_home`` says it opens request links."""

    text = read_private_regular_text(
        guard_home / _MARKER_FILE,
        max_bytes=_MARKER_MAX_BYTES,
        require_private_parent=True,
    )
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
