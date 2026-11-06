"""Turn a short approval link into a signed approval page."""

from __future__ import annotations

import re

from ..approval_handoff_link import handoff_code_is_valid
from ..local_dashboard_session import build_local_dashboard_session_token

_HANDOFF_PATH = re.compile(r"^/requests/(?P<id>[0-9a-f]{32})/(?P<code>[^/]+)$")


def approval_handoff_location(path: str, *, auth_token: str) -> str | None:
    """Where a short link should land, or None when the path is not a short link.

    A valid code lands on the request page with a fresh approval session in the
    fragment. A stale or forged code still lands on the request page, unsigned,
    so the daemon's normal sign-in applies.
    """

    match = _HANDOFF_PATH.match(path)
    if match is None:
        return None
    request_id = match.group("id")
    request_page = f"/requests/{request_id}"
    if not handoff_code_is_valid(request_id=request_id, code=match.group("code"), auth_token=auth_token):
        return request_page
    session = build_local_dashboard_session_token(auth_token=auth_token, surface="approval-center")
    return f"{request_page}#guard-token={session}"
