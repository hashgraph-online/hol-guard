"""Turn a short approval link into a signed approval page."""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from ..approval_handoff_link import HANDOFF_TTL_SECONDS, handoff_code_expiry
from ..local_dashboard_session import build_local_dashboard_session_token

_HANDOFF_PATH = re.compile(r"^/requests/(?P<id>[0-9a-f]{32})/(?P<code>[^/]+)$")


def approval_handoff_location(path: str, *, auth_token: str, now: float | None = None) -> str | None:
    """Where a short link should land, or None when the path is not a short link.

    A valid code lands on the request page with an approval session in the
    fragment. That session ends when the code does and keeps the code's issue
    time as its start, so opening the link again later never extends access
    past what the agent was handed. The session is bound to this request: it
    can read the approval page but decide only this request. A stale or forged code still lands on the
    request page, unsigned, so the daemon's normal sign-in applies.
    """

    match = _HANDOFF_PATH.match(path)
    if match is None:
        return None
    request_id = match.group("id")
    request_page = f"/requests/{request_id}"
    current = now if now is not None else time.time()
    expires = handoff_code_expiry(request_id=request_id, code=match.group("code"), auth_token=auth_token, now=current)
    if expires is None:
        return request_page
    issued_at = datetime.fromtimestamp(expires - HANDOFF_TTL_SECONDS, tz=timezone.utc)
    session = build_local_dashboard_session_token(
        auth_token=auth_token,
        surface="approval-center",
        expires_in_seconds=max(1, int(expires - current)),
        session_started_at=issued_at.isoformat(),
        extra_claims={"request_id": request_id},
    )
    return f"{request_page}#guard-token={session}"
