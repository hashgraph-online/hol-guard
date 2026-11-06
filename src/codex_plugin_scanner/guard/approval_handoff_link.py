"""Short approval links that open a single request signed in.

A paused review used to hand the agent `<review url>#guard-token=<session>`,
where the session is a few hundred characters of base64. Agents that relay the
link to the user routinely drop that fragment, so the user lands on a page
with no local session. This link carries a short code in the path instead:
`/requests/<id>/<expiry>-<mac>`, where the MAC binds the request id and the
expiry to the daemon auth token. The daemon checks the code and redirects to
the same signed session the long link carried. The code opens one request
only and expires with the session it replaces.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time

HANDOFF_VERSION = "guard-approval-link.v1"
HANDOFF_TTL_SECONDS = 12 * 60 * 60
_CLOCK_SKEW_SECONDS = 60
_MAC_HEX_CHARS = 32
_REQUEST_LINK = re.compile(r"^(?P<base>https?://[^/?#\s]+)/requests/(?P<id>[0-9a-f]{32})$")
_HANDOFF_CODE = re.compile(r"^(?P<expires>[0-9]{1,12})-(?P<mac>[0-9a-f]{32})$")
HANDOFF_LINK_PATTERN = re.compile(r"(/requests/[0-9a-f]{32})/[0-9]{1,12}-[0-9a-f]{32}")


def handoff_mac(*, auth_token: str, request_id: str, expires: int) -> str:
    message = f"{HANDOFF_VERSION}\n{request_id}\n{expires}".encode()
    digest = hmac.new(auth_token.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return digest[:_MAC_HEX_CHARS]


def build_approval_handoff_url(review_url: str, *, auth_token: str, now: float | None = None) -> str | None:
    """The short signed link for a bare `/requests/<id>` link, else None."""

    match = _REQUEST_LINK.match(review_url)
    if match is None:
        return None
    request_id = match.group("id")
    expires = int(now if now is not None else time.time()) + HANDOFF_TTL_SECONDS
    mac = handoff_mac(auth_token=auth_token, request_id=request_id, expires=expires)
    return f"{review_url}/{expires}-{mac}"


def handoff_code_expiry(*, request_id: str, code: str, auth_token: str, now: float | None = None) -> int | None:
    """The signed expiry of a valid code for `request_id`, else None."""

    match = _HANDOFF_CODE.match(code)
    if match is None or re.fullmatch(r"[0-9a-f]{32}", request_id) is None:
        return None
    expires = int(match.group("expires"))
    current = now if now is not None else time.time()
    if expires <= current or expires > current + HANDOFF_TTL_SECONDS + _CLOCK_SKEW_SECONDS:
        return None
    expected = handoff_mac(auth_token=auth_token, request_id=request_id, expires=expires)
    if not hmac.compare_digest(expected, match.group("mac")):
        return None
    return expires


def handoff_code_is_valid(*, request_id: str, code: str, auth_token: str, now: float | None = None) -> bool:
    return handoff_code_expiry(request_id=request_id, code=code, auth_token=auth_token, now=now) is not None


def redact_handoff_links(text: str) -> str:
    return HANDOFF_LINK_PATTERN.sub(r"\1/<redacted>", text)
