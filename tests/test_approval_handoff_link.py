"""Short approval links: the signed code an agent can relay without losing it."""

from __future__ import annotations

import re

from codex_plugin_scanner.guard.approval_handoff_link import (
    HANDOFF_TTL_SECONDS,
    build_approval_handoff_url,
    handoff_code_is_valid,
)
from codex_plugin_scanner.guard.daemon.approval_handoff_route import approval_handoff_location
from codex_plugin_scanner.guard.local_dashboard_session import build_approval_browser_url
from codex_plugin_scanner.guard.secret_redaction import sanitize_secret

AUTH = "daemon-auth-token-for-tests"
REQUEST_ID = "20fce09561634ecab2055b539113c618"
REVIEW_URL = f"http://127.0.0.1:5474/requests/{REQUEST_ID}"
NOW = 1_800_000_000


def _code(url: str) -> str:
    return url.rsplit("/", 1)[1]


def test_agent_facing_link_is_short_and_has_no_fragment() -> None:
    url = build_approval_browser_url(REVIEW_URL, auth_token=AUTH)

    assert url is not None
    assert url.startswith(f"{REVIEW_URL}/")
    assert "#" not in url
    assert re.fullmatch(r"[0-9]{1,12}-[0-9a-f]{32}", _code(url))
    assert len(url) < len(REVIEW_URL) + 50


def test_other_surfaces_and_shapes_keep_the_session_fragment() -> None:
    repair = build_approval_browser_url(REVIEW_URL, auth_token=AUTH, surface="protection-repair")
    queued = build_approval_browser_url("http://127.0.0.1:5474/requests?filter=pending", auth_token=AUTH)

    assert repair is not None and "#guard-token=gld1." in repair
    assert queued is not None and "#guard-token=gld1." in queued
    assert build_approval_handoff_url("http://127.0.0.1:5474/requests/not-a-request", auth_token=AUTH) is None


def test_code_verifies_only_for_its_request_key_and_lifetime() -> None:
    url = build_approval_handoff_url(REVIEW_URL, auth_token=AUTH, now=NOW)
    assert url is not None
    code = _code(url)

    assert handoff_code_is_valid(request_id=REQUEST_ID, code=code, auth_token=AUTH, now=NOW + 1)
    assert not handoff_code_is_valid(request_id="0" * 32, code=code, auth_token=AUTH, now=NOW + 1)
    assert not handoff_code_is_valid(request_id=REQUEST_ID, code=code, auth_token="other", now=NOW + 1)
    assert not handoff_code_is_valid(
        request_id=REQUEST_ID, code=code, auth_token=AUTH, now=NOW + HANDOFF_TTL_SECONDS + 1
    )
    expires, mac = code.split("-")
    forged_later = f"{int(expires) + 60}-{mac}"
    assert not handoff_code_is_valid(request_id=REQUEST_ID, code=forged_later, auth_token=AUTH, now=NOW + 1)


def test_code_far_in_the_future_is_refused_even_when_signed() -> None:
    url = build_approval_handoff_url(REVIEW_URL, auth_token=AUTH, now=NOW + 10 * HANDOFF_TTL_SECONDS)
    assert url is not None

    assert not handoff_code_is_valid(request_id=REQUEST_ID, code=_code(url), auth_token=AUTH, now=NOW)


def test_daemon_route_signs_valid_links_and_drops_bad_ones_to_the_plain_page() -> None:
    url = build_approval_browser_url(REVIEW_URL, auth_token=AUTH)
    assert url is not None
    path = url.removeprefix("http://127.0.0.1:5474")

    signed = approval_handoff_location(path, auth_token=AUTH)
    forged = approval_handoff_location(f"/requests/{REQUEST_ID}/1-{'0' * 32}", auth_token=AUTH)

    assert signed is not None and signed.startswith(f"/requests/{REQUEST_ID}#guard-token=gld1.")
    assert forged == f"/requests/{REQUEST_ID}"
    assert approval_handoff_location(f"/requests/{REQUEST_ID}", auth_token=AUTH) is None
    assert approval_handoff_location("/requests/abc/1-00", auth_token=AUTH) is None


def test_diagnostics_redact_the_short_code() -> None:
    url = build_approval_browser_url(REVIEW_URL, auth_token=AUTH)
    assert url is not None

    assert sanitize_secret(f"open {url} now") == f"open {REVIEW_URL}/<redacted> now"


def _session_claims(location: str) -> dict[str, object]:
    import base64
    import json

    session = location.split("=", 1)[1]
    payload = session.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def test_opening_the_link_late_never_extends_access_past_the_code() -> None:
    from datetime import datetime

    link = build_approval_handoff_url(REVIEW_URL, auth_token=AUTH, now=NOW)
    assert link is not None
    expires = NOW + HANDOFF_TTL_SECONDS
    path = link.split("127.0.0.1:5474", 1)[1]

    late = approval_handoff_location(path, auth_token=AUTH, now=expires - 30)

    assert late is not None and "=" in late
    claims = _session_claims(late)
    assert datetime.fromisoformat(str(claims["expires_at"])).timestamp() <= expires
    started = datetime.fromisoformat(str(claims["session_started_at"])).timestamp()
    assert started == NOW
    assert approval_handoff_location(path, auth_token=AUTH, now=expires + 1) == f"/requests/{REQUEST_ID}"
