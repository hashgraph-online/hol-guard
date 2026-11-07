"""A session opened from an agent-handed approval link is bound to one request."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_daemon_route
from codex_plugin_scanner.guard.daemon.approval_handoff_route import approval_handoff_location
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from codex_plugin_scanner.guard.local_dashboard_session import build_approval_browser_url

AUTH = "test-daemon-auth-token"
REQUEST_ID = "0123456789abcdef0123456789abcdef"
REVIEW_URL = f"http://127.0.0.1:5474/requests/{REQUEST_ID}"


def _claims(location: str) -> dict[str, object]:
    session = location.split("=", 1)[1]
    payload = session.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def test_the_link_session_names_the_request_it_was_handed_for() -> None:
    url = build_approval_browser_url(REVIEW_URL, auth_token=AUTH)
    assert url is not None

    location = approval_handoff_location(url.removeprefix("http://127.0.0.1:5474"), auth_token=AUTH)

    assert location is not None
    claims = _claims(location)
    assert claims["surface"] == "approval-center"
    assert claims["request_id"] == REQUEST_ID


def test_the_request_claim_reaches_the_native_session_check(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_decide(query: dict[str, Any], *_args: object, **_kwargs: object) -> dict[str, Any]:
        seen.update(query)
        return {"allowed": False, "consume_nonce": None}

    monkeypatch.setattr(native_daemon_route, "_decide", fake_decide)
    native_daemon_route.native_session_authorize(
        method="POST",
        path=f"/v1/requests/{REQUEST_ID}/approve",
        claims={"surface": "approval-center", "request_id": REQUEST_ID},
        payload=None,
        header_nonce=None,
        request_origin=None,
    )

    assert seen["claims"]["request_id"] == REQUEST_ID


@pytest.mark.parametrize("request_id", [REQUEST_ID, "ffffffffffffffffffffffffffffffff"])
def test_a_link_bound_session_is_never_refreshed_into_a_broader_one(request_id: str) -> None:
    handler = SimpleNamespace(
        _refreshable_dashboard_session_claims=lambda: {
            "surface": "approval-center",
            "request_id": request_id,
            "expires_at": "2999-01-01T00:00:00+00:00",
        },
    )

    assert _GuardDaemonHandler._refresh_dashboard_session_token(handler, surface="dashboard") is None
