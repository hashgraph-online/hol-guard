"""A session opened from an agent-handed approval link is bound to one request."""

from __future__ import annotations

import base64
import json
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_daemon_route
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.approval_handoff_route import approval_handoff_location
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from codex_plugin_scanner.guard.local_dashboard_session import (
    build_approval_browser_url,
    build_local_dashboard_session_token,
)
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

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


def _pending_request(request_id: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id="codex:project:tool-action:shared",
        artifact_name="Scoped action",
        artifact_type="tool_action_request",
        artifact_hash="hash-shared",
        publisher="publisher-a",
        policy_action="require-reapproval",
        recommended_scope="global",
        changed_fields=("command",),
        source_scope="project",
        config_path=f"/workspace/repo-{request_id[0]}/.guard/config.toml",
        workspace=f"/workspace/repo-{request_id[0]}",
        launch_target="echo test",
        action_envelope_json={"action_type": "shell_command", "command": "echo test"},
        decision_v2_json={"action": "ask", "approval_scopes": ["artifact", "harness"]},
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
    )


def _block_for_harness(daemon: GuardDaemonServer, request_id: str, headers: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/requests/{request_id}/block",
        data=json.dumps({"scope": "harness", "persist_policy": True}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{daemon.port}", **headers},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


@pytest.mark.parametrize("bound", [True, False])
def test_a_link_bound_decision_leaves_other_pending_requests_alone(tmp_path: Path, bound: bool) -> None:
    linked = "a" * 32
    other = "b" * 32
    store = GuardStore(tmp_path / "guard-home")
    for request_id in (linked, other):
        stored_id = store.add_approval_request(_pending_request(request_id), "2026-04-11T00:00:00+00:00")
        assert stored_id == request_id
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = daemon._server.auth_token
        if bound:
            session = build_local_dashboard_session_token(
                auth_token=auth_token,
                surface="approval-center",
                extra_claims={"request_id": linked},
            )
            headers = {"X-Guard-Dashboard-Session": session}
        else:
            headers = {"X-Guard-Token": auth_token}
        body = _block_for_harness(daemon, linked, headers)
    finally:
        daemon.stop()

    assert body["resolved"] is True
    assert store.get_approval_request(linked)["status"] != "pending"
    other_status = store.get_approval_request(other)["status"]
    # Guard's own session still settles this action's pending requests in every workspace;
    # a session opened from an agent-handed link settles only its own request.
    assert (other_status == "pending") is bound
