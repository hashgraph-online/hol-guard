"""Codex hook-bridge browser approval continuation tests."""

from __future__ import annotations

import argparse
import http.client
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_resume as resume
from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction
from tests.package_review_settings import review_package_signals
from tests.test_guard_phase04_harness_ux import _json_line, _run_hook

pytestmark = pytest.mark.usefixtures("approval_questionnaire_mode")


def test_pending_pretool_approval_requires_safe_request_id() -> None:
    assert resume.pending_pretool_approval(
        {
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
            "guardApprovalRequestId": "abcd1234ef567890",
            "guardApprovalUrl": "http://127.0.0.1:9/requests/abcd1234ef567890",
        },
        event_name="PreToolUse",
    ) == ("abcd1234ef567890", "http://127.0.0.1:9/requests/abcd1234ef567890")
    assert (
        resume.pending_pretool_approval(
            {
                "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
                "guardApprovalRequestId": "../secret",
            },
            event_name="PreToolUse",
        )
        is None
    )
    assert (
        resume.pending_pretool_approval(
            {
                "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
                "guardApprovalRequestId": "abcd1234ef567890",
            },
            event_name="PostToolUse",
        )
        is None
    )


def test_codex_json_pretool_does_not_hold_inside_daemon_worker() -> None:
    args = argparse.Namespace(harness="codex", json=True)
    assert not interaction._codex_hook_waits_for_browser_approval(
        args,
        event_name="PreToolUse",
        policy_action="require-reapproval",
        payload={"tool_input": {"command": "cat ~/.npmrc"}},
    )


def test_codex_direct_pretool_wait_is_not_limited_to_package_installs() -> None:
    assert interaction._codex_hook_waits_for_browser_approval(
        argparse.Namespace(harness="codex", json=False),
        event_name="PreToolUse",
        policy_action="review",
        payload={"tool_name": "Read", "tool_input": {"path": "/workspace/project/.env"}},
    )


def test_resolution_action_rejects_terminal_or_unknown_policy() -> None:
    allow_payload = {
        "status": "resolved",
        "resolution_action": "allow",
        "policy_action": "require-reapproval",
    }
    assert resume._resolution_action(allow_payload) == "allow"
    assert resume._resolution_action({**allow_payload, "policy_action": "review"}) == "allow"
    assert resume._resolution_action({**allow_payload, "policy_action": "sandbox-required"}) == "block"
    assert resume._resolution_action({**allow_payload, "policy_action": "block"}) == "block"
    assert resume._resolution_action({"status": "resolved", "resolution_action": "allow"}) == "block"


def test_pending_pretool_parses_request_binding_from_reason() -> None:
    pending = resume.pending_pretool_approval(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "HOL Guard paused `is-even@1.0.0` for review before install. "
                    "Open HOL Guard to approve or keep this blocked: "
                    "http://127.0.0.1:4959/requests/e6a363623e084e69b3b5ff34c476deb4. "
                    "After you choose, retry the same Codex action."
                ),
            }
        },
        event_name="PreToolUse",
    )
    assert pending == (
        "e6a363623e084e69b3b5ff34c476deb4",
        "http://127.0.0.1:4959/requests/e6a363623e084e69b3b5ff34c476deb4",
    )


@pytest.mark.usefixtures("native_hook_force")
def test_codex_json_pretool_package_install_reason_includes_request(tmp_path: Path) -> None:
    review_package_signals(tmp_path / "guard-home")
    exit_code, output = _run_hook(
        tmp_path,
        harness="codex",
        json_output=True,
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "npm install is-even@1.0.0"},
        },
    )
    payload = _json_line(output)
    pending = resume.pending_pretool_approval(payload, event_name="PreToolUse")
    assert exit_code == 0
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert pending is not None
    assert pending[0]
    assert pending[1] is not None and pending[0] in pending[1]


def test_poll_resolution_treats_http_exception_as_transient(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"count": 0}

    def flaky_get(**_kwargs: object) -> dict[str, object]:
        calls["count"] += 1
        if calls["count"] == 1:
            raise http.client.IncompleteRead(b"")
        return {
            "status": "resolved",
            "resolution_action": "allow",
            "policy_action": "require-reapproval",
        }

    monkeypatch.setattr(resume, "_daemon_json_get", flaky_get)
    monkeypatch.setattr(resume, "_POLL_INTERVAL_SECONDS", 0.01)
    action = resume._poll_resolution(
        request_id="abcd1234ef567890",
        state_path=tmp_path / "daemon-state.json",
        deadline=time.monotonic() + 1,
    )
    assert action == "allow"
    assert calls["count"] >= 2
