from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

from codex_plugin_scanner.guard.adapters.cursor_hook_payload import cursor_hook_response_from_guard
from codex_plugin_scanner.guard.daemon.hook_worker_responses import _native_policy_not_ready_reason


def test_cursor_hook_response_surfaces_native_policy_reason() -> None:
    reason = "HOL Guard could not prepare the native policy safely. native_policy_snapshot_runtime_unavailable."
    response = cursor_hook_response_from_guard(
        policy_action="block",
        guard_payload={"reason": reason},
        hook_event_name="beforeShellExecution",
    )
    assert response["permission"] == "deny"
    assert response["user_message"] == reason
    assert response["agent_message"] == reason


def test_cursor_read_deny_surfaces_native_policy_reason() -> None:
    reason = "HOL Guard could not prepare the native policy safely."
    response = cursor_hook_response_from_guard(
        policy_action="block",
        guard_payload={"reason": reason},
        hook_event_name="beforeReadFile",
    )
    assert response["permission"] == "deny"
    assert response["user_message"] == reason
    assert "agent_message" not in response


def test_installed_cursor_hook_script_includes_approval_url_copy() -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import _HOOK_SCRIPT_TEMPLATE

    assert "def _cursor_reason(" in _HOOK_SCRIPT_TEMPLATE
    assert "Open HOL Guard to approve or keep this blocked: " in _HOOK_SCRIPT_TEMPLATE
    assert "primary_approval_url" in _HOOK_SCRIPT_TEMPLATE
    assert "live_approval_review_url" in _HOOK_SCRIPT_TEMPLATE


def test_cursor_ask_signs_loopback_url_when_guard_home_is_provided(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)
    guard_home.chmod(0o700)
    token_path = guard_home / "daemon-auth-token"
    token_path.write_text("secret-daemon-token", encoding="utf-8")
    token_path.chmod(0o600)
    review_url = "http://127.0.0.1:5474/requests/req-cursor-1"
    response = cursor_hook_response_from_guard(
        policy_action="review",
        guard_payload={
            "reason": "HOL Guard paused this browser script until you approve it.",
            "approval_request_id": "req-cursor-1",
            "approval_url": review_url,
        },
        hook_event_name="beforeMCPExecution",
        guard_home=guard_home,
    )
    agent = str(response["agent_message"])
    assert review_url in agent
    assert "guard-token=" in agent
    assert "secret-daemon-token" not in agent
    start = agent.index("http://")
    fragment = parse_qs(urlparse(agent[start:].split()[0].rstrip(".")).fragment)
    assert fragment["guard-token"][0].startswith("gld1.")


def test_cursor_ask_keeps_signed_approval_url() -> None:
    review_url = "http://127.0.0.1:5474/requests/req-cursor-1"
    signed = f"{review_url}#guard-token=gld1.abc.def"
    response = cursor_hook_response_from_guard(
        policy_action="review",
        guard_payload={
            "reason": (
                "HOL Guard paused this browser script until you approve it. "
                f"Open HOL Guard to approve or keep this blocked: {signed}."
            ),
            "approval_request_id": "req-cursor-1",
            "approval_url": review_url,
        },
        hook_event_name="beforeMCPExecution",
    )
    agent = str(response["agent_message"])
    assert signed in agent
    assert agent.count("http://") == 1
    assert "Open HOL Guard to approve or keep this blocked:" in agent


def test_cursor_ask_includes_approval_url_for_the_agent() -> None:
    review_url = "http://127.0.0.1:5474/requests/req-cursor-1"
    response = cursor_hook_response_from_guard(
        policy_action="review",
        guard_payload={
            "reason": "HOL Guard paused this browser script until you approve it.",
            "approval_request_id": "req-cursor-1",
            "approval_url": review_url,
        },
        hook_event_name="beforeMCPExecution",
    )
    assert response["permission"] == "ask"
    assert review_url in str(response["agent_message"])
    assert review_url in str(response["user_message"])
    assert "Open HOL Guard to approve or keep this blocked:" in str(response["agent_message"])


def test_native_policy_not_ready_reason_includes_publisher_error() -> None:
    daemon = SimpleNamespace(
        hook_worker=SimpleNamespace(
            policy_snapshot_publisher=SimpleNamespace(last_error="native_policy_snapshot_runtime_unavailable")
        )
    )
    assert _native_policy_not_ready_reason(daemon) == (
        "HOL Guard could not prepare the native policy safely. native_policy_snapshot_runtime_unavailable."
    )
