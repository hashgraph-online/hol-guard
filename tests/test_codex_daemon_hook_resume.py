"""Codex hook-bridge browser approval continuation tests."""

from __future__ import annotations

import argparse
import http.client
import io
import json
import threading
import time
from http.server import HTTPServer
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_resume as resume
from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.live_process_identity import (
    CODEX_BROWSER_INLINE_WAIT_TIMEOUT_SECONDS_KEY,
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.codex_daemon_hook_bridge_fixtures import (
    _bridge_config,
    _ResumeDaemonHandler,
    _write_authenticated_daemon_files,
)
from tests.test_guard_phase04_harness_ux import _json_line, _run_hook


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


def test_codex_bridge_pretool_advertises_the_live_outer_waiter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_identity = {"pid": 4102, "startToken": "fixture-start"}
    monkeypatch.setattr(
        interaction,
        "process_identity_matches",
        lambda value: value == process_identity,
    )
    args = argparse.Namespace(harness="codex", json=True)

    payload = {
        "tool_name": "Read",
        "tool_input": {"path": "/workspace/project/.env"},
        CODEX_BROWSER_WAIT_PROCESS_KEY: process_identity,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 30,
    }
    assert interaction._codex_hook_waits_for_browser_approval(
        args,
        event_name="PreToolUse",
        policy_action="require-reapproval",
        payload=payload,
    )
    metadata = interaction._codex_browser_wait_metadata(
        args=args,
        event_name="PreToolUse",
        policy_action="require-reapproval",
        config=GuardConfig(tmp_path, None, approval_wait_timeout_seconds=30),
        payload=payload,
    )
    assert metadata["codex_hook_waits_for_browser_approval"] is True
    assert metadata["codex_browser_wait_process"] == process_identity
    assert metadata["codex_browser_wait_timeout_seconds"] == 30


def test_codex_bridge_wait_uses_the_outer_hook_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    process_identity = {"pid": 4102, "startToken": "fixture-start"}
    monkeypatch.setattr(interaction, "process_identity_matches", lambda value: value == process_identity)
    metadata = interaction._codex_browser_wait_metadata(
        args=argparse.Namespace(harness="codex", json=True),
        event_name="PreToolUse",
        policy_action="require-reapproval",
        config=GuardConfig(tmp_path, None, approval_wait_timeout_seconds=600),
        payload={
            CODEX_BROWSER_WAIT_PROCESS_KEY: process_identity,
            CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 7,
        },
    )

    assert metadata["codex_browser_wait_timeout_seconds"] == 7


def test_codex_bridge_budget_bounds_the_actual_approval_wait(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_timeout: list[int] = []

    def capture_wait(**kwargs: object) -> dict[str, object]:
        captured_timeout.append(int(kwargs["timeout_seconds"]))
        return {"resolved": False, "items": []}

    monkeypatch.setattr(interaction, "wait_for_approval_requests", capture_wait)
    monkeypatch.setattr(interaction, "_open_codex_live_approval", lambda *_args, **_kwargs: None)
    process_identity = {"pid": 4102, "startToken": "fixture-start"}
    monkeypatch.setattr(interaction, "process_identity_matches", lambda value: value == process_identity)
    payload = {
        CODEX_BROWSER_WAIT_PROCESS_KEY: process_identity,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 7,
        CODEX_BROWSER_INLINE_WAIT_TIMEOUT_SECONDS_KEY: 600,
    }
    metadata = interaction._codex_browser_wait_metadata(
        args=argparse.Namespace(harness="codex", json=True),
        event_name="PreToolUse",
        policy_action="require-reapproval",
        config=GuardConfig(tmp_path, None, approval_wait_timeout_seconds=600),
        payload=payload,
    )
    decision = interaction._codex_browser_approval_decision(
        args=argparse.Namespace(harness="codex", json=True),
        event_name="PreToolUse",
        policy_action="require-reapproval",
        response_payload={"approval_requests": [{"request_id": "request-bound"}]},
        store=GuardStore(tmp_path / "guard-home"),
        config=GuardConfig(tmp_path, None, approval_wait_timeout_seconds=600),
        browser_wait_bound=metadata["codex_hook_waits_for_browser_approval"] is True,
        inline_wait_seconds=payload[CODEX_BROWSER_INLINE_WAIT_TIMEOUT_SECONDS_KEY],
    )

    assert decision is None
    assert captured_timeout == [2]


def test_codex_unbound_browser_wait_retains_the_worker_budget() -> None:
    assert (
        interaction._codex_browser_wait_timeout_seconds(
            event_name="PreToolUse",
            configured_timeout=30,
        )
        == 8
    )


def test_codex_direct_pretool_wait_is_not_limited_to_package_installs() -> None:
    assert interaction._codex_hook_waits_for_browser_approval(
        argparse.Namespace(harness="codex", json=False),
        event_name="PreToolUse",
        policy_action="review",
        payload={"tool_name": "Read", "tool_input": {"path": "/workspace/project/.env"}},
    )


def test_codex_browser_wait_disables_inline_wait_when_process_identity_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.live_process_identity.current_process_identity",
        lambda: None,
    )
    args = argparse.Namespace(harness="codex", json=False)
    config = GuardConfig(tmp_path, None, approval_wait_timeout_seconds=30)

    metadata = interaction._codex_browser_wait_metadata(
        args=args,
        event_name="PostToolUse",
        policy_action="review",
        config=config,
    )
    assert metadata == {
        "codex_hook_waits_for_browser_approval": False,
        "codex_browser_wait_unavailable_reason": "process_identity_unavailable",
    }

    decision = interaction._codex_browser_approval_decision(
        args=args,
        event_name="PostToolUse",
        policy_action="review",
        response_payload={
            "approval_requests": [{"request_id": "request-unbound"}],
        },
        store=GuardStore(tmp_path / "guard-home"),
        config=config,
        browser_wait_bound=False,
    )
    assert decision is None


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


def test_codex_json_pretool_package_install_reason_includes_request(tmp_path: Path) -> None:
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


def test_bridge_converts_denied_pretool_to_allow_after_browser_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _ResumeDaemonHandler)
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
    _ResumeDaemonHandler.guard_home = guard_home
    _ResumeDaemonHandler.resolution = "allow"
    _ResumeDaemonHandler.policy_action = "require-reapproval"
    _ResumeDaemonHandler.approve_after = 0.15
    _ResumeDaemonHandler.started_at = time.monotonic()
    _ResumeDaemonHandler.get_count = 0
    _ResumeDaemonHandler.finalize_count = 0
    _ResumeDaemonHandler.finalize_completed = True
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "npm install is-even@1.0.0"},
                }
            )
        ),
    )
    monkeypatch.setattr(resume, "open_browser_url", lambda _url: True)

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, port))
    finally:
        daemon.shutdown()
        thread.join(timeout=5)

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
    assert "permissionDecision" not in payload.get("hookSpecificOutput", {})
    assert _ResumeDaemonHandler.get_count >= 1
    assert _ResumeDaemonHandler.finalize_count == 1
    assert "guardApprovalRequestId" not in payload


def test_bridge_keeps_deny_when_browser_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _ResumeDaemonHandler)
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
    _ResumeDaemonHandler.guard_home = guard_home
    _ResumeDaemonHandler.resolution = "block"
    _ResumeDaemonHandler.policy_action = "require-reapproval"
    _ResumeDaemonHandler.approve_after = 0.05
    _ResumeDaemonHandler.started_at = time.monotonic()
    _ResumeDaemonHandler.finalize_count = 0
    _ResumeDaemonHandler.finalize_completed = True
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "npm install is-even@1.0.0"},
                }
            )
        ),
    )
    monkeypatch.setattr(resume, "open_browser_url", lambda _url: True)

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, port))
    finally:
        daemon.shutdown()
        thread.join(timeout=5)

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert _ResumeDaemonHandler.finalize_count == 1
    assert "guardApprovalRequestId" not in payload


def test_bridge_keeps_deny_when_policy_became_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _ResumeDaemonHandler)
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
    _ResumeDaemonHandler.guard_home = guard_home
    _ResumeDaemonHandler.resolution = "allow"
    _ResumeDaemonHandler.policy_action = "sandbox-required"
    _ResumeDaemonHandler.approve_after = 0.05
    _ResumeDaemonHandler.started_at = time.monotonic()
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "npm install is-even@1.0.0"},
                }
            )
        ),
    )
    monkeypatch.setattr(resume, "open_browser_url", lambda _url: True)

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, port))
    finally:
        daemon.shutdown()
        thread.join(timeout=5)

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bridge_keeps_deny_when_browser_wait_times_out(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _ResumeDaemonHandler)
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
    _ResumeDaemonHandler.guard_home = guard_home
    _ResumeDaemonHandler.resolution = None
    _ResumeDaemonHandler.approve_after = 30.0
    _ResumeDaemonHandler.started_at = time.monotonic()
    config = _bridge_config(guard_home, port)
    config["hook_timeouts"] = {
        "PreToolUse": 3,
        "PermissionRequest": 3,
        "UserPromptSubmit": 3,
        "PostToolUse": 3,
    }
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "npm install is-even@1.0.0"},
                }
            )
        ),
    )
    monkeypatch.setattr(resume, "open_browser_url", lambda _url: True)
    monkeypatch.setattr(resume, "_POLL_INTERVAL_SECONDS", 0.05)

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.shutdown()
        thread.join(timeout=5)

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
