"""Grok approval live-wait must resume the original PreToolUse call."""

from __future__ import annotations

import argparse
import io
import json
import threading
import time
from contextlib import redirect_stderr
from pathlib import Path

from codex_plugin_scanner.guard.adapters.grok_approval_resume import (
    GROK_APPROVAL_WAIT_MAX_SECONDS,
    grok_live_approval_wait_seconds,
    wait_for_grok_live_approval,
)
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _request(tmp_path: Path, request_id: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="grok",
        artifact_id=f"grok:project:{request_id}",
        artifact_name=request_id,
        artifact_hash=f"hash-{request_id}",
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("args",),
        source_scope="project",
        config_path=str(tmp_path / ".grok" / "managed_config.toml"),
        workspace=str(tmp_path),
        launch_target="cat .env",
        action_envelope_json={
            "action_type": "shell_command",
            "tool_name": "run_terminal_command",
            "command": "cat .env",
        },
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1/pending/{request_id}",
    )


def test_grok_wait_timeout_is_capped_below_hook_deadline() -> None:
    assert grok_live_approval_wait_seconds(120) == GROK_APPROVAL_WAIT_MAX_SECONDS
    assert grok_live_approval_wait_seconds(0) == 0


def test_grok_live_wait_allows_after_approval(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request(tmp_path, "req-grok-wait"), "2026-05-08T10:00:00+00:00")
    payload: dict[str, object] = {
        "approval_requests": [{"request_id": "req-grok-wait"}],
        "session_id": "sess-grok",
    }

    def approve() -> None:
        time.sleep(0.15)
        apply_approval_resolution(
            store=store,
            request_id="req-grok-wait",
            action="allow",
            scope="artifact",
            workspace=str(tmp_path),
            reason="reviewed",
            now="2026-05-08T10:00:01+00:00",
        )

    thread = threading.Thread(target=approve)
    thread.start()
    decision = wait_for_grok_live_approval(
        event_name="PreToolUse",
        policy_action="require-reapproval",
        response_payload=payload,
        store=store,
        timeout_seconds=4,
        json_mode=False,
        payload=payload,
    )
    thread.join(timeout=5)

    assert decision == "allow"
    operation = store.get_guard_operation_for_approval_request("req-grok-wait")
    assert operation is not None
    assert operation["harness"] == "grok"
    assert operation["status"] == "waiting_on_approval"
    metadata = operation["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["grok_hook_waits_for_approval"] is True


def test_grok_live_wait_blocks_after_denial(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request(tmp_path, "req-grok-block"), "2026-05-08T10:00:00+00:00")
    payload: dict[str, object] = {"approval_requests": [{"request_id": "req-grok-block"}]}

    def deny() -> None:
        time.sleep(0.15)
        apply_approval_resolution(
            store=store,
            request_id="req-grok-block",
            action="block",
            scope="artifact",
            workspace=str(tmp_path),
            reason="blocked",
            now="2026-05-08T10:00:01+00:00",
        )

    thread = threading.Thread(target=deny)
    thread.start()
    decision = wait_for_grok_live_approval(
        event_name="PreToolUse",
        policy_action="require-reapproval",
        response_payload=payload,
        store=store,
        timeout_seconds=4,
        json_mode=False,
    )
    thread.join(timeout=5)

    assert decision == "block"


def test_grok_live_wait_skips_observe_events_and_zero_timeout(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request(tmp_path, "req-grok-skip"), "2026-05-08T10:00:00+00:00")
    payload: dict[str, object] = {"approval_requests": [{"request_id": "req-grok-skip"}]}
    assert (
        wait_for_grok_live_approval(
            event_name="UserPromptSubmit",
            policy_action="require-reapproval",
            response_payload=payload,
            store=store,
            timeout_seconds=4,
            json_mode=False,
        )
        is None
    )
    assert (
        wait_for_grok_live_approval(
            event_name="PreToolUse",
            policy_action="require-reapproval",
            response_payload=payload,
            store=store,
            timeout_seconds=0,
            json_mode=False,
        )
        is None
    )
    assert (
        wait_for_grok_live_approval(
            event_name="PreToolUse",
            policy_action="block",
            response_payload=payload,
            store=store,
            timeout_seconds=4,
            json_mode=False,
        )
        is None
    )


def test_grok_generic_hook_does_not_wait_when_timeout_is_zero(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.store import GuardStore

    guard_home = tmp_path / ".hol-guard"
    store = GuardStore(guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=tmp_path,
        approval_wait_timeout_seconds=0,
    )
    args = argparse.Namespace(
        harness="grok",
        json=False,
        policy_action="require-reapproval",
        artifact_id=None,
        artifact_name=None,
    )
    stdout_capture = io.StringIO()
    with redirect_stderr(io.StringIO()):
        started = time.monotonic()
        rc = _run_hook_generic_payload(
            args,
            action_envelope=None,
            config=config,
            output_stream=stdout_capture,
            payload={
                "hookEventName": "pre_tool_use",
                "toolName": "run_terminal_command",
                "toolInput": {"command": "cat README.md"},
            },
            home_dir=tmp_path,
            runtime_workspace=tmp_path,
            store=store,
        )
    elapsed = time.monotonic() - started

    assert rc == 2
    assert json.loads(stdout_capture.getvalue())["decision"] == "deny"
    assert elapsed < 2
