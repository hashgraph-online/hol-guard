"""Grok approval live-wait must resume the original PreToolUse call."""

from __future__ import annotations

import argparse
import io
import json
import sys
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


def test_grok_live_wait_accepts_aliased_pretool_event_name(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request(tmp_path, "req-grok-alias"), "2026-05-08T10:00:00+00:00")
    payload: dict[str, object] = {"approval_requests": [{"request_id": "req-grok-alias"}]}

    def approve() -> None:
        time.sleep(0.15)
        apply_approval_resolution(
            store=store,
            request_id="req-grok-alias",
            action="allow",
            scope="artifact",
            workspace=str(tmp_path),
            reason="reviewed",
            now="2026-05-08T10:00:01+00:00",
        )

    thread = threading.Thread(target=approve)
    thread.start()
    decision = wait_for_grok_live_approval(
        event_name="pre_tool_use",
        policy_action="require-reapproval",
        response_payload=payload,
        store=store,
        timeout_seconds=4,
        json_mode=False,
        payload=payload,
    )
    thread.join(timeout=5)

    assert decision == "allow"


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
                "hookEventName": "PreToolUse",
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


def test_grok_emit_allows_after_live_approval(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request(tmp_path, "req-grok-emit"), "2026-05-08T10:00:00+00:00")
    (store.guard_home / "config.toml").write_text("approval_wait_timeout_seconds = 4\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["hol-guard", "hook", "--guard-home", str(store.guard_home), "--harness", "grok"],
    )

    def approve() -> None:
        time.sleep(0.15)
        apply_approval_resolution(
            store=store,
            request_id="req-grok-emit",
            action="allow",
            scope="artifact",
            workspace=str(tmp_path),
            reason="reviewed",
            now="2026-05-08T10:00:01+00:00",
        )

    thread = threading.Thread(target=approve)
    thread.start()
    stream = io.StringIO()
    from codex_plugin_scanner.guard.adapters.grok_hooks import emit_grok_hook_response, grok_hook_process_exit

    emit_grok_hook_response(
        policy_action="require-reapproval",
        reason="Review in HOL Guard.",
        event_name="PreToolUse",
        approval_payload={"approval_requests": [{"request_id": "req-grok-emit"}]},
        output_stream=stream,
    )
    thread.join(timeout=5)

    assert json.loads(stream.getvalue()) == {"decision": "allow"}
    assert grok_hook_process_exit("require-reapproval") == 0


def test_grok_live_wait_ignores_unrelated_pending_requests(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request(tmp_path, "req-grok-stale"), "2026-05-08T10:00:00+00:00")
    store.add_approval_request(_request(tmp_path, "req-grok-live"), "2026-05-08T10:00:00+00:00")
    payload: dict[str, object] = {"approval_requests": [{"request_id": "req-grok-live"}]}

    def approve_live_only() -> None:
        time.sleep(0.15)
        apply_approval_resolution(
            store=store,
            request_id="req-grok-live",
            action="allow",
            scope="artifact",
            workspace=str(tmp_path),
            reason="reviewed",
            now="2026-05-08T10:00:01+00:00",
        )

    thread = threading.Thread(target=approve_live_only)
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
    stale = store.get_approval_request("req-grok-stale")
    assert stale is not None
    assert stale["status"] == "pending"


def test_grok_pretool_skips_short_daemon_budget(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import _try_daemon_hook

    result = _try_daemon_hook(
        guard_home=tmp_path / "guard-home",
        harness="grok",
        input_text=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"}),
        timeout_seconds=5.0,
    )
    assert result is None


def test_grok_isolated_hook_resumes_after_approval(tmp_path: Path) -> None:
    import sys as runtime_sys

    import codex_plugin_scanner
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
        isolated_guard_cli_command,
        isolated_hook_environment,
        run_isolated_hook_process,
    )

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'approval_wait_timeout_seconds = 6\nsecurity_level = "strict"\n'
        '[risk_actions]\nlocal_secret_read = "require-reapproval"\n',
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".env").write_text("SECRET=1\n", encoding="utf-8")
    package_root = Path(codex_plugin_scanner.__file__).resolve().parents[1]
    command = isolated_guard_cli_command(
        runtime_sys.executable,
        package_root,
        [
            "guard",
            "hook",
            "--guard-home",
            str(guard_home),
            "--harness",
            "grok",
            "--home",
            str(tmp_path),
            "--workspace",
            str(workspace),
        ],
    )
    store = GuardStore(guard_home)

    def approve_pending() -> None:
        for _ in range(100):
            pending = store.list_approval_requests(status="pending", harness="grok", limit=5)
            if pending:
                request_id = pending[0]["request_id"]
                assert isinstance(request_id, str)
                apply_approval_resolution(
                    store=store,
                    request_id=request_id,
                    action="allow",
                    scope="artifact",
                    workspace=str(workspace),
                    reason="reviewed",
                    now="2026-05-08T10:00:01+00:00",
                )
                return
            time.sleep(0.05)

    thread = threading.Thread(target=approve_pending)
    thread.start()
    result = run_isolated_hook_process(
        command,
        input_text=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "run_terminal_command",
                "toolInput": {"command": "cat .env"},
                "cwd": str(workspace),
                "session_id": "sess-isolated-grok",
            }
        ),
        cwd=guard_home,
        environment=isolated_hook_environment(),
        timeout_seconds=20,
    )
    thread.join(timeout=21)

    assert result.timed_out is False
    assert result.returncode == 0
    stdout_line = next(line for line in reversed(result.stdout.splitlines()) if line.strip())
    assert json.loads(stdout_line)["decision"] == "allow"
