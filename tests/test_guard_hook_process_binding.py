"""Process-identity binding across Guard hook and continuation boundaries."""

from __future__ import annotations

import io
import json
import threading
from http.server import HTTPServer
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import continuation_runtime as continuation_runtime_module
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.codex_daemon_hook_bridge_fixtures import (
    _bridge_config,
    _DaemonHandler,
    _ProxyHandler,
    _write_authenticated_daemon_files,
)
from tests.test_guard_codex_resume_endpoints import _post_json, _request, _seed_codex_operation
from tests.test_guard_package_hook import (
    WORKSPACE_ID,
    _bundle_response,
    _review_policy_rule,
    _seed_guard_cloud,
    _write_codex_pre_tool_payload,
)

pytest_plugins = ["tests.bundle_first_cloud"]


def _approve_request(store: GuardStore, request_id: str) -> dict[str, object]:
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        return _post_json(
            daemon.port,
            daemon._server.auth_token,
            f"/v1/requests/{request_id}/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()


def test_main_binds_authenticated_daemon_request_to_bridge_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    proxy = HTTPServer(("127.0.0.1", 0), _ProxyHandler)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
    _DaemonHandler.response_body = (
        b'{"hookSpecificOutput":{"hookEventName":"PreToolUse"},"reason_code":"daemon_hook_queue_capacity"}'
    )
    _ProxyHandler.captured_paths = []
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.server_address[1]}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.server_address[1]}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    complete_command = "trap - DEBUG; { cat .env; } > /dev/null\ncat <<'EOF'\nharmless\nEOF"
    hook_payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": complete_command},
    }
    bridge_process = {"pid": 4102, "startToken": "fixture-start"}
    monkeypatch.setattr(bridge, "current_process_identity", lambda: bridge_process)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(hook_payload)))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, port))
    finally:
        daemon.shutdown()
        proxy.shutdown()
        daemon_thread.join(timeout=5)
        proxy_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.captured_challenge_guard_token is None
    assert _DaemonHandler.captured_guard_token == "fixture-token"
    captured_hook_payload = json.loads(str(_DaemonHandler.captured_hook_body))
    assert captured_hook_payload.pop("guard_remaining_ms") in range(1, 4_001)
    assert captured_hook_payload.pop(CODEX_BROWSER_WAIT_PROCESS_KEY) == bridge_process
    assert captured_hook_payload.pop(CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY) == 1
    assert captured_hook_payload == hook_payload
    assert json.loads(str(_DaemonHandler.captured_hook_body))["tool_input"]["command"] == complete_command
    assert _ProxyHandler.captured_paths == []
    response = json.loads(capsys.readouterr().out)
    if response != {}:
        if "hookSpecificOutput" in response:
            assert response["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        else:
            assert response["continue"] is False


def test_bridge_replaces_untrusted_wait_process_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    live_process = {"pid": 4102, "startToken": "fixture-start"}
    monkeypatch.setattr(bridge, "current_process_identity", lambda: live_process)

    payload = json.loads(
        bridge._with_browser_wait_process(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    CODEX_BROWSER_WAIT_PROCESS_KEY: {
                        "pid": 9999,
                        "startToken": "untrusted-input",
                    },
                    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 9999,
                }
            ),
            wait_timeout_seconds=7,
        )
    )

    assert payload[CODEX_BROWSER_WAIT_PROCESS_KEY] == live_process
    assert payload[CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY] == 7
    assert set(payload) == {
        "hook_event_name",
        CODEX_BROWSER_WAIT_PROCESS_KEY,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
    }


def test_codex_approve_without_resume_binding_returns_honest_manual_fallback(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-manual"), "2026-05-19T10:00:00+00:00")

    payload = _approve_request(store, "req-manual")

    assert payload["resolved"] is True
    assert payload["codexResume"]["status"] == "skipped"
    assert payload["codexResume"]["supported"] is False
    assert payload["codexResume"]["strategy"] == "manual-only"
    assert "could not find the original Codex chat" in payload["resolution_summary"]
    assert "approval is now saved" in payload["copy"]["body"]


@pytest.mark.parametrize("process_state", ["missing", "reused"])
def test_codex_approve_unproven_live_hook_terminalizes_through_daemon_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process_state: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-dead-live"), "2026-05-19T10:00:00+00:00")
    _seed_codex_operation(
        store,
        request_id="req-dead-live",
        socket_path=None,
        thread_id="dead-live-session-1",
        hook_event_name="PostToolUse",
        waits_for_browser_approval=True,
        browser_wait_deadline_at="2999-01-01T00:00:00+00:00",
        status="waiting_on_approval",
    )
    operation = store.get_guard_operation_for_approval_request("req-dead-live")
    assert isinstance(operation, dict)
    metadata = operation.get("metadata")
    assert isinstance(metadata, dict)
    process_identity = metadata.get("codex_browser_wait_process")
    assert isinstance(process_identity, dict)
    if process_state == "missing":
        del metadata["codex_browser_wait_process"]
    else:
        metadata["codex_browser_wait_process"] = {
            **process_identity,
            "startToken": "reused-process",
        }
    store.upsert_guard_operation(
        operation_id=str(operation["operation_id"]),
        session_id=str(operation["session_id"]),
        harness=str(operation["harness"]),
        operation_type=str(operation["operation_type"]),
        status=str(operation["status"]),
        approval_request_ids=list(operation["approval_request_ids"]),
        resume_token=str(operation["resume_token"]),
        metadata=metadata,
        now="2026-05-19T10:00:01+00:00",
    )
    monkeypatch.setattr(
        continuation_runtime_module,
        "codex_app_server_target_reachable",
        lambda _metadata: True,
    )

    payload = _approve_request(store, "req-dead-live")

    assert payload["resolved"] is True
    assert payload["codexResume"]["status"] == "skipped"
    assert payload["codexResume"]["reason"] == "manual_retry_required"
    recovered = store.get_guard_operation_for_approval_request("req-dead-live")
    assert isinstance(recovered, dict)
    assert recovered["status"] == "manual_retry_required"
    events = store.list_events(event_name="review.continuation.manual_retry_required")
    assert len(events) == 1


@pytest.mark.usefixtures("bundle_first_cloud")
def test_guard_hook_ask_package_fallback_does_not_wait_without_process_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    payload_path = workspace_dir / "hook-event.json"
    _write_codex_pre_tool_payload(payload_path, workspace_dir, "npm install minimist@1.2.8")
    store = GuardStore(home_dir)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            action="block",
            policy_rules=[_review_policy_rule("policy-review-identity-unavailable")],
        ),
        "2026-05-19T00:00:00Z",
    )
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 10\n", encoding="utf-8")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(
        guard_commands_module,
        "load_guard_surface_daemon_client",
        lambda _home: (_ for _ in ()).throw(RuntimeError("no daemon")),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.live_process_identity.current_process_identity",
        lambda: None,
    )

    def unexpected_wait(**_kwargs: object) -> dict[str, object]:
        raise AssertionError("an unbound hook must not enter the inline browser wait")

    monkeypatch.setattr(guard_commands_module, "wait_for_approval_requests", unexpected_wait)

    rc = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--event-file",
            str(payload_path),
        ]
    )
    _ = capsys.readouterr()

    assert rc == 0
    queued = store.list_approval_requests(limit=5)
    assert len(queued) == 1
    assert queued[0]["resolution_action"] is None
