"""Daemon contract tests for Codex browser approval auto-resume."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_app_server as codex_app_server_module
from codex_plugin_scanner.guard import codex_resume as codex_resume_module
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _stub_codex_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        codex_resume_module.shutil, "which", lambda command: "/usr/bin/codex" if command == "codex" else None
    )


def _request(request_id: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name=request_id,
        artifact_hash=f"hash-{request_id}",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("args",),
        source_scope="project",
        config_path="/workspace/.codex/config.toml",
        workspace="/workspace",
        launch_target="cat ~/.npmrc",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1/pending/{request_id}",
    )


def _post_json(port: int, token: str, path: str, payload: dict[str, object]) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_json_without_token(port: int, path: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def _get_json(port: int, token: str, path: str) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"X-Guard-Token": token},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def _get_json_without_token(port: int, path: str) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def _seed_codex_operation(
    store: GuardStore,
    *,
    request_id: str,
    socket_path: Path | None,
    thread_id: str = "thread-1",
    workspace: str = "/workspace",
    codex_home: str | None = None,
    command_text: str | None = None,
    status: str = "waiting_on_approval",
) -> None:
    session = store.upsert_guard_session(
        session_id=f"session-{request_id}",
        harness="codex",
        surface="harness-adapter",
        status=status,
        client_name="codex-hook",
        client_title="Codex hook",
        client_version="1.0.0",
        workspace=workspace,
        capabilities=["approval-resolution"],
        now="2026-05-19T10:00:00+00:00",
    )
    metadata: dict[str, object] = {
        "codex_thread_id": thread_id,
        "codex_turn_id": "turn-1",
    }
    if socket_path is not None:
        metadata["codex_app_server_socket"] = str(socket_path)
    if codex_home is not None:
        metadata["codex_home"] = codex_home
    if command_text is not None:
        metadata["command_text"] = command_text
    store.upsert_guard_operation(
        operation_id=f"operation-{request_id}",
        session_id=str(session["session_id"]),
        harness="codex",
        operation_type="tool_call",
        status=status,
        approval_request_ids=[request_id],
        resume_token=f"resume-{request_id}",
        metadata=metadata,
        now="2026-05-19T10:00:00+00:00",
    )


def test_codex_approve_without_resume_binding_returns_honest_manual_fallback(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-manual"), "2026-05-19T10:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-manual/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["resolved"] is True
    assert payload["codex_resume"]["status"] == "skipped"
    assert payload["codex_resume"]["supported"] is False
    assert payload["codex_resume"]["strategy"] == "manual-only"
    assert "could not find the Codex session to resume" in payload["resolution_summary"]
    assert "approval is now saved" in payload["copy"]["body"]


def test_codex_block_resume_prompt_includes_request_id_and_safe_alternative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_payloads: list[dict[str, object]] = []

    def _fake_send(**kwargs):
        payloads = kwargs["payloads"]
        captured_payloads.extend(payloads)
        return {"id": 2, "result": {"turnId": "turn-2"}}, "turn_completed"

    monkeypatch.setattr(codex_app_server_module, "_send_app_server_websocket_messages", _fake_send)

    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-block"), "2026-05-19T10:00:00+00:00")
    socket_path = tmp_path / "codex-control.sock"
    socket_path.write_text("", encoding="utf-8")
    _seed_codex_operation(
        store,
        request_id="req-block",
        socket_path=socket_path,
        status="approval_wait_timeout",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-block/block",
            {"scope": "artifact", "reason": "blocked"},
        )
    finally:
        daemon.stop()

    assert payload["codex_resume"]["status"] == "sent"
    prompt = captured_payloads[2]["params"]["input"][0]["text"]
    assert prompt == "HOL Guard blocked request `req-block`. Do not retry that action. Explain a safe alternative."


def test_codex_approve_defers_headless_resume_while_live_hook_waits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_codex_binary(monkeypatch)

    def _fail_run(command, **kwargs):
        raise AssertionError("browser approval must not launch headless Codex while the live hook is waiting")

    monkeypatch.setattr(codex_resume_module.subprocess, "run", _fail_run)

    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-live"), "2026-05-19T10:00:00+00:00")
    missing_socket = tmp_path / "missing-codex.sock"
    _seed_codex_operation(
        store,
        request_id="req-live",
        socket_path=missing_socket,
        thread_id="live-session-1",
        status="waiting_on_approval",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-live/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["resolved"] is True
    assert payload["codex_resume"]["status"] == "in_progress"
    assert payload["codex_resume"]["reason"] == "live_hook_waiting"
    assert "original Codex action continue" in payload["codex_resume"]["message"]


def test_request_resume_status_endpoint_returns_persisted_result(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-status"), "2026-05-19T10:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-status/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
        status_code, payload = _get_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-status/resume",
        )
    finally:
        daemon.stop()

    assert status_code == 200
    assert payload["request_id"] == "req-status"
    assert payload["status"] == "skipped"
    assert payload["strategy"] == "manual-only"


def test_request_resume_status_endpoint_requires_guard_token(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-auth"), "2026-05-19T10:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        status, payload = _get_json_without_token(daemon.port, "/v1/requests/req-auth/resume")
    finally:
        daemon.stop()

    assert status == 401
    assert payload["error"] == "unauthorized"


def test_request_resume_retry_endpoint_requires_guard_token(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-auth-post"), "2026-05-19T10:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        status, payload = _post_json_without_token(
            daemon.port,
            "/v1/requests/req-auth-post/resume",
            {},
        )
    finally:
        daemon.stop()

    assert status == 401
    assert payload["error"] == "unauthorized"


def test_codex_allow_resume_prompt_includes_exact_command_when_metadata_is_present(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_payloads: list[dict[str, object]] = []

    def _fake_send(**kwargs):
        payloads = kwargs["payloads"]
        captured_payloads.extend(payloads)
        return {"id": 2, "result": {"turnId": "turn-2"}}, "turn_completed"

    monkeypatch.setattr(codex_app_server_module, "_send_app_server_websocket_messages", _fake_send)

    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-allow-command"), "2026-05-19T10:00:00+00:00")
    socket_path = tmp_path / "codex-allow-command.sock"
    socket_path.write_text("", encoding="utf-8")
    _seed_codex_operation(
        store,
        request_id="req-allow-command",
        socket_path=socket_path,
        command_text="python - <<'PY'\nprint('guard')\nPY",
        status="approval_wait_timeout",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-allow-command/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["codex_resume"]["status"] == "sent"
    prompt = captured_payloads[2]["params"]["input"][0]["text"]
    assert "HOL Guard approved request `req-allow-command` for this exact command:" in prompt
    assert "python - <<'PY'" in prompt
    assert "Retry that exact command now using the existing saved approval." in prompt


def test_request_resume_retry_endpoint_can_recover_after_socket_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resume_calls = 0
    _stub_codex_binary(monkeypatch)

    def _fake_run(command, **kwargs):
        nonlocal resume_calls
        resume_calls += 1
        if resume_calls == 1:
            return type(
                "CompletedProcess",
                (),
                {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "session unavailable",
                },
            )()
        return type(
            "CompletedProcess",
            (),
            {
                "returncode": 0,
                "stdout": '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}\n',
                "stderr": "",
            },
        )()

    monkeypatch.setattr(codex_resume_module.subprocess, "run", _fake_run)

    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-retry"), "2026-05-19T10:00:00+00:00")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _seed_codex_operation(
        store,
        request_id="req-retry",
        socket_path=None,
        workspace=str(workspace),
        codex_home="/tmp/codex-home",
        status="approval_wait_timeout",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        initial = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-retry/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
        assert initial["codex_resume"]["reason"] == "exec_resume_failed"

        retried = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-retry/resume",
            {},
        )
        status_code, current = _get_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-retry/resume",
        )
    finally:
        daemon.stop()

    assert retried["status"] == "sent"
    assert retried["strategy"] == "codex-exec-resume"
    assert retried["attempt_count"] == 2
    assert status_code == 200
    assert current["status"] == "sent"
    assert resume_calls == 2


def test_request_resume_retry_is_idempotent_after_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    send_calls = 0

    def _fake_send(**kwargs):
        nonlocal send_calls
        send_calls += 1
        return {"id": 2, "result": {"turnId": "turn-2"}}, "turn_completed"

    monkeypatch.setattr(codex_app_server_module, "_send_app_server_websocket_messages", _fake_send)

    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-idempotent"), "2026-05-19T10:00:00+00:00")
    socket_path = tmp_path / "codex-idempotent.sock"
    socket_path.write_text("", encoding="utf-8")
    _seed_codex_operation(
        store,
        request_id="req-idempotent",
        socket_path=socket_path,
        status="approval_wait_timeout",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-idempotent/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
        retried = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-idempotent/resume",
            {},
        )
    finally:
        daemon.stop()

    assert retried["status"] == "already_sent"
    assert send_calls == 1


def test_codex_approve_falls_back_to_exec_resume_when_socket_binding_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: dict[str, object] = {}
    _stub_codex_binary(monkeypatch)

    def _fake_run(command, **kwargs):
        recorded["command"] = command
        recorded["cwd"] = kwargs.get("cwd")
        recorded["env"] = kwargs.get("env")
        recorded["input"] = kwargs.get("input")
        return type(
            "CompletedProcess",
            (),
            {
                "returncode": 0,
                "stdout": '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}\n',
                "stderr": "",
            },
        )()

    monkeypatch.setattr(codex_resume_module.subprocess, "run", _fake_run)

    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-exec"), "2026-05-19T10:00:00+00:00")
    missing_socket = tmp_path / "missing-codex.sock"
    workspace = tmp_path / "workspace"
    codex_home = tmp_path / "codex-home"
    workspace.mkdir()
    codex_home.mkdir()
    _seed_codex_operation(
        store,
        request_id="req-exec",
        socket_path=missing_socket,
        thread_id="session-exec-1",
        workspace=str(workspace),
        codex_home=str(codex_home),
        status="approval_wait_timeout",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-exec/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    command = recorded["command"]
    assert payload["codex_resume"]["status"] == "sent"
    assert payload["codex_resume"]["strategy"] == "codex-exec-resume"
    assert command[:3] == ["codex", "exec", "resume"]
    assert "--dangerously-bypass-approvals-and-sandbox" in command
    assert "session-exec-1" in command
    assert "--dangerously-bypass-hook-trust" in command
    assert command[-1] == "-"
    assert recorded["cwd"] == str(workspace)
    assert isinstance(recorded["env"], dict)
    assert recorded["env"]["CODEX_HOME"] == str(codex_home)
    assert isinstance(recorded["input"], str)
    assert "approved request `req-exec`" in recorded["input"]


def test_codex_approve_uses_default_app_server_when_hook_omits_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    send_calls = 0

    def _fake_resume(**kwargs):
        nonlocal send_calls
        send_calls += 1
        return {
            "status": "sent",
            "reason": "turn_start_sent",
            "thread_id": "session-default-socket-1",
            "strategy": "codex-app-server-thread",
            "supported": True,
        }

    def _fail_run(command, **kwargs):
        raise AssertionError("app-server resume should be attempted before headless exec")

    monkeypatch.setattr(codex_resume_module, "resume_codex_thread_for_request", _fake_resume)
    monkeypatch.setattr(codex_resume_module.subprocess, "run", _fail_run)

    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-default-socket"), "2026-05-19T10:00:00+00:00")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _seed_codex_operation(
        store,
        request_id="req-default-socket",
        socket_path=None,
        thread_id="session-default-socket-1",
        workspace=str(workspace),
        status="approval_wait_timeout",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-default-socket/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["codex_resume"]["status"] == "sent"
    assert payload["codex_resume"]["strategy"] == "codex-app-server-thread"
    assert send_calls == 1


def test_codex_approve_returns_failed_resume_when_exec_launch_raises_oserror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_codex_binary(monkeypatch)

    def _raise_oserror(command, **kwargs):
        raise PermissionError("exec denied")

    monkeypatch.setattr(codex_resume_module.subprocess, "run", _raise_oserror)

    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-oserror"), "2026-05-19T10:00:00+00:00")
    missing_socket = tmp_path / "missing-codex.sock"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _seed_codex_operation(
        store,
        request_id="req-oserror",
        socket_path=missing_socket,
        thread_id="session-oserror-1",
        workspace=str(workspace),
        status="approval_wait_timeout",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-oserror/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["resolved"] is True
    assert payload["codex_resume"]["status"] == "failed"
    assert payload["codex_resume"]["reason"] == "exec_resume_launch_failed"
    assert payload["codex_resume"]["last_error"] == "exec denied"


def test_codex_approve_falls_back_to_exec_resume_after_transport_error_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: dict[str, object] = {}
    _stub_codex_binary(monkeypatch)

    def _fake_resume(**kwargs):
        return {
            "status": "failed",
            "reason": "ConnectionRefusedError",
            "thread_id": "session-transport-1",
        }

    def _fake_run(command, **kwargs):
        recorded["command"] = command
        return type(
            "CompletedProcess",
            (),
            {
                "returncode": 0,
                "stdout": '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}\n',
                "stderr": "",
            },
        )()

    monkeypatch.setattr(codex_resume_module, "resume_codex_thread_for_request", _fake_resume)
    monkeypatch.setattr(codex_resume_module.subprocess, "run", _fake_run)

    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-transport"), "2026-05-19T10:00:00+00:00")
    socket_path = tmp_path / "codex.sock"
    socket_path.write_text("", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _seed_codex_operation(
        store,
        request_id="req-transport",
        socket_path=socket_path,
        thread_id="session-transport-1",
        workspace=str(workspace),
        status="approval_wait_timeout",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-transport/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["codex_resume"]["status"] == "sent"
    assert payload["codex_resume"]["strategy"] == "codex-exec-resume"
    assert recorded["command"][:3] == ["codex", "exec", "resume"]
