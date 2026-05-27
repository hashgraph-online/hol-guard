"""CLI tests for Codex resume retry and diagnostics."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import codex_app_server as codex_app_server_module
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


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


def _seed_codex_operation(
    store: GuardStore,
    *,
    request_id: str,
    socket_path: Path | None,
    workspace: str = "/workspace",
    codex_home: str | None = None,
    thread_id: str = "thread-1",
) -> None:
    session = store.upsert_guard_session(
        session_id=f"session-{request_id}",
        harness="codex",
        surface="harness-adapter",
        status="waiting_on_approval",
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
        "workspace": workspace,
    }
    if socket_path is not None:
        metadata["codex_app_server_socket"] = str(socket_path)
    if codex_home is not None:
        metadata["codex_home"] = codex_home
    store.upsert_guard_operation(
        operation_id=f"operation-{request_id}",
        session_id=str(session["session_id"]),
        harness="codex",
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=[request_id],
        resume_token=f"resume-{request_id}",
        metadata=metadata,
        now="2026-05-19T10:00:00+00:00",
    )


def test_guard_approvals_resume_retries_failed_codex_resume(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    send_calls = 0

    def _fake_send(**kwargs):
        nonlocal send_calls
        send_calls += 1
        return {"id": 2, "result": {"turnId": "turn-2"}}, "turn_completed"

    monkeypatch.setattr(codex_app_server_module, "_send_app_server_websocket_messages", _fake_send)

    home_dir = tmp_path / "guard-home"
    store = GuardStore(home_dir)
    store.add_approval_request(_request("req-cli"), "2026-05-19T10:00:00+00:00")
    socket_path = tmp_path / "codex-cli.sock"
    socket_path.write_text("", encoding="utf-8")
    _seed_codex_operation(store, request_id="req-cli", socket_path=socket_path)
    store.resolve_approval_request(
        "req-cli",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at="2026-05-19T10:01:00+00:00",
    )

    rc = main(["guard", "approvals", "resume", "req-cli", "--home", str(home_dir), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["request_id"] == "req-cli"
    assert output["status"] == "sent"
    assert send_calls == 1


def test_guard_approvals_resume_uses_codex_home_default_socket(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_paths: list[str] = []

    def _fake_send(**kwargs):
        socket_paths.append(str(kwargs["socket_path"]))
        return {"id": 2, "result": {"turnId": "turn-2"}}, "turn_completed"

    monkeypatch.setattr(codex_app_server_module, "_send_app_server_websocket_messages", _fake_send)

    home_dir = tmp_path / "guard-home"
    codex_home = tmp_path / "codex-home"
    socket_path = codex_home / "app-server-control" / "app-server-control.sock"
    socket_path.parent.mkdir(parents=True)
    socket_path.write_text("", encoding="utf-8")
    store = GuardStore(home_dir)
    store.add_approval_request(_request("req-cli-home"), "2026-05-19T10:00:00+00:00")
    _seed_codex_operation(
        store,
        request_id="req-cli-home",
        socket_path=None,
        codex_home=str(codex_home),
    )
    store.resolve_approval_request(
        "req-cli-home",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at="2026-05-19T10:01:00+00:00",
    )

    rc = main(["guard", "approvals", "resume", "req-cli-home", "--home", str(home_dir), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["status"] == "sent"
    assert socket_paths == [str(socket_path)]


def test_default_codex_app_server_socket_probe_uses_codex_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codex_home = tmp_path / "custom-codex-home"
    socket_path = codex_home / "app-server-control" / "app-server-control.sock"
    socket_path.parent.mkdir(parents=True)
    socket_path.write_text("", encoding="utf-8")
    connect_paths: list[str] = []

    class _FakeSocket:
        def __enter__(self) -> _FakeSocket:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def connect(self, path: str) -> None:
            connect_paths.append(path)

    monkeypatch.setattr(codex_app_server_module.socket, "socket", lambda *_args, **_kwargs: _FakeSocket())

    assert (
        codex_app_server_module.default_codex_app_server_socket_path(environ={"CODEX_HOME": str(codex_home)})
        == socket_path
    )
    assert codex_app_server_module.default_codex_app_server_socket_available(
        environ={"CODEX_HOME": str(codex_home)}
    )
    assert connect_paths == [str(socket_path)]


def test_codex_resume_metadata_extracts_workspace_and_nested_command() -> None:
    metadata = codex_app_server_module.codex_resume_metadata_from_hook_payload(
        {
            "session_id": "thread-123",
            "turn_id": "turn-123",
            "cwd": "/tmp/project",
            "model": "gpt-5.3",
            "tool_name": "Bash",
            "tool_input": {"command": "npm install is-even"},
        },
        environ={"CODEX_HOME": "/tmp/codex-home"},
    )

    assert metadata == {
        "codex_thread_id": "thread-123",
        "codex_turn_id": "turn-123",
        "codex_home": "/tmp/codex-home",
        "codex_model": "gpt-5.3",
        "workspace": "/tmp/project",
        "command_text": "npm install is-even",
    }


def test_guard_doctor_codex_reports_resume_diagnostics(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    GuardStore(guard_home)

    rc = main(["guard", "doctor", "codex", "--home", str(home_dir), "--guard-home", str(guard_home), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["codex_resume"]["codex_binary_found"] is False
    assert output["codex_resume"]["app_server_support"] in {True, False}
    assert "remote-control socket" in output["codex_resume"]["app_server_support_reason"]
    assert output["codex_resume"]["app_server_socket_available"] in {True, False}
    assert output["codex_resume"]["headless_resume_support"] is False
    assert "Disabled by design" in output["codex_resume"]["headless_resume_support_reason"]
    assert output["codex_resume"]["latest_attempt"] is None


def test_guard_doctor_codex_reports_headless_resume_disabled(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    GuardStore(guard_home)

    rc = main(["guard", "doctor", "codex", "--home", str(home_dir), "--guard-home", str(guard_home), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["codex_resume"]["codex_binary_found"] is False
    assert output["codex_resume"]["app_server_support"] in {True, False}
    assert "remote-control socket" in output["codex_resume"]["app_server_support_reason"]
    assert output["codex_resume"]["app_server_socket_available"] in {True, False}
    assert output["codex_resume"]["headless_resume_support"] is False
    assert "does not continue the visible Codex App chat" in output["codex_resume"]["headless_resume_support_reason"]
    assert "remote_control_support" not in output["codex_resume"]


def test_guard_approvals_resume_rejects_unsafe_headless_thread_id(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(home_dir)
    store.add_approval_request(_request("req-cli-unsafe"), "2026-05-19T10:00:00+00:00")
    _seed_codex_operation(
        store,
        request_id="req-cli-unsafe",
        socket_path=None,
        workspace=str(workspace),
        codex_home="/tmp/codex-home",
        thread_id="unsafe\nthread",
    )
    store.resolve_approval_request(
        "req-cli-unsafe",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at="2026-05-19T10:01:00+00:00",
    )

    rc = main(["guard", "approvals", "resume", "req-cli-unsafe", "--home", str(home_dir), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["status"] == "skipped"
    assert output["reason"] == "unsafe_thread_id"
    assert output["strategy"] == "codex-app-server-thread"
    assert "retry the same request" in output["message"]


def test_guard_approvals_resume_requires_app_server_when_socket_unavailable(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    codex_home = tmp_path / "codex-home"
    workspace.mkdir()
    codex_home.mkdir()
    store = GuardStore(home_dir)
    store.add_approval_request(_request("req-cli-exec"), "2026-05-19T10:00:00+00:00")
    _seed_codex_operation(
        store,
        request_id="req-cli-exec",
        socket_path=None,
        workspace=str(workspace),
        codex_home=str(codex_home),
    )
    store.resolve_approval_request(
        "req-cli-exec",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at="2026-05-19T10:01:00+00:00",
    )

    rc = main(["guard", "approvals", "resume", "req-cli-exec", "--home", str(home_dir), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["status"] == "failed"
    assert output["reason"] == "socket_not_available"
    assert output["strategy"] == "codex-app-server-thread"
    assert "original chat" in output["message"]


def test_guard_approvals_resume_does_not_start_headless_codex_for_blocked_request(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    codex_home = tmp_path / "codex-home"
    workspace.mkdir()
    codex_home.mkdir()
    store = GuardStore(home_dir)
    store.add_approval_request(_request("req-cli-block"), "2026-05-19T10:00:00+00:00")
    _seed_codex_operation(
        store,
        request_id="req-cli-block",
        socket_path=None,
        workspace=str(workspace),
        codex_home=str(codex_home),
    )
    store.resolve_approval_request(
        "req-cli-block",
        resolution_action="block",
        resolution_scope="artifact",
        reason="blocked",
        resolved_at="2026-05-19T10:01:00+00:00",
    )

    rc = main(["guard", "approvals", "resume", "req-cli-block", "--home", str(home_dir), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["status"] == "skipped"
    assert output["reason"] == "blocked_not_resumed"
    assert output["supported"] is False
    assert "blocked this Codex request" in output["message"]


def test_guard_approvals_resume_reports_missing_app_server_without_spawning(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(home_dir)
    store.add_approval_request(_request("req-cli-no-home"), "2026-05-19T10:00:00+00:00")
    _seed_codex_operation(
        store,
        request_id="req-cli-no-home",
        socket_path=None,
        workspace=str(workspace),
        codex_home=str(tmp_path / "missing-codex-home"),
    )
    store.resolve_approval_request(
        "req-cli-no-home",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at="2026-05-19T10:01:00+00:00",
    )

    rc = main(["guard", "approvals", "resume", "req-cli-no-home", "--home", str(home_dir), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["status"] == "failed"
    assert output["reason"] == "socket_not_available"
    assert output["strategy"] == "codex-app-server-thread"
