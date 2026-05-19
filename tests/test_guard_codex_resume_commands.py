"""CLI tests for Codex resume retry and diagnostics."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import codex_app_server as codex_app_server_module
from codex_plugin_scanner.guard import codex_resume as codex_resume_module
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
    assert output["codex_resume"]["codex_binary_found"] in {True, False}
    assert output["codex_resume"]["app_server_support"] in {True, False}
    assert output["codex_resume"]["remote_control_support"] in {True, False}
    assert output["codex_resume"]["headless_resume_support"] in {True, False}
    assert output["codex_resume"]["latest_attempt"] is None


def test_guard_doctor_codex_handles_launch_oserror(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    GuardStore(guard_home)
    _stub_codex_binary(monkeypatch)

    def _raise_oserror(command, **kwargs):
        raise PermissionError("exec denied")

    monkeypatch.setattr(codex_resume_module.subprocess, "run", _raise_oserror)

    rc = main(["guard", "doctor", "codex", "--home", str(home_dir), "--guard-home", str(guard_home), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["codex_resume"]["codex_binary_found"] is True
    assert output["codex_resume"]["app_server_support"] is False
    assert output["codex_resume"]["remote_control_support"] is False
    assert output["codex_resume"]["headless_resume_support"] is False


def test_guard_approvals_resume_rejects_unsafe_thread_id(
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
    assert output["status"] == "failed"
    assert output["reason"] == "unsafe_thread_id"


def test_guard_approvals_resume_falls_back_to_exec_resume_when_app_server_unavailable(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
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

    home_dir = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(home_dir)
    store.add_approval_request(_request("req-cli-exec"), "2026-05-19T10:00:00+00:00")
    _seed_codex_operation(
        store,
        request_id="req-cli-exec",
        socket_path=None,
        workspace=str(workspace),
        codex_home="/tmp/codex-home",
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
    assert output["status"] == "sent"
    assert output["strategy"] == "codex-exec-resume"
    assert recorded["command"][:3] == ["codex", "exec", "resume"]
    assert "--dangerously-bypass-approvals-and-sandbox" in recorded["command"]
    assert "thread-1" in recorded["command"]
    assert recorded["command"][-1] == "-"
    assert isinstance(recorded["input"], str)
    assert "approved request `req-cli-exec`" in recorded["input"]
    assert recorded["cwd"] == str(workspace)
