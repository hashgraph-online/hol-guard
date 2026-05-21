"""Phase 14 package approval resume regressions."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_app_server as codex_app_server_module
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _request(request_id: str, launch_target: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name=request_id,
        artifact_hash=f"hash-{request_id}",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("package_request",),
        source_scope="project",
        config_path="/workspace/.codex/config.toml",
        workspace="/workspace",
        launch_target=launch_target,
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


def _seed_codex_operation(store: GuardStore, *, request_id: str, socket_path: Path, command_text: str) -> None:
    session = store.upsert_guard_session(
        session_id=f"session-{request_id}",
        harness="codex",
        surface="harness-adapter",
        status="approval_wait_timeout",
        client_name="codex-hook",
        client_title="Codex hook",
        client_version="1.0.0",
        workspace="/workspace",
        capabilities=["approval-resolution"],
        now="2026-05-19T10:00:00+00:00",
    )
    store.upsert_guard_operation(
        operation_id=f"operation-{request_id}",
        session_id=str(session["session_id"]),
        harness="codex",
        operation_type="tool_call",
        status="approval_wait_timeout",
        approval_request_ids=[request_id],
        resume_token=f"resume-{request_id}",
        metadata={
            "codex_thread_id": "thread-1",
            "codex_turn_id": "turn-1",
            "codex_app_server_socket": str(socket_path),
            "command_text": command_text,
        },
        now="2026-05-19T10:00:00+00:00",
    )


def test_phase14_package_approval_resume_targets_only_matching_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_payloads: list[dict[str, object]] = []

    def _fake_send(**kwargs):
        captured_payloads.extend(kwargs["payloads"])
        return {"id": 2, "result": {"turnId": "turn-2"}}, "turn_completed"

    monkeypatch.setattr(codex_app_server_module, "_send_app_server_websocket_messages", _fake_send)
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-minimist", "npm install minimist@1.2.8"), "2026-05-19T10:00:00+00:00")
    store.add_approval_request(_request("req-lodash", "npm install lodash@4.17.21"), "2026-05-19T10:00:00+00:00")
    socket_path = tmp_path / "codex-control.sock"
    socket_path.write_text("", encoding="utf-8")
    _seed_codex_operation(
        store,
        request_id="req-minimist",
        socket_path=socket_path,
        command_text="npm install minimist@1.2.8",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-minimist/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    serialized_payloads = json.dumps(captured_payloads)

    assert payload["codex_resume"]["status"] == "sent"
    assert "req-minimist" in serialized_payloads
    assert "req-lodash" not in serialized_payloads
    assert store.get_approval_request("req-minimist")["status"] != "pending"
    assert store.get_approval_request("req-lodash")["status"] == "pending"
