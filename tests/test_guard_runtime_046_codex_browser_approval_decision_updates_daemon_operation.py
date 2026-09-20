"""Runtime regression tests: codex browser approval decision updates daemon operation."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardApprovalRequest,
    GuardConfig,
    GuardStore,
    Path,
    apply_approval_resolution,
    argparse,
    guard_commands_module,
    interaction_module,
    io,
    json,
    main,
    pytest,
    sys,
    wait_for_approval_requests,
)
from tests.guard_runtime_test_scenarios import (
    _codex_browser_approval_context_token,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _run_guard_hook,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_codex_browser_approval_decision_updates_daemon_operation_status(tmp_path, monkeypatch):
    monkeypatch.setattr(interaction_module, "wait_for_approval_requests", wait_for_approval_requests)
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    context_token = _codex_browser_approval_context_token(current_action="review")
    request = GuardApprovalRequest(
        request_id="request-1",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="Bash request",
        artifact_hash=context_token,
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("command",),
        source_scope="project",
        config_path="~/.codex/config.toml",
        review_command="hol-guard approvals approve request-1",
        approval_url="http://127.0.0.1:4455/requests/request-1",
        launch_target="bash ./guard-canary.sh",
    )
    store.add_approval_request(request, "2026-04-30T00:00:00+00:00")
    apply_approval_resolution(
        store=store,
        request_id="request-1",
        action="allow",
        scope="artifact",
        workspace=None,
        reason="approved in browser",
    )
    statuses: list[dict[str, object]] = []

    class _FakeDaemonClient:
        def update_operation_status(self, **kwargs) -> None:
            statuses.append(dict(kwargs))

    payload: dict[str, object] = {
        "artifact_id": "artifact-1",
        "artifact_hash": context_token,
        "operation_id": "operation-1",
        "operation": {"operation_id": "operation-1", "status": "waiting_on_approval"},
        "approval_requests": [request.to_dict()],
    }

    decision = guard_commands_module._codex_browser_approval_decision(
        args=argparse.Namespace(harness="codex", json=False),
        event_name="PostToolUse",
        policy_action="review",
        response_payload=payload,
        store=store,
        config=GuardConfig(home_dir, None, approval_wait_timeout_seconds=1),
        daemon_client=_FakeDaemonClient(),
        expected_artifact_hash=context_token,
        fresh_context_provider=lambda: {
            "artifact_id": "artifact-1",
            "artifact_hash": context_token,
            "current_action": "review",
            "authoritative_action": "allow",
        },
    )

    assert decision == "allow"
    assert statuses == [{"operation_id": "operation-1", "status": "completed"}]
    assert payload["operation"]["status"] == "completed"
    assert payload["continuation"]["resolution_action"] == "allow"


def test_codex_browser_block_decision_updates_daemon_operation_status(tmp_path, monkeypatch):
    monkeypatch.setattr(interaction_module, "wait_for_approval_requests", wait_for_approval_requests)
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    context_token = _codex_browser_approval_context_token(current_action="require-reapproval")
    request = GuardApprovalRequest(
        request_id="request-1",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="Bash request",
        artifact_hash=context_token,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("command",),
        source_scope="project",
        config_path="~/.codex/config.toml",
        review_command="hol-guard approvals approve request-1",
        approval_url="http://127.0.0.1:4455/requests/request-1",
        launch_target="bash ./guard-canary.sh",
    )
    store.add_approval_request(request, "2026-04-30T00:00:00+00:00")
    apply_approval_resolution(
        store=store,
        request_id="request-1",
        action="block",
        scope="artifact",
        workspace=None,
        reason="blocked in browser",
    )
    statuses: list[dict[str, object]] = []

    class _FakeDaemonClient:
        def update_operation_status(self, **kwargs) -> None:
            statuses.append(dict(kwargs))

    payload: dict[str, object] = {
        "artifact_id": "artifact-1",
        "artifact_hash": context_token,
        "operation_id": "operation-1",
        "operation": {"operation_id": "operation-1", "status": "waiting_on_approval"},
        "approval_requests": [request.to_dict()],
    }

    decision = guard_commands_module._codex_browser_approval_decision(
        args=argparse.Namespace(harness="codex", json=False),
        event_name="PostToolUse",
        policy_action="require-reapproval",
        response_payload=payload,
        store=store,
        config=GuardConfig(home_dir, None, approval_wait_timeout_seconds=1),
        daemon_client=_FakeDaemonClient(),
        expected_artifact_hash=context_token,
    )

    assert decision == "block"
    assert statuses == [{"operation_id": "operation-1", "status": "blocked"}]
    assert payload["operation"]["status"] == "blocked"
    assert payload["continuation"]["resolution_action"] == "block"


def test_codex_browser_approval_uses_configured_wait_timeout(tmp_path, monkeypatch):
    captured_timeout: list[int] = []
    statuses: list[dict[str, object]] = []
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))

    def _fake_wait_for_approval_requests(**kwargs) -> dict[str, object]:
        captured_timeout.append(int(kwargs["timeout_seconds"]))
        return {"resolved": False, "pending_request_ids": ["request-1"], "items": []}

    class _FakeDaemonClient:
        def update_operation_status(self, **kwargs) -> None:
            statuses.append(dict(kwargs))

    monkeypatch.setattr(guard_commands_module, "wait_for_approval_requests", _fake_wait_for_approval_requests)

    decision = guard_commands_module._codex_browser_approval_decision(
        args=argparse.Namespace(harness="codex", json=False),
        event_name="PreToolUse",
        policy_action="block",
        response_payload={"operation_id": "operation-1", "approval_requests": [{"request_id": "request-1"}]},
        store=GuardStore(tmp_path / "home"),
        config=GuardConfig(tmp_path / "home", None, approval_wait_timeout_seconds=120),
        daemon_client=_FakeDaemonClient(),
    )

    assert decision is None
    assert captured_timeout == []
    assert statuses == []


def test_codex_browser_approval_fallback_uses_configured_wait_timeout(tmp_path, monkeypatch):
    captured_timeout: list[int] = []
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))

    def _fake_wait_for_approval_requests(**kwargs) -> dict[str, object]:
        captured_timeout.append(int(kwargs["timeout_seconds"]))
        return {"resolved": False, "pending_request_ids": ["request-1"], "items": []}

    monkeypatch.setattr(guard_commands_module, "wait_for_approval_requests", _fake_wait_for_approval_requests)

    decision = guard_commands_module._codex_browser_approval_decision(
        args=argparse.Namespace(harness="codex", json=False),
        event_name="PreToolUse",
        policy_action="block",
        response_payload={"approval_requests": [{"request_id": "request-1"}]},
        store=GuardStore(tmp_path / "home"),
        config=GuardConfig(tmp_path / "home", None, approval_wait_timeout_seconds=120),
    )

    assert decision is None
    assert captured_timeout == []


def test_guard_hook_codex_post_tool_use_blocks_named_secret_output(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "sed -n '1,20p' .npmrc"},
        "tool_response": "token = fixture-only\n",
        "source_scope": "project",
    }
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 0
    assert payload["continue"] is True
    assert "credential-looking output" in payload["stopReason"]


def test_guard_hook_codex_user_prompt_submit_blocks_credential_looking_dotfile(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(workspace_dir / ".authrc", "fake_credential\n")
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Use bash to print the full contents of ./.authrc exactly.",
        "source_scope": "project",
    }
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload["decision"] == "block"
    assert "HOL Guard" in payload["reason"]
    assert "credential-looking local file" in payload["reason"]
    assert "http://127.0.0.1:4455/requests/" in payload["reason"]


def test_guard_hook_codex_user_prompt_submit_allows_generic_dotfile_with_canary_text(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(workspace_dir / ".nvmrc", "fake_credential\n")
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "read .nvmrc",
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload == {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}


def test_guard_hook_codex_user_prompt_submit_blocks_bare_credential_dotfile(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(workspace_dir / ".authrc", "fake_credential\n")
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "read .authrc",
        "source_scope": "project",
    }
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload["decision"] == "block"
    assert "HOL Guard" in payload["reason"]
    assert "credential-looking local file" in payload["reason"]


def test_guard_hook_codex_user_prompt_submit_blocks_envrc_credential_dotfile(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(workspace_dir / ".envrc", "token = fixture-only\n")
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "read .envrc",
        "source_scope": "project",
    }
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload["decision"] == "block"
    assert "HOL Guard" in payload["reason"]
    assert "credential-looking local file" in payload["reason"]


def test_guard_hook_codex_prompt_dotfile_scan_uses_bounded_file_read(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(workspace_dir / ".authrc", "token = fixture-only\n")
    monkeypatch.setattr(Path, "read_bytes", lambda _path: (_ for _ in ()).throw(AssertionError("unbounded read")))
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "read .authrc",
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload["decision"] == "block"
    assert "credential-looking local file" in payload["reason"]


@pytest.mark.parametrize("prompt", ["read .authrc.", "print ./.authrc, please"])
def test_guard_hook_codex_prompt_dotfile_scan_ignores_trailing_punctuation(
    prompt,
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(workspace_dir / ".authrc", "token = fixture-only\n")
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": prompt,
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload["decision"] == "block"
    assert "credential-looking local file" in payload["reason"]
