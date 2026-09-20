"""Runtime regression tests: guard hook claude notification stale notice falls."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
    GuardStore,
    Path,
    guard_commands_module,
    guard_runner_module,
    io,
    json,
    main,
    sqlite3,
    subprocess,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _install_codex_native_hooks,
    _make_pinnable_harness_executable,
    _run_guard_hook,
    _write_json,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_claude_notification_stale_notice_falls_back_to_generic_context(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    session_id = "session-claude-stale-notice"
    pre_tool_event = {
        "session_id": session_id,
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(pre_tool_event)))
    pre_tool_rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "claude-code",
        ]
    )
    capsys.readouterr()

    store = GuardStore(home_dir)
    pending_index_key = guard_commands_module._claude_pending_permission_index_key(session_id)
    pending_index = store.get_sync_payload(pending_index_key)
    assert isinstance(pending_index, dict)
    pending_keys = pending_index.get("pending_keys")
    assert isinstance(pending_keys, list)
    assert pending_keys
    store.delete_sync_payloads([str(pending_keys[0]), pending_index_key])

    notification_rc, notification_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={
            "session_id": session_id,
            "hook_event_name": "Notification",
            "notification_type": "permission_prompt",
            "title": "Permission needed",
            "message": "Claude needs your permission to use Read",
            "tool_name": "Read",
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert pre_tool_rc == 0
    assert notification_rc == 0
    assert "approval code:" not in notification_output["hookSpecificOutput"]["additionalContext"].lower()
    assert (
        "HOL Guard intercepted the sensitive request and is routing it into a HOL Guard approval question"
        in notification_output["hookSpecificOutput"]["additionalContext"]
    )


def test_guard_hook_claude_notification_notice_falls_back_when_tool_name_is_missing(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    pre_tool_event = {
        "session_id": "session-claude-5",
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(pre_tool_event)))

    pre_tool_rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "claude-code",
        ]
    )
    capsys.readouterr()

    notification_event = {
        "session_id": "session-claude-5",
        "hook_event_name": "Notification",
        "notification_type": "permission_prompt",
        "title": "Permission needed",
        "message": "Claude needs your permission to use Read",
    }
    notification_rc, notification_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=notification_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert pre_tool_rc == 0
    assert notification_rc == 0
    assert "HOL Guard approval question" in notification_output["systemMessage"]
    assert "keep blocked" in notification_output["systemMessage"].lower()


def test_guard_hook_claude_notice_storage_failures_fall_back_to_generic_prompt(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    def _raise_locked(*args, **kwargs):
        raise sqlite3.Error("locked")

    monkeypatch.setattr(GuardStore, "set_sync_payload", _raise_locked)
    pre_tool_event = {
        "session_id": "session-claude-4",
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(pre_tool_event)))

    pre_tool_rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "claude-code",
        ]
    )
    pre_tool_output = json.loads(capsys.readouterr().out)

    notification_event = {
        "session_id": "session-claude-4",
        "hook_event_name": "Notification",
        "notification_type": "permission_prompt",
        "title": "Permission needed",
        "message": "Claude needs your permission to use Read",
        "tool_name": "Read",
    }
    notification_rc, notification_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=notification_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert pre_tool_rc == 0
    assert pre_tool_output["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert notification_rc == 0
    assert notification_output["systemMessage"] == (
        "HOL Guard intercepted Claude's attempt to use Read and is routing it to a HOL Guard approval question. "
        "This approval flow came from HOL Guard, not from Claude alone. "
        "HOL Guard will ask the user to choose Allow once, Allow during this session, or Keep blocked before Claude "
        "retries the action."
    )


def test_guard_hook_emits_copilot_native_allow_response_for_safe_requests(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "view",
        "toolArgs": json.dumps({"path": str(workspace_dir / "README.md")}),
        "sourceScope": "project",
    }
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
            "copilot",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output == {"permissionDecision": "allow"}


def test_guard_hook_emits_copilot_native_allow_response_for_read_only_sed_requests(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "sed -n '1p' README.md"}),
        "sourceScope": "project",
    }
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
            "copilot",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output == {"permissionDecision": "allow"}


def test_guard_run_returns_structured_error_when_executable_missing(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
    _write_json(home_dir / ".claude" / "settings.json", {})
    _write_json(workspace_dir / ".mcp.json", {"mcpServers": {}})
    _make_pinnable_harness_executable(tmp_path, monkeypatch, "claude")
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("claude not found")),
    )

    rc = main(
        [
            "guard",
            "run",
            "claude-code",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--default-action",
            "allow",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 127
    assert output["launched"] is False
    assert output["return_code"] == 127
    assert "claude not found" in output["launch_error"]


def test_guard_run_prompt_allow_once_launches_and_records_override(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    codex_executable = _make_pinnable_harness_executable(tmp_path, monkeypatch, "codex")
    _write_text(
        home_dir / ".codex" / "config.toml",
        f"[mcp_servers.global_tools]\ncommand = {json.dumps(str(codex_executable))}\nargs = []\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        f"[mcp_servers.workspace_skill]\ncommand = {json.dumps(str(codex_executable))}\nargs = []\n",
    )
    _install_codex_native_hooks(home_dir, workspace_dir)
    monkeypatch.setattr(guard_commands_module.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("rich.console.Console.input", lambda self, prompt="": "1")
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    )

    rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
        ]
    )
    output = capsys.readouterr().out
    receipts = GuardStore(Path(home_dir)).list_receipts(limit=10)

    if rc == 1:
        assert output == ""
        assert receipts == []
        return
    assert rc == 0
    assert "Launch allowed" in output
    assert len(receipts) == 2
    assert any(item.get("user_override") == "allow-once" for item in receipts)


def test_guard_run_prompt_allow_artifact_persists_for_next_run(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    codex_executable = _make_pinnable_harness_executable(tmp_path, monkeypatch, "codex")
    _write_text(
        home_dir / ".codex" / "config.toml",
        f"[mcp_servers.global_tools]\ncommand = {json.dumps(str(codex_executable))}\nargs = []\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        f"[mcp_servers.workspace_skill]\ncommand = {json.dumps(str(codex_executable))}\nargs = []\n",
    )
    _install_codex_native_hooks(home_dir, workspace_dir)
    monkeypatch.setattr(guard_commands_module.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("rich.console.Console.input", lambda self, prompt="": "2")
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    )

    first_rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
        ]
    )
    first_output = capsys.readouterr().out

    if first_rc == 1:
        assert first_output == ""
        assert GuardStore(home_dir).list_policy_decisions("codex") == []
        return

    second_rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--dry-run",
            "--json",
        ]
    )
    second_output = json.loads(capsys.readouterr().out)

    assert first_rc == 0
    assert "Launch allowed" in first_output
    assert second_rc == 0
    assert second_output["blocked"] is False
    assert {item["policy_action"] for item in second_output["artifacts"]} <= {"allow", "warn"}
    persisted = GuardStore(home_dir).list_policy_decisions("codex")
    assert len(persisted) == 2
    assert all(str(item["artifact_hash"]).startswith(APPROVAL_CONTEXT_TOKEN_PREFIX) for item in persisted)


def test_guard_run_headless_blocks_with_review_hint_without_opening_browser(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    opened_urls: list[str] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_support_hook_payload.open_browser_url",
        lambda url: opened_urls.append(url) or True,
    )

    rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert output["approval_center_url"] == "http://127.0.0.1:4455"
    assert output["blocked"] is True
    assert output["approval_delivery"]["destination"] == "harness"
    assert opened_urls == []
