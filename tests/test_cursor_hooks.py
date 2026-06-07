"""Regression tests for Cursor native hook installation and payload mapping."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import (
    _MANAGED_HOOK_EVENTS,
    _MANAGED_HOOK_TIMEOUT_SECONDS,
    _strip_managed_hook_entries,
    cursor_hook_response_from_guard,
    cursor_hook_should_block,
    install_cursor_hooks,
    prepare_cursor_hook_payload,
    uninstall_cursor_hooks,
)


def test_managed_hook_events_exclude_pretooluse() -> None:
    assert "preToolUse" not in _MANAGED_HOOK_EVENTS
    assert _MANAGED_HOOK_EVENTS == (
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
        "afterShellExecution",
    )


def test_prepare_cursor_hook_payload_maps_before_read_file() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "beforeReadFile",
            "file_path": "/tmp/secrets.env",
        }
    )
    assert payload["hook_event_name"] == "PreToolUse"
    assert payload["tool_name"] == "Read"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["file_path"] == "/tmp/secrets.env"
    assert tool_input["path"] == "/tmp/secrets.env"


def test_prepare_cursor_hook_payload_infers_shell_without_event_name() -> None:
    payload = prepare_cursor_hook_payload({"command": "echo hello", "cwd": "/tmp"})
    assert payload["tool_name"] == "Shell"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["command"] == "echo hello"
    assert tool_input["working_directory"] == "/tmp"


def test_prepare_cursor_hook_payload_infers_read_without_event_name() -> None:
    payload = prepare_cursor_hook_payload({"file_path": "/tmp/secrets.env"})
    assert payload["tool_name"] == "Read"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["file_path"] == "/tmp/secrets.env"


def test_prepare_cursor_hook_payload_maps_before_shell_execution() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "beforeShellExecution",
            "command": "echo hello",
            "cwd": "/tmp",
        }
    )
    assert payload["tool_name"] == "Shell"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["command"] == "echo hello"
    assert tool_input["working_directory"] == "/tmp"


def test_prepare_cursor_hook_payload_maps_after_shell_execution() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "afterShellExecution",
            "command": "echo hello",
            "cwd": "/tmp",
            "duration": 12,
        }
    )
    assert payload["hook_event_name"] == "afterShellExecution"
    assert payload["tool_name"] == "Shell"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["command"] == "echo hello"
    assert tool_input["working_directory"] == "/tmp"


def test_cursor_hook_script_source_skips_missing_workspace(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source

    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=tmp_path)
    source = cursor_hook_script_source(context)
    assert "Path(candidate).is_dir()" in source


def test_strip_managed_hook_entries_removes_hol_guard_pretooluse(tmp_path: Path) -> None:
    script_path = tmp_path / "hol-guard-cursor-hook.py"
    script_path.write_text("# Managed by HOL Guard\n", encoding="utf-8")
    entries = [
        {"command": "lean-ctx hook rewrite", "matcher": "Shell"},
        {
            "command": str(script_path.resolve()),
            "failClosed": True,
            "matcher": "Shell|MCP|mcp__.*|Bash|Read",
            "timeout": 35,
        },
    ]
    stripped = _strip_managed_hook_entries(entries, script_path=script_path)
    assert stripped == [{"command": "lean-ctx hook rewrite", "matcher": "Shell"}]


def test_install_cursor_hooks_strips_legacy_pretooluse_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    guard_home = tmp_path / "guard"
    workspace = tmp_path / "workspace"
    home.mkdir()
    guard_home.mkdir()
    workspace.mkdir()
    cursor_dir = home / ".cursor"
    cursor_dir.mkdir()
    script_path = cursor_dir / "hooks" / "hol-guard-cursor-hook.py"
    hooks_path = cursor_dir / "hooks.json"
    hooks_path.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "preToolUse": [
                        {"command": "lean-ctx hook rewrite", "matcher": "Shell"},
                        {
                            "command": str(script_path),
                            "failClosed": True,
                            "matcher": "Shell|Read",
                            "timeout": 35,
                        },
                    ]
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hooks._resolve_guard_cli_command",
        lambda: ["hol-guard"],
    )
    context = HarnessContext(home_dir=home, guard_home=guard_home, workspace_dir=workspace)
    result = install_cursor_hooks(context)
    installed = json.loads(hooks_path.read_text(encoding="utf-8"))
    pre_tool_use = installed["hooks"].get("preToolUse")
    if pre_tool_use is not None:
        assert all("hol-guard-cursor-hook.py" not in str(entry.get("command", "")) for entry in pre_tool_use)
    assert "beforeShellExecution" in installed["hooks"]
    assert result["managed_hook_events"] == list(_MANAGED_HOOK_EVENTS)
    for event_name in _MANAGED_HOOK_EVENTS:
        entry = installed["hooks"][event_name][-1]
        assert entry["timeout"] == _MANAGED_HOOK_TIMEOUT_SECONDS


def test_prepare_cursor_hook_payload_maps_before_mcp_execution() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "plugin-notion-workspace-notion",
            "url": "https://example.com/mcp",
        }
    )
    assert payload["tool_name"] == "plugin-notion-workspace-notion"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["url"] == "https://example.com/mcp"


def test_cursor_hook_response_from_guard_maps_read_ask_to_deny() -> None:
    response = cursor_hook_response_from_guard(
        policy_action="require-reapproval",
        guard_payload={"review_hint": "Approve in Guard"},
        hook_event_name="beforeReadFile",
    )
    assert response["permission"] == "deny"
    assert response["user_message"] == "Approve in Guard"


def test_cursor_hook_response_from_guard_allows_shell() -> None:
    response = cursor_hook_response_from_guard(
        policy_action="allow",
        guard_payload={},
        hook_event_name="beforeShellExecution",
    )
    assert response["permission"] == "allow"


def test_cursor_hook_would_prompt_user_for_warn_with_risk() -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_would_prompt_user

    assert cursor_hook_would_prompt_user(
        policy_action="warn",
        guard_payload={"risk_signals": ["destructive shell command"]},
    )
    assert not cursor_hook_would_prompt_user(policy_action="allow", guard_payload={})
    assert cursor_hook_would_prompt_user(policy_action="require-reapproval", guard_payload={})


def test_validated_hol_guard_src_path_rejects_non_guard_trees(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import _validated_hol_guard_src_path

    assert _validated_hol_guard_src_path(str(tmp_path)) is None
    src_root = tmp_path / "src"
    src_root.mkdir()
    (src_root / "codex_plugin_scanner").mkdir()
    assert _validated_hol_guard_src_path(str(src_root)) == str(src_root.resolve())


def test_cursor_after_shell_requires_observer_fields(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.models import GuardArtifact
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-after-shell-guard"
    command = "rm -rf ./hol-guard-cursor-native-test-marker"
    guard_commands_module._record_cursor_pending_shell_permission(
        store=store,
        payload={
            "conversation_id": conversation_id,
            "hook_event_name": "beforeShellExecution",
            "command": command,
            "cwd": str(workspace_dir),
        },
        reason="Requests a sensitive native tool action.",
        artifact=GuardArtifact(
            artifact_id="cursor:project:shell:rm",
            name="Shell",
            harness="cursor",
            artifact_type="tool_action_request",
            source_scope="project",
            config_path=str(workspace_dir / ".cursor" / "mcp.json"),
            command=command,
        ),
        artifact_hash="hash-cursor-shell",
    )
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "hook_event_name": "afterShellExecution",
                "command": command,
                "cwd": str(workspace_dir),
            }
        ),
        harness="cursor",
        home_dir=home_dir,
        guard_home=home_dir,
        workspace=workspace_dir,
    )
    assert saved is False


def test_cursor_hook_should_block() -> None:
    assert cursor_hook_should_block(policy_action="block") is True
    assert cursor_hook_should_block(policy_action="allow") is False


def test_cursor_hook_script_source_infers_event_before_prepare(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source

    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=tmp_path)
    source = cursor_hook_script_source(context)
    assert "inferred = _infer_cursor_hook_event_name(payload)" in source
    assert "hook_event_name = str(inferred.get(\"hook_event_name\")" in source
    assert "aftershellexecution" in source.lower()


def test_install_cursor_hooks_registers_after_shell_observer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    guard_home = tmp_path / "guard"
    workspace = tmp_path / "workspace"
    home.mkdir()
    guard_home.mkdir()
    workspace.mkdir()
    hooks_path = home / ".cursor" / "hooks.json"
    hooks_path.parent.mkdir(parents=True)
    hooks_path.write_text('{"version": 1, "hooks": {}}\n', encoding="utf-8")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hooks._resolve_guard_cli_command",
        lambda: ["hol-guard"],
    )
    context = HarnessContext(home_dir=home, guard_home=guard_home, workspace_dir=workspace)
    install_cursor_hooks(context)
    installed = json.loads(hooks_path.read_text(encoding="utf-8"))
    after_shell = installed["hooks"]["afterShellExecution"][-1]
    assert after_shell.get("failClosed") is not True


def test_cursor_native_shell_approval_persists_after_shell(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.models import GuardArtifact
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-native-shell"
    command = "rm -rf ./hol-guard-cursor-native-test-marker"
    guard_commands_module._record_cursor_pending_shell_permission(
        store=store,
        payload={
            "conversation_id": conversation_id,
            "hook_event_name": "beforeShellExecution",
            "command": command,
            "cwd": str(workspace_dir),
        },
        reason="Requests a sensitive native tool action.",
        artifact=GuardArtifact(
            artifact_id="cursor:project:shell:rm",
            name="Shell",
            harness="cursor",
            artifact_type="tool_action_request",
            source_scope="project",
            config_path=str(workspace_dir / ".cursor" / "mcp.json"),
            command=command,
        ),
        artifact_hash="hash-cursor-shell",
    )
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "hook_event_name": "afterShellExecution",
                "command": command,
                "cwd": str(workspace_dir),
                "duration": 15,
            }
        ),
        harness="cursor",
        home_dir=home_dir,
        guard_home=home_dir,
        workspace=workspace_dir,
    )
    policies = store.list_policy_decisions("cursor")

    assert saved is True
    assert len(policies) == 1
    assert policies[0]["action"] == "allow"
    assert policies[0]["source"] == "cursor-native-approval"
    assert (
        guard_commands_module._load_cursor_pending_shell_permission(
            store,
            conversation_id=conversation_id,
            command=command,
        )
        is None
    )


def test_cursor_native_shell_session_allow_survives_approval_gate_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.models import GuardArtifact
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-session-allow"
    command = "rm -rf ./hol-guard-cursor-native-test-marker"
    guard_commands_module._record_cursor_pending_shell_permission(
        store=store,
        payload={
            "conversation_id": conversation_id,
            "hook_event_name": "beforeShellExecution",
            "command": command,
            "cwd": str(workspace_dir),
        },
        reason="Requests a sensitive native tool action.",
        artifact=GuardArtifact(
            artifact_id="cursor:project:shell:rm",
            name="Shell",
            harness="cursor",
            artifact_type="tool_action_request",
            source_scope="project",
            config_path=str(workspace_dir / ".cursor" / "mcp.json"),
            command=command,
        ),
        artifact_hash="hash-cursor-shell",
    )

    def _blocked_policy(**kwargs: object) -> bool:
        del kwargs
        return False

    monkeypatch.setattr(guard_commands_module, "_persist_cursor_native_permission_policy", _blocked_policy)
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "hook_event_name": "afterShellExecution",
                "command": command,
                "cwd": str(workspace_dir),
                "duration": 12,
            }
        ),
        harness="cursor",
        home_dir=home_dir,
        guard_home=home_dir,
        workspace=workspace_dir,
    )
    assert saved is True
    assert guard_commands_module._cursor_native_shell_is_approved(
        store,
        prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "hook_event_name": "beforeShellExecution",
                "command": command,
                "cwd": str(workspace_dir),
            }
        ),
    )


def test_cursor_after_shell_rejects_boolean_duration(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.models import GuardArtifact
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-bool-duration"
    command = "rm -rf ./hol-guard-cursor-native-test-marker"
    guard_commands_module._record_cursor_pending_shell_permission(
        store=store,
        payload={
            "conversation_id": conversation_id,
            "hook_event_name": "beforeShellExecution",
            "command": command,
            "cwd": str(workspace_dir),
        },
        reason="Requests a sensitive native tool action.",
        artifact=GuardArtifact(
            artifact_id="cursor:project:shell:rm",
            name="Shell",
            harness="cursor",
            artifact_type="tool_action_request",
            source_scope="project",
            config_path=str(workspace_dir / ".cursor" / "mcp.json"),
            command=command,
        ),
        artifact_hash="hash-cursor-shell",
    )
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "hook_event_name": "afterShellExecution",
                "command": command,
                "cwd": str(workspace_dir),
                "duration": True,
            }
        ),
        harness="cursor",
        home_dir=home_dir,
        guard_home=home_dir,
        workspace=workspace_dir,
    )
    assert saved is False


def test_uninstall_cursor_hooks_restores_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    guard_home = tmp_path / "guard"
    workspace = tmp_path / "workspace"
    home.mkdir()
    guard_home.mkdir()
    workspace.mkdir()
    hooks_path = home / ".cursor" / "hooks.json"
    hooks_path.parent.mkdir(parents=True)
    hooks_path.write_text('{"version": 1, "hooks": {"preToolUse": []}}\n', encoding="utf-8")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hooks._resolve_guard_cli_command",
        lambda: ["hol-guard"],
    )
    context = HarnessContext(home_dir=home, guard_home=guard_home, workspace_dir=workspace)
    install_cursor_hooks(context)
    result = uninstall_cursor_hooks(context)
    assert result["restored"] is True
    assert json.loads(hooks_path.read_text(encoding="utf-8")) == {"version": 1, "hooks": {"preToolUse": []}}
