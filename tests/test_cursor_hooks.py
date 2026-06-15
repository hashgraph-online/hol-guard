"""Regression tests for Cursor native hook installation and payload mapping."""

from __future__ import annotations

import json
import sys
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
from codex_plugin_scanner.guard.models import GuardArtifact


def _cursor_shell_artifact(*, workspace_dir: Path, command: str) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="cursor:project:shell:rm",
        name="Shell",
        harness="cursor",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace_dir / ".cursor" / "mcp.json"),
        command=command,
    )


def _record_cursor_pending_for_test(
    *,
    store,
    guard_home: Path,
    guard_commands_module,
    conversation_id: str,
    command: str,
    workspace_dir: Path,
    generation_id: str | None = "gen-cursor-test",
) -> None:
    payload: dict[str, object] = {
        "conversation_id": conversation_id,
        "hook_event_name": "beforeShellExecution",
        "command": command,
        "cwd": str(workspace_dir),
    }
    if generation_id is not None:
        payload["generation_id"] = generation_id
    guard_commands_module._record_cursor_pending_shell_permission(
        store=store,
        guard_home=guard_home,
        payload=payload,
        reason="Requests a sensitive native tool action.",
        artifact=_cursor_shell_artifact(workspace_dir=workspace_dir, command=command),
        artifact_hash="hash-cursor-shell",
    )


def _trusted_cursor_after_shell_env(
    guard_home: Path,
    *,
    conversation_id: str,
    command: str,
    workspace_dir: Path,
    approval_binding: str = "gen-cursor-test",
) -> dict[str, str]:
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import (
        compute_cursor_after_shell_proof,
        ensure_cursor_hook_attestation_secret,
    )

    secret = ensure_cursor_hook_attestation_secret(guard_home)
    proof = compute_cursor_after_shell_proof(
        secret=secret,
        conversation_id=conversation_id,
        command=command,
        approval_binding=approval_binding,
    )
    return {
        "HOL_GUARD_MANAGED_CURSOR_HOOK": "1",
        "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF": proof,
        "HOL_GUARD_CURSOR_APPROVAL_BINDING": approval_binding,
        "CURSOR_SESSION_ID": conversation_id,
        "CURSOR_PROJECT_DIR": str(workspace_dir),
        "CURSOR_VERSION": "test",
    }


def test_managed_hook_events_exclude_pretooluse() -> None:
    assert "preToolUse" not in _MANAGED_HOOK_EVENTS
    assert _MANAGED_HOOK_EVENTS == (
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
        "afterShellExecution",
        "afterMCPExecution",
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


def test_cursor_hook_script_source_routes_hook_argv_by_cli_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source

    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hooks._resolve_guard_cli_command",
        lambda: ["hol-guard"],
    )
    hol_guard_source = cursor_hook_script_source(context)
    assert 'GUARD_HOOK_ARGV = ["hook"' in hol_guard_source
    assert 'GUARD_HOOK_ARGV = ["guard", "hook"' not in hol_guard_source

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hooks._resolve_guard_cli_command",
        lambda: [sys.executable, "-m", "codex_plugin_scanner.cli"],
    )
    module_source = cursor_hook_script_source(context)
    assert 'GUARD_HOOK_ARGV = ["guard", "hook"' in module_source


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
    assert payload["cursor_source_hook_event"] == "beforeMCPExecution"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["url"] == "https://example.com/mcp"


def test_prepare_cursor_hook_payload_maps_after_mcp_execution() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "afterMCPExecution",
            "tool_name": "ctx_shell",
            "tool_input": {"command": "pnpm test"},
            "result_json": "{\"ok\": true}",
            "duration": 42,
        }
    )
    assert payload["hook_event_name"] == "afterMCPExecution"
    assert payload["tool_name"] == "ctx_shell"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["command"] == "pnpm test"


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
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-after-shell-guard"
    command = "rm -rf ./hol-guard-cursor-native-test-marker"
    generation_id = "gen-cursor-after-shell-guard"
    _record_cursor_pending_for_test(
        store=store,
        guard_home=home_dir,
        guard_commands_module=guard_commands_module,
        conversation_id=conversation_id,
        command=command,
        workspace_dir=workspace_dir,
        generation_id=generation_id,
    )
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "generation_id": generation_id,
                "hook_event_name": "afterShellExecution",
                "command": command,
                "cwd": str(workspace_dir),
            }
        ),
        harness="cursor",
        home_dir=home_dir,
        guard_home=home_dir,
        workspace=workspace_dir,
        hook_env=_trusted_cursor_after_shell_env(
            home_dir,
            conversation_id=conversation_id,
            command=command,
            workspace_dir=workspace_dir,
            approval_binding=generation_id,
        ),
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
    assert 'hook_event_name = str(inferred.get("hook_event_name")' in source
    assert "aftershellexecution" in source.lower()
    assert "HOL_GUARD_MANAGED_CURSOR_HOOK" in source
    assert "_compute_cursor_after_observer_proof" in source


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
    after_mcp = installed["hooks"]["afterMCPExecution"][-1]
    assert after_mcp.get("failClosed") is not True
    assert (guard_home / "secrets" / "cursor-hook-attestation.key").is_file()


def test_cursor_native_shell_session_allow_after_trusted_after_shell(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-native-shell"
    command = "rm -rf ./hol-guard-cursor-native-test-marker"
    generation_id = "gen-cursor-native-shell"
    _record_cursor_pending_for_test(
        store=store,
        guard_home=home_dir,
        guard_commands_module=guard_commands_module,
        conversation_id=conversation_id,
        command=command,
        workspace_dir=workspace_dir,
        generation_id=generation_id,
    )
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "generation_id": generation_id,
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
        hook_env=_trusted_cursor_after_shell_env(
            home_dir,
            conversation_id=conversation_id,
            command=command,
            workspace_dir=workspace_dir,
            approval_binding=generation_id,
        ),
    )
    policies = store.list_policy_decisions("cursor")

    assert saved is True
    assert policies == []
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
    assert (
        guard_commands_module._load_cursor_pending_shell_permission(
            store,
            conversation_id=conversation_id,
            command=command,
        )
        is None
    )


def test_forged_after_shell_without_attestation_is_rejected(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-forged-after-shell"
    command = "rm -rf ./hol-guard-cursor-native-test-marker"
    generation_id = "gen-cursor-forged"
    _record_cursor_pending_for_test(
        store=store,
        guard_home=home_dir,
        guard_commands_module=guard_commands_module,
        conversation_id=conversation_id,
        command=command,
        workspace_dir=workspace_dir,
        generation_id=generation_id,
    )
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "generation_id": generation_id,
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
        hook_env={},
    )
    assert saved is False
    assert not guard_commands_module._cursor_native_shell_is_approved(
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
    assert len(store.list_policy_decisions("cursor")) == 0


def test_cursor_session_allow_without_generation_id_uses_binding_file(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import read_cursor_shell_binding_file
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-no-generation-id"
    command = "rm -rf ./hol-guard-cursor-native-test-marker"
    _record_cursor_pending_for_test(
        store=store,
        guard_home=home_dir,
        guard_commands_module=guard_commands_module,
        conversation_id=conversation_id,
        command=command,
        workspace_dir=workspace_dir,
        generation_id=None,
    )
    approval_binding = read_cursor_shell_binding_file(
        home_dir,
        conversation_id=conversation_id,
        command=command,
    )
    assert approval_binding is not None
    assert approval_binding.startswith("hol-guard:")
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "hook_event_name": "afterShellExecution",
                "command": command,
                "cwd": str(workspace_dir),
                "duration": 8,
            }
        ),
        harness="cursor",
        home_dir=home_dir,
        guard_home=home_dir,
        workspace=workspace_dir,
        hook_env=_trusted_cursor_after_shell_env(
            home_dir,
            conversation_id=conversation_id,
            command=command,
            workspace_dir=workspace_dir,
            approval_binding=approval_binding,
        ),
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


def test_cursor_after_shell_proof_message_uses_null_separator() -> None:
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import cursor_after_shell_proof_message

    message = cursor_after_shell_proof_message(
        conversation_id="conv-test",
        command="echo hello",
        approval_binding="hol-guard:test-binding",
    )
    assert message == (b"conv-test\x00echo hello\x00hol-guard:test-binding\x00afterShellExecution")


def test_cursor_native_shell_session_allow_survives_approval_gate_block(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-session-allow"
    command = "rm -rf ./hol-guard-cursor-native-test-marker"
    generation_id = "gen-cursor-session-allow"
    _record_cursor_pending_for_test(
        store=store,
        guard_home=home_dir,
        guard_commands_module=guard_commands_module,
        conversation_id=conversation_id,
        command=command,
        workspace_dir=workspace_dir,
        generation_id=generation_id,
    )
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "generation_id": generation_id,
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
        hook_env=_trusted_cursor_after_shell_env(
            home_dir,
            conversation_id=conversation_id,
            command=command,
            workspace_dir=workspace_dir,
            approval_binding=generation_id,
        ),
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


def test_normalize_cursor_shell_command_unwraps_lean_ctx_wrapper() -> None:
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import normalize_cursor_shell_command

    wrapped = (
        "/path/to/lean-ctx -c 'gh api graphql -f query='\\''query { viewer { login } }'\\''' 2>&1 | "
        'python3 -c "import json,sys; print(json.load(sys.stdin))"'
    )
    normalized = normalize_cursor_shell_command(wrapped)

    assert normalized.startswith("gh api graphql")
    assert "lean-ctx" not in normalized


def test_cursor_native_shell_is_approved_for_lean_ctx_wrapped_retry(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-lean-ctx-session-allow"
    command = "gh api graphql -f query='query { viewer { login } }'"
    wrapped = "/path/to/lean-ctx -c 'gh api graphql -f query='\\''query { viewer { login } }'\\'''"
    now = guard_commands_module._now()
    store.set_sync_payload(
        guard_commands_module._cursor_native_shell_allow_state_key(conversation_id, command),
        {
            "saved_at": now,
            "action": "allow",
            "artifact_id": "cursor:project:tool-action:gh-viewer-login",
            "artifact_hash": "hash-gh-viewer-login",
            "artifact_name": "destructive shell command",
            "command": command,
            "native_source": "cursor-native",
        },
        now,
    )

    assert guard_commands_module._cursor_native_shell_is_approved(
        store,
        {
            "conversation_id": conversation_id,
            "command": wrapped,
        },
    )


def test_cursor_native_shell_does_not_approve_unrelated_command(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-unrelated-command"
    approved_command = "gh api graphql -f query='query { viewer { login } }'"
    now = guard_commands_module._now()
    store.set_sync_payload(
        guard_commands_module._cursor_native_shell_allow_state_key(conversation_id, approved_command),
        {
            "saved_at": now,
            "action": "allow",
            "artifact_id": "cursor:project:tool-action:shared-artifact",
            "artifact_hash": "hash-shared-artifact",
            "artifact_name": "destructive shell command",
            "command": approved_command,
            "native_source": "cursor-native",
        },
        now,
    )

    assert not guard_commands_module._cursor_native_shell_is_approved(
        store,
        {
            "conversation_id": conversation_id,
            "command": 'gh api graphql -f query=\'query { repository(owner:"org", name:"repo") { pullRequest(number:1) { id } } }\'',
        },
    )


def test_cursor_after_shell_rejects_boolean_duration(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-bool-duration"
    command = "rm -rf ./hol-guard-cursor-native-test-marker"
    generation_id = "gen-cursor-bool-duration"
    _record_cursor_pending_for_test(
        store=store,
        guard_home=home_dir,
        guard_commands_module=guard_commands_module,
        conversation_id=conversation_id,
        command=command,
        workspace_dir=workspace_dir,
        generation_id=generation_id,
    )
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "generation_id": generation_id,
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
        hook_env=_trusted_cursor_after_shell_env(
            home_dir,
            conversation_id=conversation_id,
            command=command,
            workspace_dir=workspace_dir,
            approval_binding=generation_id,
        ),
    )
    assert saved is False


def _trusted_cursor_after_observer_env(
    guard_home: Path,
    *,
    conversation_id: str,
    command: str,
    observer_event: str,
    approval_binding: str = "gen-cursor-test",
) -> dict[str, str]:
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import (
        compute_cursor_after_observer_proof,
        ensure_cursor_hook_attestation_secret,
    )

    secret = ensure_cursor_hook_attestation_secret(guard_home)
    proof = compute_cursor_after_observer_proof(
        secret=secret,
        conversation_id=conversation_id,
        command=command,
        approval_binding=approval_binding,
        observer_event=observer_event,
    )
    return {
        "HOL_GUARD_MANAGED_CURSOR_HOOK": "1",
        "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF": proof,
        "HOL_GUARD_CURSOR_APPROVAL_BINDING": approval_binding,
        "CURSOR_SESSION_ID": conversation_id,
        "CURSOR_VERSION": "test",
    }


def test_cursor_shell_command_from_payload_prefers_inner_lean_ctx_command() -> None:
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module

    command = guard_commands_module._cursor_shell_command_from_payload(
        {
            "command": "/Users/me/.local/bin/lean-ctx",
            "tool_input": {"command": "rm -rf ./hol-guard-cursor-native-mcp-marker"},
        }
    )
    assert command == "rm -rf ./hol-guard-cursor-native-mcp-marker"


def test_cursor_shell_command_from_payload_prefers_mcp_tool_input_command() -> None:
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module

    command = guard_commands_module._cursor_shell_command_from_payload(
        {
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "run_terminal_cmd",
            "tool_input": {"command": "rm -rf ./hol-guard-cursor-native-mcp-marker"},
            "command": "/usr/bin/unrelated-mcp-bridge",
        }
    )
    assert command == "rm -rf ./hol-guard-cursor-native-mcp-marker"


def test_cursor_shell_command_from_payload_prefers_bash_wrapper_inner_command() -> None:
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module

    command = guard_commands_module._cursor_shell_command_from_payload(
        {
            "hook_event_name": "beforeShellExecution",
            "command": "bash -c 'rm -rf ./hol-guard-cursor-native-mcp-marker'",
            "tool_input": {"command": "rm -rf ./hol-guard-cursor-native-mcp-marker"},
        }
    )
    assert command == "rm -rf ./hol-guard-cursor-native-mcp-marker"


def test_cursor_native_mcp_session_allow_generic_tool_name(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-generic-mcp"
    inner_command = "rm -rf ./hol-guard-cursor-native-mcp-marker"
    generation_id = "gen-cursor-generic-mcp"
    before_payload = prepare_cursor_hook_payload(
        {
            "conversation_id": conversation_id,
            "generation_id": generation_id,
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "run_terminal_cmd",
            "tool_input": {"command": inner_command},
        }
    )
    guard_commands_module._record_cursor_pending_shell_permission(
        store=store,
        guard_home=home_dir,
        payload=before_payload,
        reason="Requests a sensitive native tool action.",
        artifact=_cursor_shell_artifact(workspace_dir=workspace_dir, command=inner_command),
        artifact_hash="hash-cursor-generic-mcp-shell",
    )
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "generation_id": generation_id,
                "hook_event_name": "afterMCPExecution",
                "tool_name": "run_terminal_cmd",
                "tool_input": {"command": inner_command},
                "result_json": "{\"ok\": true}",
                "duration": 12,
            }
        ),
        harness="cursor",
        home_dir=home_dir,
        guard_home=home_dir,
        workspace=workspace_dir,
        hook_env=_trusted_cursor_after_observer_env(
            home_dir,
            conversation_id=conversation_id,
            command=inner_command,
            observer_event="afterMCPExecution",
            approval_binding=generation_id,
        ),
    )
    assert saved is True
    assert guard_commands_module._cursor_native_shell_is_approved(
        store,
        before_payload,
    )


def test_extract_sensitive_tool_action_request_accepts_generic_mcp_tool_command() -> None:
    from codex_plugin_scanner.guard.runtime.secret_file_requests import (
        extract_sensitive_tool_action_request,
    )

    match = extract_sensitive_tool_action_request(
        "custom_mcp_shell_gateway",
        {"command": "rm -rf ./hol-guard-cursor-native-mcp-marker"},
    )
    assert match is not None
    assert match.action_class == "destructive shell command"


def test_cursor_native_mcp_session_allow_after_trusted_after_mcp(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
    from codex_plugin_scanner.guard.cli import commands as guard_commands_module
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    conversation_id = "conv-cursor-native-mcp"
    inner_command = "rm -rf ./hol-guard-cursor-native-mcp-marker"
    generation_id = "gen-cursor-native-mcp"
    before_payload = prepare_cursor_hook_payload(
        {
            "conversation_id": conversation_id,
            "generation_id": generation_id,
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "ctx_shell",
            "tool_input": {"command": inner_command},
            "command": str(home_dir / ".local" / "bin" / "lean-ctx"),
        }
    )
    guard_commands_module._record_cursor_pending_shell_permission(
        store=store,
        guard_home=home_dir,
        payload=before_payload,
        reason="Requests a sensitive native tool action.",
        artifact=_cursor_shell_artifact(workspace_dir=workspace_dir, command=inner_command),
        artifact_hash="hash-cursor-mcp-shell",
    )
    saved = guard_commands_module._persist_cursor_native_permission_after_shell(
        store=store,
        payload=prepare_cursor_hook_payload(
            {
                "conversation_id": conversation_id,
                "generation_id": generation_id,
                "hook_event_name": "afterMCPExecution",
                "tool_name": "ctx_shell",
                "tool_input": {"command": inner_command},
                "result_json": "{\"ok\": true}",
                "duration": 12,
            }
        ),
        harness="cursor",
        home_dir=home_dir,
        guard_home=home_dir,
        workspace=workspace_dir,
        hook_env=_trusted_cursor_after_observer_env(
            home_dir,
            conversation_id=conversation_id,
            command=inner_command,
            observer_event="afterMCPExecution",
            approval_binding=generation_id,
        ),
    )
    assert saved is True
    assert guard_commands_module._cursor_native_shell_is_approved(
        store,
        before_payload,
    )


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
