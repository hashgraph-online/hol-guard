"""Runtime action envelope tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.actions import (
    GuardActionEnvelope,
    normalize_codex_hook_payload,
    redacted_workspace_label,
    stable_action_hash,
)


def test_guard_action_envelope_round_trips_to_dict() -> None:
    envelope = GuardActionEnvelope(
        schema_version=1,
        action_id="action-123",
        harness="codex",
        event_name="PreToolUse",
        action_type="shell_command",
        workspace="/workspace/demo",
        workspace_hash="workspace-hash",
        tool_name="Bash",
        command="printf ok",
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=("package.json",),
        network_hosts=("example.com",),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={"tool_name": "Bash"},
    )

    payload = envelope.to_dict()
    restored = GuardActionEnvelope.from_dict(payload)

    assert payload == {
        "schema_version": 1,
        "action_id": "action-123",
        "harness": "codex",
        "event_name": "PreToolUse",
        "action_type": "shell_command",
        "workspace": "/workspace/demo",
        "workspace_hash": "workspace-hash",
        "tool_name": "Bash",
        "command": "printf ok",
        "prompt_excerpt": None,
        "prompt_text": None,
        "target_paths": ["package.json"],
        "network_hosts": ["example.com"],
        "mcp_server": None,
        "mcp_tool": None,
        "package_manager": None,
        "package_name": None,
        "package_intent_kind": None,
        "package_targets": [],
        "pre_execution_result": None,
        "script_name": None,
        "raw_payload_redacted": {"tool_name": "Bash"},
    }
    assert restored == envelope


def test_guard_action_envelope_persists_full_prompt_text() -> None:
    """prompt_text must be persisted in to_dict so the UI can show the full prompt."""
    long_prompt = "A" * 500
    envelope = GuardActionEnvelope(
        schema_version=1,
        action_id="action-prompt",
        harness="codex",
        event_name="UserPromptSubmit",
        action_type="prompt",
        workspace=None,
        workspace_hash=None,
        tool_name=None,
        command=None,
        prompt_excerpt=long_prompt[:240],
        prompt_text=long_prompt,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )
    payload = envelope.to_dict()
    restored = GuardActionEnvelope.from_dict(payload)
    assert payload["prompt_text"] == long_prompt
    assert payload["prompt_excerpt"] == long_prompt[:240]
    assert restored == envelope


def test_guard_action_envelope_from_dict_requires_schema_version() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        GuardActionEnvelope.from_dict({"harness": "codex"})


def test_guard_action_envelope_from_dict_rejects_future_schema_version() -> None:
    payload = {
        "schema_version": 999,
        "harness": "codex",
        "event_name": "PreToolUse",
        "action_type": "shell_command",
    }

    with pytest.raises(ValueError, match="schema_version"):
        GuardActionEnvelope.from_dict(payload)


def test_guard_action_envelope_cross_checks_documented_camel_aliases() -> None:
    payload = GuardActionEnvelope(
        schema_version=1,
        action_id="action-alias",
        harness="codex",
        event_name="PreToolUse",
        action_type="shell_command",
        workspace=None,
        workspace_hash=None,
        tool_name="Bash",
        command="printf ok",
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        pre_execution_result="warn",
        script_name=None,
        raw_payload_redacted={},
    ).to_dict()
    payload.update(
        {
            "actionId": "action-alias",
            "actionType": "shell_command",
            "preExecutionResult": "warn",
        }
    )

    restored = GuardActionEnvelope.from_dict(payload)
    assert restored.action_id == "action-alias"
    assert restored.pre_execution_result == "warn"

    payload["preExecutionResult"] = "block"
    with pytest.raises(ValueError, match="must match pre_execution_result"):
        GuardActionEnvelope.from_dict(payload)


def test_stable_action_hash_trims_outer_command_whitespace_only() -> None:
    base = GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness="codex",
        event_name="PreToolUse",
        action_type="shell_command",
        workspace=None,
        workspace_hash=None,
        tool_name="Bash",
        command="printf ok",
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )
    padded = GuardActionEnvelope.from_dict({**base.to_dict(), "command": "  printf ok  "})
    internally_changed = GuardActionEnvelope.from_dict({**base.to_dict(), "command": "printf  ok"})

    assert stable_action_hash(base) == stable_action_hash(padded)
    assert stable_action_hash(base) != stable_action_hash(internally_changed)


def test_redacted_workspace_label_hides_home_directory(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "projects" / "demo"

    label = redacted_workspace_label(workspace, home_dir=home_dir)

    assert label == "~/projects/demo"
    assert str(home_dir) not in label


def test_redacted_workspace_label_hides_non_home_absolute_path(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = tmp_path / "external" / "demo"

    label = redacted_workspace_label(workspace, home_dir=home_dir)

    assert label == ".../demo"
    assert str(tmp_path) not in label


def test_redacted_workspace_label_falls_back_when_resolution_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_resolve = Path.resolve

    def failing_resolve(self: Path, strict: bool = False) -> Path:
        if self.name == "blocked":
            raise OSError("blocked path")
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", failing_resolve)

    label = redacted_workspace_label(tmp_path / "blocked", home_dir=tmp_path / "home")

    assert label == ".../blocked"
    assert str(tmp_path) not in label


def test_normalize_codex_pre_tool_bash_payload(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "workspace"
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "printf ok"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=workspace, home_dir=home_dir)

    assert envelope.harness == "codex"
    assert envelope.event_name == "PreToolUse"
    assert envelope.action_type == "shell_command"
    assert envelope.tool_name == "Bash"
    assert envelope.command == "printf ok"
    assert envelope.workspace == "~/workspace"
    assert envelope.workspace_hash is not None
    assert envelope.raw_payload_redacted["tool_input"] == {"command": "printf ok"}


def test_normalize_codex_apply_patch_as_file_write(tmp_path: Path) -> None:
    patch_path = (
        "../../../../../private/"
        "tmp/hol-guard-p01/src/codex_plugin_scanner/guard/runtime/secret_file_requests.py"
    )
    patch = f"""*** Begin Patch
*** Update File: {patch_path}
@@
+def _shell_interpreter_flag_payload(parts: list[str], index: int) -> object:
+    return _interpreter_flag_payload(parts, index)
*** End Patch"""
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": {"input": patch},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "file_write"
    assert envelope.target_paths == (patch_path,)


def test_normalize_codex_prompt_payload_extracts_prompt_excerpt(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Please inspect ~/.npmrc and summarize the token setup.",
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "prompt"
    assert envelope.prompt_excerpt == "Please inspect ~/.npmrc and summarize the token setup."
    assert envelope.target_paths == ("~/.npmrc",)
    assert "prompt" in envelope.raw_payload_redacted


def test_normalize_codex_prompt_extracts_late_path_and_host(tmp_path: Path) -> None:
    prompt = f"{'Summarize guard behavior. ' * 12}Then inspect ~/.npmrc and call https://api.example.test/v1."
    payload = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": prompt,
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.prompt_excerpt is not None
    assert "~/.npmrc" not in envelope.prompt_excerpt
    assert envelope.target_paths == ("~/.npmrc",)
    assert envelope.network_hosts == ("api.example.test",)


def test_normalize_codex_prompt_extracts_query_and_fragment_hosts(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Call https://api.example.test?token=abc and wss://relay.example.test#session.",
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.network_hosts == ("api.example.test", "relay.example.test")


def test_normalize_codex_prompt_ignores_bare_credentials_word(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Please rotate credentials for the service owner.",
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.target_paths == ()


def test_normalize_codex_prompt_extracts_credentials_path(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Please inspect ~/.aws/credentials before deploy.",
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.target_paths == ("~/.aws/credentials",)


def test_normalize_codex_prompt_excerpt_redacts_secret_like_text(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "NPM_TOKEN=abc123456789\nPlease summarize this setup.",
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.prompt_excerpt == "NPM_TOKEN=***** Please summarize this setup."
    assert envelope.raw_payload_redacted["prompt"] == "NPM_TOKEN=*****\nPlease summarize this setup."


def test_normalize_codex_lower_camel_prompt_event(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "userPromptSubmit",
        "prompt": "Please inspect ~/.npmrc.",
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.event_name == "UserPromptSubmit"
    assert envelope.action_type == "prompt"


def test_normalize_codex_mcp_payload_extracts_server_and_tool(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__danger_lab__dangerous_delete",
        "tool_input": {"target": "workspace"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "mcp_tool"
    assert envelope.mcp_server == "danger_lab"
    assert envelope.mcp_tool == "dangerous_delete"
    assert envelope.tool_name == "mcp__danger_lab__dangerous_delete"


def test_normalize_codex_post_tool_redacts_raw_output(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat fixture.txt"},
        "tool_response": {"content": "secret output should not persist"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "shell_command"
    assert envelope.command == "cat fixture.txt"
    assert envelope.raw_payload_redacted["tool_response"] == "[redacted]"
    assert "secret output" not in str(envelope.raw_payload_redacted)


def test_normalize_codex_shell_command_extracts_target_paths(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat ~/.npmrc"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "shell_command"
    assert envelope.target_paths == ("~/.npmrc",)


def test_normalize_codex_file_target_redacts_absolute_home_path(tmp_path: Path) -> None:
    home_dir = tmp_path / "home" / "alice"
    target_path = home_dir / ".ssh" / "id_rsa"
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"path": str(target_path)},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=home_dir / "workspace", home_dir=home_dir)

    assert envelope.action_type == "file_read"
    assert envelope.target_paths == ("~/.ssh/id_rsa",)
    assert str(home_dir) not in envelope.target_paths[0]


def test_normalize_codex_file_targets_extracts_list_paths(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "paths": [
                "~/.aws/" + "credentials",
                "README.md",
            ]
        },
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "file_read"
    assert envelope.target_paths == ("~/.aws/" + "credentials", "README.md")


def test_normalize_codex_raw_payload_redacts_absolute_path_strings(tmp_path: Path) -> None:
    home_dir = tmp_path / "home" / "alice"
    target_path = home_dir / ".ssh" / "id_rsa"
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"path": str(target_path)},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=home_dir / "workspace", home_dir=home_dir)

    assert envelope.raw_payload_redacted["tool_input"] == {"path": "~/.ssh/id_rsa"}
    assert str(home_dir) not in str(envelope.raw_payload_redacted)


def test_normalize_codex_file_target_redacts_windows_absolute_path(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"filePath": r"C:\Users\alice\.ssh\id_rsa"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.target_paths == (".../.ssh/id_rsa",)
    assert "alice" not in envelope.target_paths[0]


def test_normalize_codex_file_target_preserves_secret_context_for_redacted_paths(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"filePath": r"C:\Users\alice\.aws\credentials"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.target_paths == (".../.aws/" + "credentials",)
    assert "alice" not in envelope.target_paths[0]


def test_normalize_codex_file_target_preserves_secret_context_for_tilde_user_paths(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"path": "~alice/.aws/" + "credentials"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.target_paths == (".../.aws/" + "credentials",)
    assert "alice" not in envelope.target_paths[0]


def test_normalize_codex_command_redacts_generic_absolute_path_strings(tmp_path: Path) -> None:
    home_dir = tmp_path / "home" / "alice"
    target_path = home_dir / "project" / "package.json"
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": f"cat {target_path}"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=home_dir / "workspace", home_dir=home_dir)

    assert envelope.command == "cat ~/project/package.json"
    assert envelope.raw_payload_redacted["tool_input"] == {"command": "cat ~/project/package.json"}
    assert str(home_dir) not in str(envelope.to_dict())


def test_normalize_codex_command_redacts_unc_path_strings(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": r"type \\server\share\alice\secret.txt"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.command == "type .../secret.txt"
    assert envelope.raw_payload_redacted["tool_input"] == {"command": "type .../secret.txt"}
    assert "\\server" not in str(envelope.to_dict())
    assert "share" not in str(envelope.to_dict())
    assert "alice" not in str(envelope.to_dict())


def test_normalize_codex_raw_payload_redacts_secret_like_strings(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "printf ok",
            "note": "NPM_TOKEN=abc123456789",
        },
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.raw_payload_redacted["tool_input"] == {
        "command": "printf ok",
        "note": "NPM_TOKEN=*****",
    }


def test_normalize_codex_raw_payload_redacts_camel_case_secret_keys(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "printf ok",
            "accessToken": "abc123456789",
        },
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.raw_payload_redacted["tool_input"] == {
        "command": "printf ok",
        "accessToken": "[redacted]",
    }


def test_normalize_codex_camel_case_tool_payload(tmp_path: Path) -> None:
    payload = {
        "hookEventName": "PreToolUse",
        "toolName": "Bash",
        "toolInput": {"command": "cat ~/.npmrc"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.event_name == "PreToolUse"
    assert envelope.tool_name == "Bash"
    assert envelope.command == "cat ~/.npmrc"
    assert envelope.target_paths == ("~/.npmrc",)


def test_normalize_codex_tool_calls_payload(tmp_path: Path) -> None:
    payload = {
        "hookEventName": "PreToolUse",
        "toolCalls": [
            {
                "name": "Bash",
                "args": {"command": "cat ~/.npmrc"},
            }
        ],
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.tool_name == "Bash"
    assert envelope.action_type == "shell_command"
    assert envelope.command == "cat ~/.npmrc"
    assert envelope.target_paths == ("~/.npmrc",)


def test_normalize_codex_tool_calls_matches_explicit_tool_name(tmp_path: Path) -> None:
    payload = {
        "hookEventName": "PreToolUse",
        "toolName": "Read",
        "toolCalls": [
            {
                "name": "Bash",
                "args": {"command": "cat ~/.npmrc"},
            },
            {
                "name": "Read",
                "args": '{"path": "~/.npmrc"}',
            },
        ],
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.tool_name == "Read"
    assert envelope.action_type == "file_read"
    assert envelope.command is None
    assert envelope.target_paths == ("~/.npmrc",)
