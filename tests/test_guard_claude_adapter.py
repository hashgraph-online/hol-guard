"""Guard adapter tests for Claude Code surfaces."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import claude_code, get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import (
    CLAUDE_GUARD_DAEMON_HOOK_MARKER,
    CLAUDE_GUARD_TOOL_MATCHER,
    ClaudeCodeHarnessAdapter,
    _shell_command,
)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _symlink_or_skip(link_path: Path, target: Path) -> None:
    try:
        link_path.parent.mkdir(parents=True, exist_ok=True)
        link_path.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are not supported in this environment")


def _build_context(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=guard_home,
    )


def _runtime_hook_handlers(payload: dict[str, object]) -> list[dict[str, object]]:
    hooks = payload["hooks"]
    assert isinstance(hooks, dict)
    handlers: list[dict[str, object]] = []
    for key in ("PreToolUse", "PermissionRequest", "PostToolUse", "Notification", "Stop"):
        entries = hooks.get(key, [])
        assert isinstance(entries, list)
        for entry in entries:
            assert isinstance(entry, dict)
            entry_hooks = entry["hooks"]
            assert isinstance(entry_hooks, list)
            for hook in entry_hooks:
                assert isinstance(hook, dict)
                handlers.append(hook)
    return handlers


def test_claude_detect_marks_local_cli_install_as_available_when_not_on_path(monkeypatch, tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    actual_home = tmp_path / "actual-home"
    local_claude = actual_home / ".claude" / "local" / "claude"
    local_claude.parent.mkdir(parents=True, exist_ok=True)
    local_claude.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    local_claude.chmod(0o755)
    monkeypatch.setattr("shutil.which", lambda command: None)
    monkeypatch.setattr(Path, "home", lambda: actual_home)

    detection = adapter.detect(context)

    assert detection.installed is True
    assert detection.command_available is True


def test_claude_launch_command_uses_local_cli_install_when_not_on_path(monkeypatch, tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    actual_home = tmp_path / "actual-home"
    local_claude = actual_home / ".claude" / "local" / "claude"
    local_claude.parent.mkdir(parents=True, exist_ok=True)
    local_claude.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    local_claude.chmod(0o755)
    monkeypatch.setattr("shutil.which", lambda command: None)
    monkeypatch.setattr(Path, "home", lambda: actual_home)

    launch_command = adapter.launch_command(context, ["--print", "hello"])

    assert launch_command[0] == str(local_claude)
    assert launch_command[1] == str(context.workspace_dir)
    assert launch_command[2:] == ["--print", "hello"]


def test_claude_detect_ignores_non_executable_local_cli_candidate_when_not_on_path(monkeypatch, tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    local_binary = tmp_path / "actual-home" / ".claude" / "local" / "claude"
    local_binary.parent.mkdir(parents=True, exist_ok=True)
    local_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    local_binary.chmod(0o644)

    monkeypatch.setattr("shutil.which", lambda command: None)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "actual-home")

    detection = adapter.detect(context)

    assert detection.installed is False
    assert detection.command_available is False


def test_claude_install_bakes_current_source_root_into_session_start_command(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()

    install_output = adapter.install(context)

    settings_path = context.workspace_dir / ".claude" / "settings.local.json"
    payload = json.loads(settings_path.read_text(encoding="utf-8"))
    hook_command = str(payload["hooks"]["SessionStart"][0]["hooks"][0]["command"])
    expected_source_root = str(Path(__file__).resolve().parents[1] / "src")

    assert install_output["active"] is True
    assert "ensure_guard_daemon" in hook_command
    assert "refresh_installed_hook_urls" in hook_command
    assert "hookEventName" in hook_command
    assert "SessionStart" in hook_command
    assert "HOL Guard protection is active for this workspace." in hook_command
    assert expected_source_root in hook_command
    assert '"guard", "hook"' not in hook_command


def test_claude_install_writes_session_start_and_command_hook_schema_and_is_idempotent(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()

    adapter.install(context)
    adapter.install(context)

    settings_path = context.workspace_dir / ".claude" / "settings.local.json"
    payload = json.loads(settings_path.read_text(encoding="utf-8"))
    session_start = payload["hooks"]["SessionStart"]
    pre_tool_use = payload["hooks"]["PreToolUse"]
    permission_request = payload["hooks"]["PermissionRequest"]
    post_tool_use = payload["hooks"]["PostToolUse"]
    notification = payload["hooks"]["Notification"]
    stop = payload["hooks"]["Stop"]
    assert len(session_start) == 4
    assert {entry["matcher"] for entry in session_start} == {"startup", "resume", "clear", "compact"}
    assert all(entry["hooks"][0]["type"] == "command" for entry in session_start)
    assert len(pre_tool_use) == 1
    assert pre_tool_use[0]["matcher"] == "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*"
    assert pre_tool_use[0]["hooks"][0]["type"] == "command"
    assert CLAUDE_GUARD_DAEMON_HOOK_MARKER in pre_tool_use[0]["hooks"][0]["command"]
    assert "url" not in pre_tool_use[0]["hooks"][0]
    assert pre_tool_use[0]["hooks"][0]["timeout"] == 30
    assert len(permission_request) == 1
    assert permission_request[0]["matcher"] == "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*"
    assert permission_request[0]["hooks"][0]["type"] == "command"
    assert permission_request[0]["hooks"][0]["timeout"] == 10
    assert len(post_tool_use) == 1
    assert post_tool_use[0]["matcher"] == "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*|AskUserQuestion"
    assert post_tool_use[0]["hooks"][0]["type"] == "command"
    assert payload["hooks"].get("UserPromptSubmit", []) == []
    assert len(notification) == 1
    assert notification[0]["matcher"] == "permission_prompt"
    assert notification[0]["hooks"][0]["type"] == "command"
    assert notification[0]["hooks"][0]["timeout"] == 10
    assert len(stop) == 1
    assert "matcher" not in stop[0]
    assert stop[0]["hooks"][0]["type"] == "command"
    assert stop[0]["hooks"][0]["timeout"] == 10
    assert all("url" not in handler for handler in _runtime_hook_handlers(payload))


def test_get_adapter_accepts_claude_alias():
    adapter = get_adapter("claude")

    assert isinstance(adapter, ClaudeCodeHarnessAdapter)


def test_claude_install_replaces_legacy_http_guard_hooks(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    settings_path = context.workspace_dir / ".claude" / "settings.local.json"
    _write_json(
        settings_path,
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*",
                        "hooks": [
                            {
                                "type": "http",
                                "url": "http://127.0.0.1:5371/v1/hooks/claude-code?guard-home=%2Fold",
                                "timeout": 30,
                            }
                        ],
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*",
                        "hooks": [
                            {
                                "type": "http",
                                "url": "http://127.0.0.1:5371/v1/hooks/claude-code?guard-home=%2Fold",
                                "timeout": 30,
                            }
                        ],
                    }
                ],
                "UserPromptSubmit": [
                    {
                        "hooks": [
                            {
                                "type": "http",
                                "url": "http://127.0.0.1:5371/v1/hooks/claude-code?guard-home=%2Fold",
                                "timeout": 20,
                            }
                        ],
                    }
                ],
                "Notification": [
                    {
                        "matcher": "permission_prompt",
                        "hooks": [
                            {
                                "type": "http",
                                "url": "http://127.0.0.1:5371/v1/hooks/claude-code?guard-home=%2Fold",
                                "timeout": 10,
                            }
                        ],
                    }
                ],
            }
        },
    )

    adapter.install(context)

    payload = json.loads(settings_path.read_text(encoding="utf-8"))
    installed_handlers = _runtime_hook_handlers(payload)

    assert [handler["type"] for handler in installed_handlers] == [
        "command",
        "command",
        "command",
        "command",
        "command",
    ]
    assert payload["hooks"].get("UserPromptSubmit", []) == []
    assert all(CLAUDE_GUARD_DAEMON_HOOK_MARKER in str(handler.get("command", "")) for handler in installed_handlers)
    assert all("url" not in handler for handler in installed_handlers)


def test_claude_refresh_runtime_hook_urls_rewrites_stale_daemon_port(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    settings_path = context.workspace_dir / ".claude" / "settings.local.json"
    _write_json(
        settings_path,
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": CLAUDE_GUARD_TOOL_MATCHER,
                        "hooks": [
                            {
                                "type": "http",
                                "url": "http://127.0.0.1:5371/v1/hooks/claude-code?guard-home=%2Fold",
                                "timeout": 30,
                            }
                        ],
                    }
                ],
                "PostToolUse": [],
                "UserPromptSubmit": [],
                "Notification": [],
            }
        },
    )

    original_guard_daemon_url_for_home = claude_code.guard_daemon_url_for_home
    original_load_guard_daemon_url = claude_code.load_guard_daemon_url
    claude_code.guard_daemon_url_for_home = lambda _guard_home: "http://127.0.0.1:5888"
    claude_code.load_guard_daemon_url = lambda _guard_home: "http://127.0.0.1:5999"
    try:
        adapter.refresh_runtime_hook_urls(context)
    finally:
        claude_code.guard_daemon_url_for_home = original_guard_daemon_url_for_home
        claude_code.load_guard_daemon_url = original_load_guard_daemon_url

    payload = json.loads(settings_path.read_text(encoding="utf-8"))
    installed_handlers = _runtime_hook_handlers(payload)

    assert all(handler["type"] == "command" for handler in installed_handlers)
    assert all("url" not in handler for handler in installed_handlers)
    assert all("http://127.0.0.1:5999" in str(handler["command"]) for handler in installed_handlers)
    assert all(CLAUDE_GUARD_DAEMON_HOOK_MARKER in str(handler["command"]) for handler in installed_handlers)


def test_claude_install_rejects_symlinked_settings_file(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    outside_settings = tmp_path / "outside-settings.json"
    outside_settings.write_text("{}", encoding="utf-8")
    settings_path = context.workspace_dir / ".claude" / "settings.local.json"
    _symlink_or_skip(settings_path, outside_settings)

    with pytest.raises(ValueError, match="settings path"):
        adapter.install(context)

    assert outside_settings.read_text(encoding="utf-8") == "{}"


def test_claude_legacy_guard_url_detection_only_matches_local_guard_urls():
    assert (
        claude_code._is_guard_hook_url(
            "http://127.0.0.1:5371/v1/hooks/claude-code?guard-home=%2Fold&workspace=%2Fworkspace"
        )
        is True
    )
    assert claude_code._is_guard_hook_url("https://hol.org/v1/hooks/claude-code") is False
    assert claude_code._is_guard_hook_url("http://localhost:5371/v1/hooks/claude-code") is False


def test_claude_handler_identity_uses_http_url_for_http_hooks():
    assert claude_code._handler_identity({"type": "http", "url": "http://127.0.0.1:5371/one"}) == (
        "http",
        "http://127.0.0.1:5371/one",
    )
    assert claude_code._handler_identity({"type": "http", "url": "http://127.0.0.1:5371/two"}) == (
        "http",
        "http://127.0.0.1:5371/two",
    )


def test_claude_daemon_hook_command_is_identified_as_guard_hook(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    command = adapter._daemon_hook_command(context)

    assert CLAUDE_GUARD_DAEMON_HOOK_MARKER in command
    assert claude_code._is_guard_hook_command(command) is True


def test_claude_shell_command_uses_list2cmdline_on_windows():
    command = ("node", "-e", "console.log('hello')")

    assert _shell_command(command, windows=True) == subprocess.list2cmdline(list(command))


def test_claude_daemon_hook_command_survives_shell_execution(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    command = adapter._daemon_hook_command(context)

    result = subprocess.run(
        ["/bin/sh", "-c", command],
        input=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hello"}),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == ""


def test_claude_daemon_hook_command_falls_back_without_blocking_prompt_on_daemon_miss(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    command = adapter._daemon_hook_command(context)

    result = subprocess.run(
        ["/bin/sh", "-c", command],
        input=json.dumps(
            {
                "hook_event_name": "UserPromptSubmit",
                "prompt": "Use the Read tool to open ./.env and print the full file contents exactly.",
            }
        ),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == ""


def test_claude_daemon_hook_command_falls_back_to_native_ask_on_daemon_miss(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    command = adapter._daemon_hook_command(context)

    result = subprocess.run(
        ["/bin/sh", "-c", command],
        input=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": str(context.workspace_dir / ".env")},
            }
        ),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert result.stderr == ""
    assert payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    reason = payload["hookSpecificOutput"]["permissionDecisionReason"]
    assert "HOL Guard" in reason
    assert "approval flow came from HOL Guard" in reason
    assert "Allow once" in reason
    assert "Keep blocked" in reason


def test_claude_install_replaces_prior_session_start_guard_handlers_when_context_changes(tmp_path):
    initial_context = _build_context(tmp_path)
    changed_context = HarnessContext(
        home_dir=tmp_path / "different-home",
        workspace_dir=initial_context.workspace_dir,
        guard_home=tmp_path / "different-guard-home",
    )
    adapter = ClaudeCodeHarnessAdapter()

    adapter.install(initial_context)
    adapter.install(changed_context)

    settings_path = initial_context.workspace_dir / ".claude" / "settings.local.json"
    payload = json.loads(settings_path.read_text(encoding="utf-8"))
    session_start = payload["hooks"]["SessionStart"]
    hook_commands = [entry["hooks"][0]["command"] for entry in session_start]
    operational_handlers = _runtime_hook_handlers(payload)
    operational_commands = [str(handler["command"]) for handler in operational_handlers]

    assert len(session_start) == 4
    assert all(len(entry["hooks"]) == 1 for entry in session_start)
    assert all(str(changed_context.guard_home) in command for command in hook_commands)
    assert all(str(initial_context.guard_home) not in command for command in hook_commands)
    assert all(handler["type"] == "command" for handler in operational_handlers)
    assert all(CLAUDE_GUARD_DAEMON_HOOK_MARKER in command for command in operational_commands)
    assert all(str(changed_context.guard_home) in command for command in operational_commands)
    assert all(str(initial_context.guard_home) not in command for command in operational_commands)


def test_claude_install_and_uninstall_preserve_unrelated_nested_hooks(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    settings_path = context.workspace_dir / ".claude" / "settings.local.json"
    _write_json(
        settings_path,
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python3 custom-pre.py", "timeout": 5}],
                    }
                ]
            },
            "permissions": {
                "ask": ["Read(./notes.txt)"],
            },
            "theme": "dark",
        },
    )

    adapter.install(context)
    adapter.uninstall(context)

    payload = json.loads(settings_path.read_text(encoding="utf-8"))

    assert payload["theme"] == "dark"
    assert payload["hooks"]["PreToolUse"] == [
        {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "python3 custom-pre.py", "timeout": 5}],
        }
    ]
    assert payload["permissions"]["ask"] == ["Read(./notes.txt)"]


def test_claude_install_migrates_legacy_flat_guard_hook_entries(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    settings_path = context.workspace_dir / ".claude" / "settings.local.json"
    legacy_command = adapter._hook_command(context)
    _write_json(
        settings_path,
        {
            "hooks": {
                "PreToolUse": [{"command": legacy_command}],
                "PostToolUse": [{"command": legacy_command}],
            }
        },
    )

    adapter.install(context)

    payload = json.loads(settings_path.read_text(encoding="utf-8"))
    pre_tool_use = payload["hooks"]["PreToolUse"]
    post_tool_use = payload["hooks"]["PostToolUse"]

    assert len(pre_tool_use) == 1
    assert pre_tool_use[0]["hooks"][0]["type"] == "command"
    assert CLAUDE_GUARD_DAEMON_HOOK_MARKER in pre_tool_use[0]["hooks"][0]["command"]
    assert len(post_tool_use) == 1
    assert post_tool_use[0]["hooks"][0]["type"] == "command"
    assert CLAUDE_GUARD_DAEMON_HOOK_MARKER in post_tool_use[0]["hooks"][0]["command"]


def test_claude_detect_discovers_nested_hooks_skills_commands_and_rules(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    _write_json(
        context.home_dir / ".claude" / "settings.json",
        {
            "mcpServers": {
                "global-tools": {
                    "command": "python",
                    "args": ["-m", "http.server", "9000"],
                    "env": {"OPENROUTER_API_KEY": "secret", "MODE": "prod"},
                }
            }
        },
    )
    _write_json(
        context.workspace_dir / ".claude" / "settings.local.json",
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash|Read",
                        "hooks": [{"type": "command", "command": "python3 guard-pre.py", "timeout": 30}],
                    }
                ],
                "UserPromptSubmit": [
                    {"hooks": [{"type": "command", "command": "python3 guard-prompt.py", "timeout": 20}]}
                ],
            }
        },
    )
    _write_json(
        context.workspace_dir / ".mcp.json",
        {
            "mcpServers": {
                "workspace-tools": {
                    "url": "http://example.invalid/mcp",
                    "headers": {"Authorization": "Bearer secret"},
                    "env": {"TOKEN": "secret", "MODE": "workspace"},
                }
            }
        },
    )
    skill_path = context.workspace_dir / ".claude" / "skills" / "review" / "SKILL.md"
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    skill_path.write_text("---\nname: review\ndescription: Review skill\n---\n", encoding="utf-8")
    command_path = context.workspace_dir / ".claude" / "commands" / "deploy.md"
    command_path.parent.mkdir(parents=True, exist_ok=True)
    command_path.write_text("# deploy\n", encoding="utf-8")
    rule_path = context.workspace_dir / ".claude" / "rules" / "secrets.md"
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    rule_path.write_text("# secrets\n", encoding="utf-8")
    claude_md = context.workspace_dir / "CLAUDE.md"
    claude_md.write_text("# workspace instructions\n", encoding="utf-8")

    detection = adapter.detect(context)
    artifacts = {artifact.artifact_id: artifact for artifact in detection.artifacts}

    assert "claude-code:global:global-tools" in artifacts
    assert artifacts["claude-code:global:global-tools"].metadata["env_keys"] == ["MODE", "OPENROUTER_API_KEY"]
    assert "claude-code:project:workspace-tools" in artifacts
    assert artifacts["claude-code:project:workspace-tools"].metadata["headers_keys"] == ["Authorization"]
    assert "claude-code:project:pretooluse:0:0" in artifacts
    assert "claude-code:project:userpromptsubmit:0:0" in artifacts
    assert "claude-code:project:skill:review" in artifacts
    assert "claude-code:project:command:deploy" in artifacts
    assert "claude-code:project:instruction:secrets" in artifacts
    assert "claude-code:project:instruction:claude-md" in artifacts


def test_claude_detect_tolerates_unreadable_markdown_artifacts(monkeypatch, tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    skill_path = context.workspace_dir / ".claude" / "skills" / "review" / "SKILL.md"
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    skill_path.write_text("---\nname: review\ndescription: Review skill\n---\n", encoding="utf-8")
    original_read_bytes = Path.read_bytes

    def _guarded_read_bytes(path: Path) -> bytes:
        if path == skill_path:
            raise OSError("permission denied")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", _guarded_read_bytes)

    detection = adapter.detect(context)
    artifacts = {artifact.artifact_id: artifact for artifact in detection.artifacts}

    assert "claude-code:project:skill:review" in artifacts
    assert artifacts["claude-code:project:skill:review"].metadata == {}
