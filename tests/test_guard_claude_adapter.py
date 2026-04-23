"""Guard adapter tests for Claude Code surfaces."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters import claude_code as claude_code_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


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
    assert "hookEventName" in hook_command
    assert "SessionStart" in hook_command
    assert "HOL Guard protection is active for this workspace." in hook_command
    assert expected_source_root in hook_command
    assert "sync_claude_workspace_hook_urls" in hook_command
    assert '"guard", "hook"' not in hook_command


def test_claude_install_writes_session_start_and_http_hook_schema_and_is_idempotent(tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()

    adapter.install(context)
    adapter.install(context)

    settings_path = context.workspace_dir / ".claude" / "settings.local.json"
    payload = json.loads(settings_path.read_text(encoding="utf-8"))
    session_start = payload["hooks"]["SessionStart"]
    pre_tool_use = payload["hooks"]["PreToolUse"]
    post_tool_use = payload["hooks"]["PostToolUse"]
    prompt_submit = payload["hooks"]["UserPromptSubmit"]
    notification = payload["hooks"]["Notification"]

    assert len(session_start) == 4
    assert {entry["matcher"] for entry in session_start} == {"startup", "resume", "clear", "compact"}
    assert all(entry["hooks"][0]["type"] == "command" for entry in session_start)
    assert len(pre_tool_use) == 1
    assert pre_tool_use[0]["matcher"] == "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*"
    assert pre_tool_use[0]["hooks"][0]["type"] == "http"
    assert "/v1/hooks/claude-code?" in pre_tool_use[0]["hooks"][0]["url"]
    assert pre_tool_use[0]["hooks"][0]["timeout"] == 30
    assert len(post_tool_use) == 1
    assert len(prompt_submit) == 1
    assert "matcher" not in prompt_submit[0]
    assert len(notification) == 1
    assert notification[0]["matcher"] == "permission_prompt"
    assert notification[0]["hooks"][0]["type"] == "http"
    assert notification[0]["hooks"][0]["timeout"] == 10


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

    assert len(session_start) == 4
    assert all(len(entry["hooks"]) == 1 for entry in session_start)
    assert all(str(changed_context.guard_home) in command for command in hook_commands)
    assert all(str(initial_context.guard_home) not in command for command in hook_commands)


def test_claude_sync_workspace_hook_urls_uses_active_daemon_port(tmp_path, monkeypatch):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    adapter.install(context)
    settings_path = context.workspace_dir / ".claude" / "settings.local.json"
    initial_payload = json.loads(settings_path.read_text(encoding="utf-8"))
    initial_url = initial_payload["hooks"]["PreToolUse"][0]["hooks"][0]["url"]

    monkeypatch.setattr(
        claude_code_module,
        "load_guard_daemon_url",
        lambda _guard_home: "http://127.0.0.1:5999",
    )

    claude_code_module.sync_claude_workspace_hook_urls(
        context.guard_home,
        context.home_dir,
        context.workspace_dir,
    )

    updated_payload = json.loads(settings_path.read_text(encoding="utf-8"))
    updated_url = updated_payload["hooks"]["PreToolUse"][0]["hooks"][0]["url"]

    assert initial_url != updated_url
    assert updated_url.startswith("http://127.0.0.1:5999/")


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
    assert pre_tool_use[0]["hooks"][0]["type"] == "http"
    assert "/v1/hooks/claude-code?" in pre_tool_use[0]["hooks"][0]["url"]
    assert len(post_tool_use) == 1
    assert post_tool_use[0]["hooks"][0]["type"] == "http"


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
