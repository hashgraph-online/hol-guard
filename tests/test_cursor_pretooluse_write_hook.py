"""Cursor file writes reach Guard through a matched preToolUse hook."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hook_payload import cursor_hook_response_from_guard
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source, install_cursor_hooks

_WRITE_MATCHER = "^(Write|Edit|StrReplace|MultiEdit|Delete)$"


def _context(tmp_path: Path) -> HarnessContext:
    for name in ("home", "guard", "workspace"):
        (tmp_path / name).mkdir(exist_ok=True)
    (tmp_path / "guard" / "config.toml").write_text(
        'mode = "prompt"\nprotection_posture = "protected"\n', encoding="utf-8"
    )
    return HarnessContext(
        home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=tmp_path / "workspace"
    )


def test_matcher_selects_only_file_mutation_tools() -> None:
    pattern = re.compile(_WRITE_MATCHER)
    for tool in ("Write", "Edit", "StrReplace", "MultiEdit", "Delete"):
        assert pattern.search(tool)
    for tool in ("Shell", "Read", "Grep", "WriteNotes", "MCP:Write"):
        assert pattern.search(tool) is None


def test_reinstall_removes_retired_before_write_file_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hooks._resolve_guard_cli_command",
        lambda _context: ["hol-guard"],
    )
    script_path = tmp_path / "home" / ".cursor" / "hooks" / "hol-guard-cursor-hook.py"
    hooks_path = tmp_path / "home" / ".cursor" / "hooks.json"
    hooks_path.parent.mkdir(parents=True)
    other = {"command": "other-tool audit"}
    hooks_path.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {"beforeWriteFile": [other, {"command": str(script_path), "failClosed": True}]},
            }
        ),
        encoding="utf-8",
    )
    install_cursor_hooks(context)
    hooks = json.loads(hooks_path.read_text(encoding="utf-8"))["hooks"]
    assert hooks["beforeWriteFile"] == [other]
    [managed] = hooks["preToolUse"]
    assert managed["matcher"] == _WRITE_MATCHER
    assert managed["failClosed"] is True

    hooks_path.write_text(
        json.dumps({"version": 1, "hooks": {"beforeWriteFile": [{"command": str(script_path)}]}}),
        encoding="utf-8",
    )
    install_cursor_hooks(context)
    hooks = json.loads(hooks_path.read_text(encoding="utf-8"))["hooks"]
    assert "beforeWriteFile" not in hooks
    assert len(hooks["preToolUse"]) == 1


@pytest.mark.parametrize(("policy_action", "permission"), [("review", "deny"), ("block", "deny"), ("allow", "allow")])
def test_pretooluse_review_denies_because_cursor_ignores_ask(policy_action: str, permission: str) -> None:
    response = cursor_hook_response_from_guard(
        policy_action=policy_action, guard_payload={"reason": "protected path"}, hook_event_name="preToolUse"
    )
    assert response["permission"] == permission
    if permission == "deny":
        assert response["user_message"] and response["agent_message"]


def test_generated_script_denies_pretooluse_review_and_keeps_shell_ask(tmp_path: Path) -> None:
    source = cursor_hook_script_source(_context(tmp_path))
    script_globals: dict[str, object] = {"__name__": "cursor_hook"}
    exec(compile(source, "hol-guard-cursor-hook.py", "exec"), script_globals)
    emit = script_globals["_emit_cursor_response"]
    prepare = script_globals["_prepare_cursor_hook_payload"]
    assert callable(emit) and callable(prepare)
    response, exit_code = emit(hook_event_name="preToolUse", policy_action="review", guard_payload={})
    assert (response["permission"], exit_code) == ("deny", 2)
    response, exit_code = emit(hook_event_name="beforeShellExecution", policy_action="review", guard_payload={})
    assert (response["permission"], exit_code) == ("ask", 0)
    mapped = prepare(
        {"hook_event_name": "preToolUse", "tool_name": "Write", "tool_input": {"file_path": "a.txt", "content": "x"}}
    )
    assert isinstance(mapped, dict)
    assert (mapped["hook_event_name"], mapped["tool_name"]) == ("PreToolUse", "Write")
