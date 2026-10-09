"""Cursor file writes reach Guard through a matched preToolUse hook."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hook_config import _MANAGED_HOOK_EVENTS, _MANAGED_HOOK_TIMEOUT_SECONDS
from codex_plugin_scanner.guard.adapters.cursor_hook_payload import cursor_hook_response_from_guard
from codex_plugin_scanner.guard.adapters.cursor_hooks import (
    cursor_hook_script_source,
    cursor_native_hook_state,
    install_cursor_hooks,
)

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


def _stub_guard_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hooks._resolve_guard_cli_command",
        lambda _context: ["hol-guard"],
    )


def _write_hooks(tmp_path: Path, hooks: dict[str, object]) -> Path:
    hooks_path = tmp_path / "home" / ".cursor" / "hooks.json"
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    hooks_path.write_text(json.dumps({"version": 1, "hooks": hooks}), encoding="utf-8")
    return hooks_path


def _script_path(tmp_path: Path) -> Path:
    return tmp_path / "home" / ".cursor" / "hooks" / "hol-guard-cursor-hook.py"


def test_managed_hook_events_use_pretooluse_for_writes() -> None:
    assert "beforeWriteFile" not in _MANAGED_HOOK_EVENTS
    assert _MANAGED_HOOK_EVENTS == (
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
        "preToolUse",
        "afterShellExecution",
        "afterMCPExecution",
    )


def test_install_replaces_legacy_pretooluse_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    _stub_guard_cli(monkeypatch)
    other = {"command": "lean-ctx hook rewrite", "matcher": "Shell"}
    legacy = {"command": str(_script_path(tmp_path)), "failClosed": True, "matcher": "Shell|Read", "timeout": 35}
    hooks_path = _write_hooks(tmp_path, {"preToolUse": [other, legacy]})
    result = install_cursor_hooks(context)
    installed = json.loads(hooks_path.read_text(encoding="utf-8"))["hooks"]
    assert installed["preToolUse"][0] == other
    managed = [entry for entry in installed["preToolUse"] if "hol-guard-cursor-hook.py" in str(entry["command"])]
    assert len(managed) == 1
    assert managed[0]["matcher"] == _WRITE_MATCHER
    assert managed[0]["failClosed"] is True
    assert result["managed_hook_events"] == list(_MANAGED_HOOK_EVENTS)
    for event_name in _MANAGED_HOOK_EVENTS:
        assert installed[event_name][-1]["timeout"] == _MANAGED_HOOK_TIMEOUT_SECONDS


@pytest.mark.parametrize("event_name", ["beforeWriteFile", "beforeEditFile", "afterWriteFile"])
def test_reinstall_removes_guard_entries_under_unsupported_events(
    event_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(tmp_path)
    _stub_guard_cli(monkeypatch)
    hooks_path = _write_hooks(tmp_path, {event_name: [{"command": str(_script_path(tmp_path)), "failClosed": True}]})
    install_cursor_hooks(context)
    hooks = json.loads(hooks_path.read_text(encoding="utf-8"))["hooks"]
    assert event_name not in hooks
    [managed] = hooks["preToolUse"]
    assert managed["matcher"] == _WRITE_MATCHER
    assert managed["failClosed"] is True


def test_install_refuses_third_party_entry_under_unsupported_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(tmp_path)
    _stub_guard_cli(monkeypatch)
    other = {"command": "other-tool audit"}
    hooks_path = _write_hooks(
        tmp_path, {"beforeWriteFile": [other, {"command": str(_script_path(tmp_path)), "failClosed": True}]}
    )
    before = hooks_path.read_text(encoding="utf-8")
    with pytest.raises(RuntimeError, match="guard_cursor_hook_unsupported_events:beforeWriteFile"):
        install_cursor_hooks(context)
    assert hooks_path.read_text(encoding="utf-8") == before


def test_native_state_rejects_unsupported_event_after_install(tmp_path: Path) -> None:
    context = _context(tmp_path)
    install_cursor_hooks(context)
    assert cursor_native_hook_state(context)["protection_active"] is True
    hooks_path = tmp_path / "home" / ".cursor" / "hooks.json"
    payload = json.loads(hooks_path.read_text(encoding="utf-8"))
    payload["hooks"]["beforeWriteFile"] = [{"command": "other-tool audit"}]
    hooks_path.write_text(json.dumps(payload), encoding="utf-8")
    state = cursor_native_hook_state(context)
    assert (state["protection_active"], state["reason"]) == (False, "guard_cursor_hook_unsupported_event")


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
