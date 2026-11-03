"""Cursor file writes reach Guard through a matched preToolUse hook."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hook_config import _MANAGED_HOOK_EVENTS, _MANAGED_HOOK_TIMEOUT_SECONDS
from codex_plugin_scanner.guard.adapters.cursor_hooks import (
    cursor_native_hook_state,
    install_cursor_hooks,
)

_FILE_MATCHER = "^(Write|Edit|StrReplace|MultiEdit|Delete)$"
# Outside Windows Shell also reaches preToolUse, for the contained-route probe.
_WRITE_MATCHER = _FILE_MATCHER if sys.platform == "win32" else "^(Write|Edit|StrReplace|MultiEdit|Delete|Shell)$"


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
    pattern = re.compile(_FILE_MATCHER)
    for tool in ("Write", "Edit", "StrReplace", "MultiEdit", "Delete"):
        assert pattern.search(tool)
    for tool in ("Shell", "Read", "Grep", "WriteNotes", "MCP:Write"):
        assert pattern.search(tool) is None


def test_route_matcher_adds_only_shell() -> None:
    pattern = re.compile("^(Write|Edit|StrReplace|MultiEdit|Delete|Shell)$")
    for tool in ("Write", "Edit", "StrReplace", "MultiEdit", "Delete", "Shell"):
        assert pattern.search(tool)
    for tool in ("Read", "Grep", "WriteNotes", "MCP:Write", "ShellScript", "MCP:Shell"):
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


@pytest.mark.skipif(sys.platform == "win32", reason="Windows keeps the file-mutation matcher")
def test_install_from_the_file_only_matcher_adds_shell(tmp_path: Path) -> None:
    context = _context(tmp_path)
    install_cursor_hooks(context)
    hooks_path = tmp_path / "home" / ".cursor" / "hooks.json"
    payload = json.loads(hooks_path.read_text(encoding="utf-8"))
    [managed] = payload["hooks"]["preToolUse"]
    assert managed["matcher"] == _WRITE_MATCHER
    # An install from before the probe matched file mutations only.
    managed["matcher"] = _FILE_MATCHER
    hooks_path.write_text(json.dumps(payload), encoding="utf-8")
    assert cursor_native_hook_state(context)["protection_active"] is False
    install_cursor_hooks(context)
    [reinstalled] = json.loads(hooks_path.read_text(encoding="utf-8"))["hooks"]["preToolUse"]
    assert reinstalled["matcher"] == _WRITE_MATCHER
    assert cursor_native_hook_state(context)["protection_active"] is True
