"""Generated Cursor hook must allow when Guard is watch/observe-only."""

from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source


def _cursor_permission(tmp_path: Path, config_text: str) -> Callable[..., object]:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(config_text, encoding="utf-8")
    context = HarnessContext(
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace_dir=tmp_path,
    )
    source = cursor_hook_script_source(context)
    assert "load_guard_config" in source
    assert "workspace=workspace_path" in source
    assert "_LAST_HOOK_EVENT_NAME" in source
    script_globals: dict[str, object] = {"__name__": "cursor_hook"}
    exec(compile(source, "hol-guard-cursor-hook.py", "exec"), script_globals)
    permission = script_globals["_cursor_permission"]
    assert callable(permission)
    return permission


def test_generated_cursor_hook_allows_block_in_watch(tmp_path: Path) -> None:
    permission = _cursor_permission(
        tmp_path,
        'mode = "observe"\nprotection_posture = "watch"\n',
    )
    assert permission("block", {}) == "allow"
    assert permission("review", {}) == "allow"


def test_generated_cursor_hook_still_denies_block_when_protected(tmp_path: Path) -> None:
    permission = _cursor_permission(
        tmp_path,
        'mode = "prompt"\nprotection_posture = "protected"\n',
    )
    assert permission("block", {}) == "deny"
    assert permission("review", {}) == "ask"


def test_generated_cursor_hook_ignores_nested_observe_keys(tmp_path: Path) -> None:
    permission = _cursor_permission(
        tmp_path,
        'mode = "prompt"\nprotection_posture = "protected"\n\n[extensions]\n'
        'mode = "observe"\nprotection_posture = "watch"\n',
    )
    assert permission("block", {}) == "deny"


def test_generated_cursor_watch_after_shell_exception_prints_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'mode = "observe"\nprotection_posture = "watch"\n',
        encoding="utf-8",
    )
    context = HarnessContext(
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace_dir=tmp_path,
    )
    script_globals: dict[str, object] = {"__name__": "cursor_hook"}
    exec(compile(cursor_hook_script_source(context), "hol-guard-cursor-hook.py", "exec"), script_globals)

    def _raise_daemon_hook(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("daemon hook unavailable")

    script_globals["_daemon_hook_result"] = _raise_daemon_hook
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"hook_event_name": "afterShellExecution", "command": "true"})),
    )
    main = script_globals["main"]
    assert callable(main)
    assert main() == 0
    assert capsys.readouterr().out.strip() == "{}"


def test_empty_stdin_before_read_allows_when_event_is_baked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'mode = "prompt"\nprotection_posture = "protected"\n',
        encoding="utf-8",
    )
    context = HarnessContext(
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace_dir=tmp_path,
    )
    script_globals: dict[str, object] = {"__name__": "cursor_hook"}
    exec(compile(cursor_hook_script_source(context), "hol-guard-cursor-hook.py", "exec"), script_globals)
    monkeypatch.setattr(sys, "argv", ["hol-guard-cursor-hook.py", "--cursor-hook-event", "beforeReadFile"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    main = script_globals["main"]
    assert callable(main)
    assert main() == 0
    assert json.loads(capsys.readouterr().out) == {"permission": "allow"}


def test_empty_stdin_before_shell_pauses_when_event_is_baked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'mode = "prompt"\nprotection_posture = "protected"\n',
        encoding="utf-8",
    )
    context = HarnessContext(
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace_dir=tmp_path,
    )
    script_globals: dict[str, object] = {"__name__": "cursor_hook"}
    exec(compile(cursor_hook_script_source(context), "hol-guard-cursor-hook.py", "exec"), script_globals)
    monkeypatch.setattr(sys, "argv", ["hol-guard-cursor-hook.py", "--cursor-hook-event", "beforeShellExecution"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    main = script_globals["main"]
    assert callable(main)
    assert main() == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["permission"] == "deny"


def test_generated_cursor_hook_ignores_stale_allow_on_completed_block(tmp_path: Path) -> None:
    permission = _cursor_permission(
        tmp_path,
        'mode = "prompt"\nprotection_posture = "protected"\n',
    )
    assert (
        permission(
            "block",
            {
                "reason_code": "secret_pattern",
                "decision": "allow",
                "hookSpecificOutput": {"permissionDecision": "allow"},
            },
        )
        == "deny"
    )
    assert (
        permission(
            "block",
            {
                "reason_code": "native_hook_edge_invalid_response",
                "hookSpecificOutput": {"permissionDecision": "deny"},
            },
        )
        == "allow"
    )


def test_generated_cursor_hook_write_overrides_conflicting_tool_name(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'mode = "prompt"\nprotection_posture = "protected"\n',
        encoding="utf-8",
    )
    source = cursor_hook_script_source(
        HarnessContext(home_dir=tmp_path / "home", guard_home=guard_home, workspace_dir=tmp_path)
    )
    script_globals: dict[str, object] = {"__name__": "cursor_hook"}
    exec(compile(source, "hol-guard-cursor-hook.py", "exec"), script_globals)
    prepare = script_globals["_prepare_cursor_hook_payload"]
    assert callable(prepare)
    mapped = prepare(
        {"hook_event_name": "beforeWriteFile", "file_path": "src/app.ts", "tool_name": "Read"}
    )
    assert isinstance(mapped, dict)
    assert mapped["tool_name"] == "Write"
