"""Generated Cursor hook must allow when Guard is watch/observe-only."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source
from codex_plugin_scanner.guard.protection_posture import recording_only_from_config_text


def test_recording_only_from_config_text_watch() -> None:
    assert (
        recording_only_from_config_text('mode = "observe"\nprotection_posture = "watch"\n')
        is True
    )
    assert recording_only_from_config_text('mode = "prompt"\nprotection_posture = "protected"\n') is False
    assert recording_only_from_config_text('mode = "observe"\n') is True


def test_generated_cursor_hook_allows_block_in_watch(tmp_path: Path) -> None:
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
    source = cursor_hook_script_source(context)
    assert "_recording_only_from_guard_home" in source
    script_globals: dict[str, object] = {"__name__": "cursor_hook"}
    exec(compile(source, "hol-guard-cursor-hook.py", "exec"), script_globals)
    permission = script_globals["_cursor_permission"]
    assert callable(permission)
    assert permission("block", {}) == "allow"
    assert permission("review", {}) == "allow"


def test_generated_cursor_hook_still_denies_block_when_protected(tmp_path: Path) -> None:
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
    source = cursor_hook_script_source(context)
    script_globals: dict[str, object] = {"__name__": "cursor_hook"}
    exec(compile(source, "hol-guard-cursor-hook.py", "exec"), script_globals)
    permission = script_globals["_cursor_permission"]
    assert callable(permission)
    assert permission("block", {}) == "deny"
    assert permission("review", {}) == "ask"
