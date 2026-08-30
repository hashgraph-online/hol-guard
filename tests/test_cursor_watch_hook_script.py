"""Generated Cursor hook must allow when Guard is watch/observe-only."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source


def _cursor_permission(tmp_path: Path, config_text: str) -> Callable[..., Any]:
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
