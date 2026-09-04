"""Unit tests for stable Cursor hook Guard CLI resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.cursor_hook_guard_cli import (
    resolve_cursor_hook_guard_cli_argv0,
    resolve_frozen_cursor_hook_launcher,
    resolved_cursor_hook_guard_cli,
)


def test_resolve_cursor_hook_guard_cli_argv0_uses_existing_file(tmp_path: Path) -> None:
    executable = tmp_path / "hol-guard"
    executable.write_text("", encoding="utf-8")
    assert resolve_cursor_hook_guard_cli_argv0(str(executable)) == str(executable)


def test_resolve_cursor_hook_guard_cli_argv0_prefers_current_hol_guard_shim(tmp_path: Path) -> None:
    core_dir = tmp_path / "core"
    versioned = core_dir / "versions" / "3.0.55" / "hol-guard"
    versioned.parent.mkdir(parents=True)
    shim = core_dir / "current-hol-guard"
    shim.write_text("", encoding="utf-8")
    assert resolve_cursor_hook_guard_cli_argv0(str(versioned)) == str(shim)


def test_resolve_frozen_cli_recognizes_bundled_desktop_layout(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.stable_guard_cli import desktop_core_shim_for_executable

    core_dir = tmp_path / "core"
    bundled = core_dir / "bundled" / "3.0.63" / "lib" / "hol-guard-core" / "hol-guard"

    assert desktop_core_shim_for_executable(bundled) == core_dir / "current-hol-guard"


def test_resolve_frozen_cli_recognizes_bundled_desktop_wrapper(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.stable_guard_cli import desktop_core_shim_for_executable

    core_dir = tmp_path / "core"
    bundled = core_dir / "bundled" / "3.0.63" / "bin" / "hol-guard"

    assert desktop_core_shim_for_executable(bundled) == core_dir / "current-hol-guard"


def test_resolved_cursor_hook_guard_cli_rewrites_argv0_only(tmp_path: Path) -> None:
    core_dir = tmp_path / "core"
    versioned = core_dir / "versions" / "3.0.55" / "hol-guard"
    versioned.parent.mkdir(parents=True)
    shim = core_dir / "current-hol-guard"
    shim.write_text("", encoding="utf-8")
    assert resolved_cursor_hook_guard_cli([str(versioned), "hook", "--harness", "cursor"]) == [
        str(shim),
        "hook",
        "--harness",
        "cursor",
    ]


def test_resolve_frozen_cursor_hook_launcher_prefers_shim(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    core_dir = tmp_path / "core"
    versioned = core_dir / "versions" / "3.0.55" / "hol-guard"
    versioned.parent.mkdir(parents=True)
    versioned.write_text("", encoding="utf-8")
    shim = core_dir / "current-hol-guard"
    shim.write_text("", encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.stable_guard_cli.sys.executable",
        str(versioned),
    )
    assert resolve_frozen_cursor_hook_launcher() == str(shim)


def test_cursor_hook_script_template_includes_guard_cli_resolver() -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hook_guard_cli import HOOK_SCRIPT_TEMPLATE_RESOLVER
    from codex_plugin_scanner.guard.adapters.cursor_hooks import _HOOK_SCRIPT_TEMPLATE

    assert "_resolve_cursor_hook_guard_cli_argv0" in HOOK_SCRIPT_TEMPLATE_RESOLVER
    assert 'ancestor.name != "bundled"' in HOOK_SCRIPT_TEMPLATE_RESOLVER
    assert 'relative_parts[1] == "bin"' in HOOK_SCRIPT_TEMPLATE_RESOLVER
    assert "_resolved_guard_cli()" in HOOK_SCRIPT_TEMPLATE_RESOLVER
    assert "_resolve_cursor_hook_guard_cli_argv0" in _HOOK_SCRIPT_TEMPLATE
    assert "_resolved_guard_cli()" in _HOOK_SCRIPT_TEMPLATE
