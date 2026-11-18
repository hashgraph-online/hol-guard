from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.install_commands import _selected_surface
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.native_harness_client import ask


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = home / "workspace"
    guard_home = home / ".hol-guard"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def test_cline_explicit_plugin_surface_reaches_adapter(tmp_path: Path) -> None:
    assert _selected_surface("cline", _context(tmp_path), "plugin") == "plugin"


def test_frozen_cline_auto_transport_uses_durable_plugin(tmp_path: Path) -> None:
    plan = ask(
        "install_plan",
        _context(tmp_path),
        harness="cline",
        surface="auto",
        frozen=True,
        cli={"path": None, "output": ""},
    )

    assert (plan["transport"], plan["fallback"]) == ("plugin", True)


def test_cline_uninstall_surface_reaches_adapter(tmp_path: Path) -> None:
    assert _selected_surface("cline", _context(tmp_path), "hooks") == "hooks"


def test_cline_without_a_surface_leaves_the_default_to_the_runtime(tmp_path: Path) -> None:
    assert _selected_surface("cline", _context(tmp_path), None) is None


def test_cursor_implicit_surface_keeps_existing_all_default(tmp_path: Path) -> None:
    assert _selected_surface("cursor", _context(tmp_path), None) == "all"


def test_unsupported_surface_is_rejected_before_other_adapter_mutation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unsupported Claude Code surface: plugin"):
        _selected_surface("claude-code", _context(tmp_path), "plugin")
