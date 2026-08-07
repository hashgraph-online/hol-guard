from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessAdapter, HarnessContext
from codex_plugin_scanner.guard.adapters.cline import ClineHarnessAdapter
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
from codex_plugin_scanner.guard.cli.install_commands import _apply_adapter_management


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = home / "workspace"
    guard_home = home / ".hol-guard"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


class _RecordingCline(ClineHarnessAdapter):
    seen: tuple[str, str] | None = None

    def install(self, context: HarnessContext, *, surface: str = "auto") -> dict[str, object]:
        del context
        self.seen = ("install", surface)
        return {"harness": "cline", "active": True, "surface": surface}

    def uninstall(self, context: HarnessContext, *, surface: str = "all") -> dict[str, object]:
        del context
        self.seen = ("uninstall", surface)
        return {"harness": "cline", "active": False, "surface": surface}


class _RecordingCursor(CursorHarnessAdapter):
    seen: tuple[str, str] | None = None

    def install(self, context: HarnessContext, *, surface: str = "all") -> dict[str, object]:
        del context
        self.seen = ("install", surface)
        return {"harness": "cursor", "active": True, "surface": surface}

    def uninstall(self, context: HarnessContext, *, surface: str = "all") -> dict[str, object]:
        del context
        self.seen = ("uninstall", surface)
        return {"harness": "cursor", "active": False, "surface": surface}


class _RecordingClaude(HarnessAdapter):
    harness = "claude-code"
    seen: str | None = None

    def detect(self, context: HarnessContext):
        raise AssertionError("detection is not part of surface dispatch")

    def install(self, context: HarnessContext) -> dict[str, object]:
        del context
        self.seen = "install"
        return {"harness": self.harness, "active": True}


def test_cline_explicit_plugin_surface_reaches_adapter(tmp_path: Path) -> None:
    adapter = _RecordingCline()
    result = _apply_adapter_management(adapter, _context(tmp_path), active=True, surface="plugin")
    assert adapter.seen == ("install", "plugin")
    assert result["surface"] == "plugin"


def test_cline_uninstall_surface_reaches_adapter(tmp_path: Path) -> None:
    adapter = _RecordingCline()
    result = _apply_adapter_management(adapter, _context(tmp_path), active=False, surface="hooks")
    assert adapter.seen == ("uninstall", "hooks")
    assert result["surface"] == "hooks"


def test_cursor_implicit_surface_keeps_existing_all_default(tmp_path: Path) -> None:
    adapter = _RecordingCursor()
    result = _apply_adapter_management(adapter, _context(tmp_path), active=True, surface=None)
    assert adapter.seen == ("install", "all")
    assert result["surface"] == "all"


def test_unsupported_surface_is_rejected_before_other_adapter_mutation(tmp_path: Path) -> None:
    adapter = _RecordingClaude()
    with pytest.raises(ValueError, match="Unsupported Claude Code surface: plugin"):
        _apply_adapter_management(adapter, _context(tmp_path), active=True, surface="plugin")
    assert adapter.seen is None
