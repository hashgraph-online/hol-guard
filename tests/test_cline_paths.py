from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_hooks import cline_hook_roots
from codex_plugin_scanner.guard.adapters.cline_mcp import cline_mcp_settings_candidates
from codex_plugin_scanner.guard.adapters.cline_paths import cline_data_dir
from codex_plugin_scanner.guard.adapters.cline_plugin import cline_plugin_root


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = home / "workspace"
    guard_home = home / ".hol-guard"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def test_default_cline_paths_cover_ui_and_cli_roots(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    monkeypatch.delenv("CLINE_DIR", raising=False)
    context = _context(tmp_path)

    assert cline_data_dir(context) == context.home_dir / ".cline"
    assert cline_hook_roots(context) == (
        context.home_dir / "Documents" / "Cline" / "Hooks",
        context.home_dir / ".cline" / "hooks",
    )
    assert cline_plugin_root(context) == context.home_dir / ".cline" / "plugins" / "hol-guard"


def test_current_cline_data_dir_override_takes_precedence(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    current = context.home_dir / "current-cline-data"
    legacy = context.home_dir / "legacy-cline-data"
    monkeypatch.setenv("CLINE_DATA_DIR", str(current))
    monkeypatch.setenv("CLINE_DIR", str(legacy))

    assert cline_data_dir(context) == current
    assert cline_hook_roots(context)[0] == current / "hooks"
    assert cline_plugin_root(context) == current / "plugins" / "hol-guard"
    candidates = cline_mcp_settings_candidates(context)
    assert current / "data" / "settings" / "cline_mcp_settings.json" in candidates
    assert current / "settings" / "cline_mcp_settings.json" in candidates
    assert all(not str(path).startswith(str(legacy)) for path in candidates)


def test_legacy_cline_dir_override_remains_compatible(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    legacy = context.home_dir / "legacy-cline-data"
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    monkeypatch.setenv("CLINE_DIR", str(legacy))

    assert cline_data_dir(context) == legacy
    assert cline_hook_roots(context)[0] == legacy / "hooks"
    assert cline_plugin_root(context) == legacy / "plugins" / "hol-guard"
