from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.native_harness import ask

_SETTINGS = '{"mcpServers": {"local": {"command": "node", "args": []}}}'


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = home / "workspace"
    guard_home = home / ".hol-guard"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def _hook_root(context: HarnessContext, tmp_path: Path) -> Path:
    runtime = tmp_path / "native-runtime"
    runtime.write_bytes(b"")
    facts = {"python": True, "runtime": str(runtime), "hook_argv": ["guard", "hook"], "identity": None}
    answer = ask("install_transport", context, harness="cline", transport="hooks", frozen=False, facts=facts)
    return Path(answer["manifest"]["managed_hooks_root"])


def _plugin_root(context: HarnessContext) -> Path:
    facts = {"guard_cli": ["guard"], "hook_argv": None, "identity": None}
    answer = ask("install_transport", context, harness="cline", transport="plugin", frozen=False, facts=facts)
    return Path(answer["manifest"]["managed_plugin_path"]).parent


def _scanned(context: HarnessContext, *settings: Path) -> set[Path]:
    for path in settings:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_SETTINGS, encoding="utf-8")
    return {Path(found["path"]) for found in ask("mcp_scan", context, harness="cline")["candidates"]}


def test_default_cline_paths_cover_ui_and_cli_roots(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    monkeypatch.delenv("CLINE_DIR", raising=False)
    context = _context(tmp_path)

    assert _hook_root(context, tmp_path) == context.home_dir / "Documents" / "Cline" / "Hooks"
    assert _plugin_root(context) == context.home_dir / ".cline" / "plugins" / "hol-guard"
    settings = context.home_dir / ".cline" / "data" / "settings" / "cline_mcp_settings.json"
    assert _scanned(context, settings) == {settings}


def test_current_cline_data_dir_override_takes_precedence(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    current = context.home_dir / "current-cline-data"
    legacy = context.home_dir / "legacy-cline-data"
    monkeypatch.setenv("CLINE_DATA_DIR", str(current))
    monkeypatch.setenv("CLINE_DIR", str(legacy))

    assert _hook_root(context, tmp_path) == current / "hooks"
    assert _plugin_root(context) == current / "plugins" / "hol-guard"
    data = current / "data" / "settings" / "cline_mcp_settings.json"
    flat = current / "settings" / "cline_mcp_settings.json"
    ignored = legacy / "data" / "settings" / "cline_mcp_settings.json"
    assert _scanned(context, data, flat, ignored) == {data, flat}


def test_legacy_cline_dir_override_remains_compatible(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    legacy = context.home_dir / "legacy-cline-data"
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    monkeypatch.setenv("CLINE_DIR", str(legacy))

    assert _hook_root(context, tmp_path) == legacy / "hooks"
    assert _plugin_root(context) == legacy / "plugins" / "hol-guard"
