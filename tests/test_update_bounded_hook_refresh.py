from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import (
    _render_bounded_hook_script,
    bounded_hook_script_path,
)
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.cli.update_bounded_hook_refresh import refresh_bounded_hook_clients
from codex_plugin_scanner.guard.launcher import merge_guard_launcher_env
from codex_plugin_scanner.guard.store import GuardStore

NOW = "2026-10-08T00:00:00+00:00"


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)


def _seed_client(context: HarnessContext, harness: str, body: str) -> Path:
    script_path = bounded_hook_script_path(context.guard_home, harness)
    assert script_path is not None
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(body, encoding="utf-8")
    return script_path


def _current_zcode_client(context: HarnessContext) -> str:
    return _render_bounded_hook_script(guard_home=context.guard_home, harness="zcode", timeout_seconds=25)


def test_refresh_rewrites_stale_client_for_active_install(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("zcode", True, None, {"harness": "zcode"}, NOW)
    script_path = _seed_client(context, "zcode", "TIMEOUT_SECONDS = 25\n# client from an older release\n")

    refreshed, warnings = refresh_bounded_hook_clients(context=context, store=store)

    assert [item["harness"] for item in refreshed] == ["zcode"]
    assert warnings == []
    assert script_path.read_text(encoding="utf-8") == _current_zcode_client(context)


def test_refresh_leaves_current_client_untouched(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("zcode", True, None, {"harness": "zcode"}, NOW)
    script_path = _seed_client(context, "zcode", _current_zcode_client(context))
    before = script_path.stat().st_mtime_ns

    refreshed, warnings = refresh_bounded_hook_clients(context=context, store=store)

    assert refreshed == []
    assert warnings == []
    assert script_path.stat().st_mtime_ns == before


@pytest.mark.parametrize("active", [False, None])
def test_refresh_skips_inactive_or_missing_install(tmp_path: Path, active: bool | None) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    if active is not None:
        store.set_managed_install("zcode", active, None, {"harness": "zcode"}, NOW)
    script_path = _seed_client(context, "zcode", "stale\n")

    refreshed, _warnings = refresh_bounded_hook_clients(context=context, store=store)

    assert refreshed == []
    assert script_path.read_text(encoding="utf-8") == "stale\n"


def test_refresh_does_not_create_or_follow_client_paths(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("zcode", True, None, {"harness": "zcode"}, NOW)
    store.set_managed_install("kimi", True, None, {"harness": "kimi"}, NOW)
    outside = tmp_path / "outside.py"
    outside.write_text("outside\n", encoding="utf-8")
    zcode_path = bounded_hook_script_path(context.guard_home, "zcode")
    assert zcode_path is not None
    zcode_path.parent.mkdir(parents=True)
    zcode_path.symlink_to(outside)

    refreshed, warnings = refresh_bounded_hook_clients(context=context, store=store)

    assert refreshed == []
    assert warnings == []
    assert outside.read_text(encoding="utf-8") == "outside\n"
    kimi_path = bounded_hook_script_path(context.guard_home, "kimi")
    assert kimi_path is not None
    assert not kimi_path.exists()


def test_refresh_does_not_write_through_symlinked_client_directory(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("zcode", True, None, {"harness": "zcode"}, NOW)
    zcode_path = bounded_hook_script_path(context.guard_home, "zcode")
    assert zcode_path is not None
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_client = outside_dir / zcode_path.name
    outside_client.write_text("outside\n", encoding="utf-8")
    zcode_path.parent.parent.mkdir(parents=True, exist_ok=True)
    zcode_path.parent.symlink_to(outside_dir, target_is_directory=True)

    refreshed, warnings = refresh_bounded_hook_clients(context=context, store=store)

    assert refreshed == []
    assert warnings == []
    assert outside_client.read_text(encoding="utf-8") == "outside\n"


def test_update_repair_refreshes_stale_bounded_client(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("zcode", True, None, {"harness": "zcode"}, NOW)
    script_path = _seed_client(context, "zcode", "stale\n")

    repaired, _notes = update_commands._repair_supported_harnesses_in_process(
        context=context,
        store=store,
        workspace=None,
        now=NOW,
        dry_run=False,
    )

    assert any(item.get("harness") == "zcode" for item in repaired)
    assert script_path.read_text(encoding="utf-8") == _current_zcode_client(context)


def test_frozen_launcher_env_does_not_pin_extraction_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    assert "PYTHONPATH" not in merge_guard_launcher_env(pin_package=True)


def test_source_launcher_env_still_pins_package_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)

    pinned = merge_guard_launcher_env(pin_package=True)["PYTHONPATH"]

    assert (Path(pinned) / "codex_plugin_scanner" / "guard" / "launcher.py").is_file()


@pytest.mark.parametrize(
    "argv",
    [
        ["settings", "--guard-home", "/iso/guard", "--home", "/iso", "set", "protection", "protected"],
        ["settings", "set", "--guard-home", "/iso/guard", "--home", "/iso", "protection", "protected"],
        ["settings", "set", "protection", "protected", "--guard-home", "/iso/guard", "--home", "/iso"],
        ["settings", "--guard-home", "/iso/guard", "--home", "/iso", "approval-password", "status"],
    ],
)
def test_settings_home_overrides_survive_nested_subcommands(argv: list[str]) -> None:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)

    args = parser.parse_args(argv)

    assert args.guard_home == "/iso/guard"
    assert args.home == "/iso"
