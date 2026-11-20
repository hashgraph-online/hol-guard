from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.cli.update_bounded_hook_refresh import refresh_bounded_hook_clients
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.launcher import merge_guard_launcher_env
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_bounded_runtime import use_bounded_runtime

NOW = "2026-10-08T00:00:00+00:00"


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)


def _seed_client(context: HarnessContext, harness: str, body: str) -> Path:
    script_path = context.guard_home / "managed" / "bounded-hooks" / f"{harness}.py"
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(body, encoding="utf-8")
    return script_path


@pytest.fixture(autouse=True)
def runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "hol-guard-runtime"
    use_bounded_runtime(monkeypatch, path)
    return path


def _refresh(context: HarnessContext, store: GuardStore) -> tuple[list[dict[str, object]], list[str]]:
    return refresh_bounded_hook_clients(context=context, store=store, workspace=None, now=NOW)


def _zcode_hook_commands(context: HarnessContext) -> str:
    return (context.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8")


def test_refresh_moves_an_old_client_to_the_native_runtime(tmp_path: Path, runtime: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("zcode", True, None, {"harness": "zcode"}, NOW)
    script_path = _seed_client(context, "zcode", "TIMEOUT_SECONDS = 25\n# client from an older release\n")

    refreshed, warnings = _refresh(context, store)

    assert [item["harness"] for item in refreshed] == ["zcode"]
    assert warnings == []
    assert not script_path.exists()
    assert f"{runtime} bounded-hook-bridge" in _zcode_hook_commands(context)


def test_an_unavailable_resident_is_a_note_not_an_abort(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli import native_managed_update
    from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError

    def unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(native_managed_update, "ask_managed", unavailable)
    context = _context(tmp_path)

    refreshed, warnings = _refresh(context, GuardStore(context.guard_home))

    assert refreshed == []
    assert len(warnings) == 1
    assert "native_runner_authority_unavailable" in warnings[0]


def test_refresh_without_an_old_client_does_nothing(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("zcode", True, None, {"harness": "zcode"}, NOW)

    assert _refresh(context, store) == ([], [])


@pytest.mark.parametrize("active", [False, None])
def test_refresh_skips_inactive_or_missing_install(tmp_path: Path, active: bool | None) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    if active is not None:
        store.set_managed_install("zcode", active, None, {"harness": "zcode"}, NOW)
    script_path = _seed_client(context, "zcode", "stale\n")

    refreshed, _warnings = _refresh(context, store)

    assert refreshed == []
    assert script_path.read_text(encoding="utf-8") == "stale\n"


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
    assert not script_path.exists()


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
