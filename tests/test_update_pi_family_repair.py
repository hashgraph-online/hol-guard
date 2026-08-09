from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.pi import OmpHarnessAdapter, PiHarnessAdapter
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.adapters.pi_support import enable_managed_extension
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    home.mkdir()
    guard_home = home / ".hol-guard"
    guard_home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)


def _seed_current_pi_family(
    *,
    harness: str,
    context: HarnessContext,
    store: GuardStore,
    now: str,
) -> None:
    adapter = PiHarnessAdapter() if harness == "pi" else OmpHarnessAdapter()
    extension_path = adapter._managed_extension_path(context)
    settings_path = adapter._managed_settings_path(context)
    extension_path.parent.mkdir(parents=True, exist_ok=True)
    extension_path.write_text(
        managed_extension_source(
            guard_home=context.guard_home,
            home_dir=context.home_dir,
            settings_path=settings_path,
            harness=adapter.harness,
            display_name=adapter.display_name,
        ),
        encoding="utf-8",
    )
    enable_managed_extension(settings_path=settings_path, extension_path=extension_path)
    store.set_managed_install(
        harness,
        True,
        None,
        {
            "harness": harness,
            "active": True,
            "config_path": str(extension_path),
        },
        now,
    )


@pytest.mark.parametrize("harness,display_name", [("pi", "Pi"), ("omp", "Oh My Pi")])
def test_pi_family_repair_skips_when_extension_already_current(
    tmp_path: Path,
    harness: str,
    display_name: str,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-08T00:00:00+00:00"
    _seed_current_pi_family(harness=harness, context=context, store=store, now=now)

    repaired, warning = update_commands._repair_pi_family_install(
        harness=harness,
        display_name=display_name,
        context=context,
        store=store,
        workspace=None,
        now=now,
    )

    assert repaired is None
    assert warning is None


@pytest.mark.parametrize("harness,display_name", [("pi", "Pi"), ("omp", "Oh My Pi")])
def test_pi_family_repair_rewrites_stale_extension(
    tmp_path: Path,
    harness: str,
    display_name: str,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-08T00:00:00+00:00"
    _seed_current_pi_family(harness=harness, context=context, store=store, now=now)
    adapter = PiHarnessAdapter() if harness == "pi" else OmpHarnessAdapter()
    extension_path = adapter._managed_extension_path(context)
    extension_path.write_text("// stale extension\n", encoding="utf-8")

    repaired, warning = update_commands._repair_pi_family_install(
        harness=harness,
        display_name=display_name,
        context=context,
        store=store,
        workspace=None,
        now=now,
    )

    assert warning is None
    assert isinstance(repaired, dict)
    assert repaired.get("harness") == harness
    assert extension_path.read_text(encoding="utf-8") != "// stale extension\n"
