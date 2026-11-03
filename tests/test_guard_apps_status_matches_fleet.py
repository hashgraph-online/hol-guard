"""`hol-guard apps` agrees with the per-app setup check that fleet sync reports to Guard Cloud."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.install_commands import build_harness_verification, list_harness_setup_items
from codex_plugin_scanner.guard.runtime.fleet_posture_common import DIAGNOSTICS_STATE_KEY, iso
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _record_fleet_check(store: GuardStore, at: datetime, **statuses: str) -> None:
    entries = {
        harness: {
            "at": iso(at),
            "diagnostics": {"setup_status": status, "has_config_paths": True, "tool_version": None},
        }
        for harness, status in statuses.items()
    }
    store.set_sync_payload(DIAGNOSTICS_STATE_KEY, entries, iso(at))


def _items_by_harness(context: HarnessContext, store: GuardStore) -> dict[str, dict[str, object]]:
    return {str(item["harness"]): item for item in list_harness_setup_items(context, store)}


def test_app_protected_by_guard_hooks_without_an_install_record_is_protected(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    _record_fleet_check(store, datetime.now(timezone.utc) - timedelta(minutes=5), kimi="active")

    kimi = _items_by_harness(context, store)["kimi"]

    assert kimi["status"] == "protected"
    assert kimi["installed"] is True
    assert kimi["observed_copy"] == "Active Guard protection is installed."


def test_installed_app_whose_setup_check_failed_needs_repair(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = datetime.now(timezone.utc)
    store.set_managed_install("codex", True, None, {}, iso(now - timedelta(days=2)))
    _record_fleet_check(store, now - timedelta(minutes=5), codex="broken")

    codex = _items_by_harness(context, store)["codex"]

    assert codex["status"] == "needs_repair"
    assert codex["installed"] is False
    assert "hol-guard repair" in str(codex["observed_copy"])


def test_install_change_after_the_last_setup_check_wins(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = datetime.now(timezone.utc)
    _record_fleet_check(store, now - timedelta(minutes=10), codex="broken", cursor="active")
    store.set_managed_install("codex", True, None, {}, iso(now - timedelta(minutes=1)))
    store.set_managed_install("cursor", False, None, {}, iso(now - timedelta(minutes=1)))

    items = _items_by_harness(context, store)

    assert items["codex"]["status"] == "protected"
    assert items["cursor"]["installed"] is False
    assert items["cursor"]["status"] != "protected"


def test_old_setup_check_falls_back_to_the_install_record(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = datetime.now(timezone.utc)
    store.set_managed_install("codex", True, None, {}, iso(now - timedelta(days=5)))
    _record_fleet_check(store, now - timedelta(days=2), codex="broken", kimi="active")

    items = _items_by_harness(context, store)

    assert items["codex"]["status"] == "protected"
    assert items["kimi"]["installed"] is False


def test_setup_check_that_overlapped_an_install_change_is_ignored(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = datetime.now(timezone.utc)
    # Repair stamps the record first; a fleet check that ran mid-repair saw the old broken setup.
    store.set_managed_install("codex", True, None, {}, iso(now - timedelta(minutes=2)))
    _record_fleet_check(store, now - timedelta(minutes=1), codex="broken")

    assert _items_by_harness(context, store)["codex"]["status"] == "protected"


def test_app_verification_reads_the_install_record_not_the_fleet_check(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = datetime.now(timezone.utc)
    store.set_managed_install("codex", True, None, {}, iso(now - timedelta(days=2)))
    _record_fleet_check(store, now - timedelta(minutes=5), codex="broken", kimi="active")

    assert build_harness_verification("codex", context, store)["verification"]["installed"] is True
    assert build_harness_verification("kimi", context, store)["verification"]["installed"] is False
