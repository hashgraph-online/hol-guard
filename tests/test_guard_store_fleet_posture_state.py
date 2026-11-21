"""The native store owns the rows that steer the fleet posture report."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import fleet_posture as fp
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-27T12:00:00+00:00"
_SETTINGS = "fleet_posture_settings"
_FORCE_FULL = "fleet_posture_force_full"


def test_settings_and_request_round_trip_through_the_native_store(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    assert store.fleet_posture_state() == {
        "opted_out": False,
        "full_inventory_requested": False,
        "last_sent": None,
    }

    assert fp.set_fleet_posture_reporting(store, enabled=False, now=_NOW) == {"enabled": False, "updatedAt": _NOW}
    assert store.get_sync_payload(_SETTINGS) == {"enabled": False, "updatedAt": _NOW}
    assert fp.fleet_posture_opted_out(store)

    fp.request_full_inventory(store, source="cli", now=_NOW)
    assert store.get_sync_payload(_FORCE_FULL) == {"requestedAt": _NOW, "source": "cli"}
    assert fp.full_inventory_requested(store)


def test_a_settings_row_written_elsewhere_is_read_as_before(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(_SETTINGS, {"enabled": 0}, _NOW)
    assert not fp.fleet_posture_opted_out(store)
    store.set_sync_payload(_SETTINGS, {"enabled": False}, _NOW)
    assert fp.fleet_posture_opted_out(store)


def test_commit_clears_the_request_only_when_the_inventory_advanced(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.request_full_fleet_inventory(source="cloud", now=_NOW)

    kept = store.commit_fleet_posture_sent(next_state={"items": {}}, advanced_inventory=False, now=_NOW)
    assert kept is False
    assert fp.full_inventory_requested(store)
    assert fp.last_sent_fleet_posture(store) == {"items": {}}

    cleared = store.commit_fleet_posture_sent(next_state={"items": {"a": "1"}}, advanced_inventory=True, now=_NOW)
    assert cleared is True
    assert not fp.full_inventory_requested(store)
    assert store.get_sync_payload(_FORCE_FULL) == {}
    assert store.fleet_posture_state()["last_sent"] == {"items": {"a": "1"}}


def test_a_snapshot_wider_than_one_native_object_is_saved(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    items = {f"item-{index:05d}": f"digest-{index}" for index in range(9000)}
    store.commit_fleet_posture_sent(next_state={"items": items, "mode": "full"}, advanced_inventory=True, now=_NOW)
    assert store.get_sync_payload(fp.LAST_SENT_STATE_KEY) == {"items": items, "mode": "full"}
    assert fp.last_sent_fleet_posture(store) == {"items": items, "mode": "full"}


def test_an_empty_last_sent_snapshot_counts_as_none(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(fp.LAST_SENT_STATE_KEY, {}, _NOW)
    assert store.fleet_posture_state()["last_sent"] == {}
    assert fp.last_sent_fleet_posture(store) is None


@pytest.mark.parametrize(
    ("method", "kwargs", "code"),
    [
        ("set_fleet_posture_reporting", {"enabled": "no", "now": _NOW}, "invalid_enabled"),
        ("request_full_fleet_inventory", {"source": "", "now": _NOW}, "invalid_source"),
    ],
)
def test_malformed_inputs_are_refused_without_a_write(
    tmp_path: Path, method: str, kwargs: dict[str, object], code: str
) -> None:
    store = GuardStore(tmp_path)
    with pytest.raises(ValueError, match=code):
        getattr(store, method)(**kwargs)
    assert store.get_sync_payload(_SETTINGS) is None
    assert store.get_sync_payload(_FORCE_FULL) is None
