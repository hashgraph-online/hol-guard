"""The native store owns the fleet posture per-tool diagnostics cache."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.fleet_posture_common import DIAGNOSTICS_STATE_KEY, iso
from codex_plugin_scanner.guard.runtime.fleet_posture_tools import DiagnosticsCache
from codex_plugin_scanner.guard.store import GuardStore

_NOW = datetime(2026, 9, 28, 0, 10, tzinfo=timezone.utc)


def _summary(status: str) -> dict[str, object]:
    return {"setup_status": status, "has_config_paths": True, "tool_version": None}


def test_only_fresh_entries_are_read_and_new_ones_merge(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(
        DIAGNOSTICS_STATE_KEY,
        {
            "codex": {"at": iso(_NOW - timedelta(minutes=5)), "diagnostics": _summary("active")},
            "cursor": {"at": iso(_NOW - timedelta(minutes=11)), "diagnostics": _summary("broken")},
        },
        iso(_NOW),
    )
    assert store.fleet_posture_cached_diagnostics(now=iso(_NOW), ttl_seconds=600) == {"codex": _summary("active")}
    assert store.fleet_posture_cached_diagnostics(now=iso(_NOW), ttl_seconds=0) == {}

    store.record_fleet_posture_diagnostics(entries={"cursor": _summary("partial")}, now=iso(_NOW))
    assert store.get_sync_payload(DIAGNOSTICS_STATE_KEY) == {
        "codex": {"at": iso(_NOW - timedelta(minutes=5)), "diagnostics": _summary("active")},
        "cursor": {"at": iso(_NOW), "diagnostics": _summary("partial")},
    }


def test_the_cache_probes_only_missing_tools_and_saves_what_it_probed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import native_harness_ops

    store = GuardStore(tmp_path)
    store.record_fleet_posture_diagnostics(entries={"codex": _summary("active")}, now=iso(_NOW))
    probed: list[str] = []

    def probe(harness: str, _context: object) -> dict[str, object]:
        probed.append(harness)
        return {"setup_status": "broken", "config_paths": [], "artifacts": []}

    monkeypatch.setattr(native_harness_ops, "diagnostics", probe)
    cache = DiagnosticsCache(store, now=_NOW + timedelta(minutes=1))
    assert cache.lookup("codex", None) == _summary("active")
    assert cache.lookup("cursor", None) == {"setup_status": "broken", "has_config_paths": False, "tool_version": None}
    cache.save()

    assert probed == ["cursor"]
    stored = store.get_sync_payload(DIAGNOSTICS_STATE_KEY)
    assert isinstance(stored, dict)
    assert stored["codex"]["at"] == iso(_NOW)
    assert stored["cursor"]["at"] == iso(_NOW + timedelta(minutes=1))


@pytest.mark.parametrize(
    ("entries", "now", "code"),
    [
        ({}, iso(_NOW), "invalid_entries"),
        ({"codex": "active"}, iso(_NOW), "invalid_entries"),
        ({"codex": _summary("active")}, "soon", "invalid_now"),
    ],
)
def test_malformed_records_are_refused_without_a_write(
    tmp_path: Path, entries: dict[str, object], now: str, code: str
) -> None:
    store = GuardStore(tmp_path)
    with pytest.raises(ValueError, match=code):
        store.record_fleet_posture_diagnostics(entries=entries, now=now)
    assert store.get_sync_payload(DIAGNOSTICS_STATE_KEY) is None
