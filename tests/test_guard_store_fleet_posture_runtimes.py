"""The native store owns the fleet posture runtimes section cache."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.fleet_posture_common import iso
from codex_plugin_scanner.guard.runtime.fleet_posture_runtimes import RUNTIMES_STATE_KEY
from codex_plugin_scanner.guard.store import GuardStore

_NOW = datetime(2026, 9, 28, 1, 0, 0, 250_000, tzinfo=timezone.utc)
_SECTION: dict[str, object] = {"scope": "partial", "runtimes": [{"family": "node"}]}


def _cached(store: GuardStore, *, scope: str = "scope-a", minutes: float = 0, ttl: int = 3600) -> object:
    return store.fleet_posture_cached_runtimes(
        scope=scope, now=(_NOW + timedelta(minutes=minutes)).isoformat(), ttl_seconds=ttl
    )


def test_a_recorded_section_answers_for_its_scope_until_the_ttl(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    assert _cached(store) is None
    store.record_fleet_posture_runtimes(scope="scope-a", section=_SECTION, valid_until=None, now=iso(_NOW))

    stored = store.get_sync_payload(RUNTIMES_STATE_KEY)
    assert stored == {"at": iso(_NOW), "scope": "scope-a", "section": _SECTION, "valid_until": None}
    assert _cached(store) == _SECTION
    assert _cached(store, minutes=59) == _SECTION
    assert _cached(store, minutes=60) is None
    assert _cached(store, minutes=-1) is None
    assert _cached(store, scope="scope-b") is None
    assert _cached(store, ttl=0) is None


def test_a_section_lapses_with_its_bundle(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    expires = (_NOW + timedelta(minutes=10)).timestamp()
    store.record_fleet_posture_runtimes(scope="scope-a", section=_SECTION, valid_until=expires, now=iso(_NOW))

    assert _cached(store, minutes=9) == _SECTION
    assert _cached(store, minutes=10) is None


@pytest.mark.parametrize(
    ("scope", "section", "valid_until", "now", "code"),
    [
        ("", _SECTION, None, iso(_NOW), "invalid_scope"),
        ("scope-a", _SECTION, None, "soon", "invalid_now"),
    ],
)
def test_malformed_records_are_refused_without_a_write(
    tmp_path: Path, scope: str, section: dict[str, object], valid_until: float | None, now: str, code: str
) -> None:
    store = GuardStore(tmp_path)
    with pytest.raises(ValueError, match=code):
        store.record_fleet_posture_runtimes(scope=scope, section=section, valid_until=valid_until, now=now)
    assert store.get_sync_payload(RUNTIMES_STATE_KEY) is None
