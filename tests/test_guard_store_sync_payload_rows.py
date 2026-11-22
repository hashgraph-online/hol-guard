"""The ``sync_state`` writes and reads run in the native store."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import review_event_wake
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-27T12:00:00+00:00"
_CREDENTIALS = "oauth_local_credentials"


def test_a_payload_reads_back_and_a_missing_or_scalar_row_reads_as_none(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    assert store.get_sync_payload("prefs") is None
    store.set_sync_payload("prefs", {"enabled": False}, _NOW)
    store.set_sync_payload("cursor", ["a", "b"], _NOW)

    assert store.get_sync_payload("prefs") == {"enabled": False}
    assert store.get_sync_payload("cursor") == ["a", "b"]
    with pytest.raises(ValueError, match="invalid_payload"):
        store.set_sync_payload("prefs", "text", _NOW)  # type: ignore[arg-type]
    assert store.get_sync_payload("prefs") == {"enabled": False}


def test_a_credential_write_clears_the_cache_and_wakes_the_outbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    events: list[str] = []
    monkeypatch.setattr(type(store), "_clear_oauth_secret_payload_cache", lambda _self: events.append("clear"))
    monkeypatch.setattr(review_event_wake.ReviewEventWakeSignal, "notify", lambda _self: events.append("wake"))

    store.set_sync_payload(f"{_CREDENTIALS}:scope", {"v": 1}, _NOW)
    store.set_sync_payload("prefs", {"v": 1}, _NOW)

    assert events == ["clear", "wake"]
    assert store.get_sync_payload(f"{_CREDENTIALS}:scope") == {"v": 1}


def test_an_existing_row_wins_over_the_first_write_insert(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    store.insert_sync_payload_if_absent("key", {"value": 1}, _NOW)
    store.insert_sync_payload_if_absent("key", {"value": 2}, _NOW)

    assert store.get_sync_payload("key") == {"value": 1}


def test_deletes_remove_the_named_rows_and_count_them(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    for state_key in ("a", "b", "c"):
        store.insert_sync_payload_if_absent(state_key, {}, _NOW)
    store.set_sync_payload(_CREDENTIALS, {"v": 1}, _NOW)
    cleared: list[bool] = []
    monkeypatch.setattr(type(store), "_clear_oauth_secret_payload_cache", lambda _self: cleared.append(True))

    store.delete_sync_payload("a")
    assert cleared == []
    assert store.delete_sync_payloads(["b", "b", "missing", _CREDENTIALS]) == 2
    assert cleared == [True]
    assert store.delete_sync_payloads([]) == 0

    assert store.get_sync_payload("a") is None
    assert store.get_sync_payload("b") is None
    assert store.get_sync_payload(_CREDENTIALS) is None
    assert store.get_sync_payload("c") == {}
