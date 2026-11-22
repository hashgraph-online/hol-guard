"""The native store owns the fleet posture hash key."""

from __future__ import annotations

import re
import sqlite3
import threading
from pathlib import Path

from codex_plugin_scanner.guard.runtime.fleet_posture_common import (
    HASH_KEY_STATE_KEY,
    keyed_digest,
    load_hash_key,
)
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-28T01:00:00+00:00"
_LATER = "2026-09-28T02:00:00+00:00"


def test_a_new_store_gets_one_random_key_that_later_builds_reuse(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)

    created = load_hash_key(store, _NOW)

    assert re.fullmatch(rb"[0-9a-f]{64}", created) is not None
    assert store.get_sync_payload(HASH_KEY_STATE_KEY) == {"key": created.decode()}
    assert load_hash_key(store, _LATER) == created
    assert load_hash_key(GuardStore(tmp_path), _LATER) == created


def test_a_key_written_by_an_older_guard_is_kept(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    existing = "a" * 64
    store.set_sync_payload(HASH_KEY_STATE_KEY, {"key": existing}, _NOW)

    key = load_hash_key(store, _LATER)

    assert key == existing.encode()
    assert keyed_digest(key, "host") == keyed_digest(existing.encode(), "host")


def test_an_unusable_stored_key_is_replaced(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(HASH_KEY_STATE_KEY, {"key": "short"}, _NOW)

    key = load_hash_key(store, _LATER)

    assert key != b"short"
    assert re.fullmatch(rb"[0-9a-f]{64}", key) is not None
    assert store.get_sync_payload(HASH_KEY_STATE_KEY) == {"key": key.decode()}


def test_a_stored_row_that_is_not_json_is_replaced(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert into sync_state (state_key, payload_json, updated_at) values (?, 'not-json', ?)",
            (HASH_KEY_STATE_KEY, _NOW),
        )

    key = load_hash_key(store, _LATER)

    assert re.fullmatch(rb"[0-9a-f]{64}", key) is not None
    assert store.get_sync_payload(HASH_KEY_STATE_KEY) == {"key": key.decode()}


def test_two_callers_racing_on_an_empty_store_share_one_key(tmp_path: Path) -> None:
    GuardStore(tmp_path)
    barrier = threading.Barrier(2)
    keys: list[bytes] = []
    errors: list[BaseException] = []

    def build() -> None:
        try:
            store = GuardStore(tmp_path)
            barrier.wait(timeout=10)
            keys.append(load_hash_key(store, _NOW))
        except BaseException as error:
            errors.append(error)

    workers = [threading.Thread(target=build) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)

    assert errors == []
    assert len(keys) == 2
    assert keys[0] == keys[1]
    assert GuardStore(tmp_path).get_sync_payload(HASH_KEY_STATE_KEY) == {"key": keys[0].decode()}
