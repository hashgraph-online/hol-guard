"""The native store stamps the stored sign-in record without handing it back."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_oauth_sign_in_stamp import OAuthSignInPresence, oauth_sign_in_stamp_from_native

_NOW = "2026-11-22T00:00:00+00:00"


def _write_record(store: GuardStore, text: str) -> None:
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert or replace into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
            (store._oauth_local_credentials_state_key, text, _NOW),  # pyright: ignore[reportPrivateUsage]
        )


def test_a_home_without_a_sign_in_has_no_stamp(tmp_path: Path) -> None:
    assert GuardStore(tmp_path).oauth_sign_in_stamp() is None


def test_the_stamp_follows_the_stored_record(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    _write_record(store, '{"key_id":"first"}')
    first = store.oauth_sign_in_stamp()

    assert first is not None and len(first) == 64
    assert store.oauth_sign_in_stamp() == first

    _write_record(store, '{"key_id":"second"}')

    assert store.oauth_sign_in_stamp() not in {None, first}


def test_a_damaged_record_has_no_stamp(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    _write_record(store, "not-json")

    assert store.oauth_sign_in_stamp() is None


@pytest.mark.parametrize(
    "answer",
    [None, {}, {"stamp": 7}, {"stamp": "abc"}, {"stamp": "A" * 64}, {"stamp": None, "record": {}}],
)
def test_a_malformed_answer_is_refused(answer: object) -> None:
    with pytest.raises(RuntimeError, match="no answer"):
        _ = oauth_sign_in_stamp_from_native(answer)


def test_presence_follows_the_stored_record(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    key = store._oauth_local_credentials_state_key  # pyright: ignore[reportPrivateUsage]

    assert store.oauth_sign_in_presence(key) == OAuthSignInPresence(present=False, device_bound=False)

    _write_record(store, '{"device_id":"  "}')
    assert store.oauth_sign_in_presence(key) == OAuthSignInPresence(present=True, device_bound=False)

    _write_record(store, '{"device_id":"device-a"}')
    assert store.oauth_sign_in_presence(key) == OAuthSignInPresence(present=True, device_bound=True)


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {},
        {"present": True},
        {"present": 1, "device_bound": False},
        {"present": False, "device_bound": True},
        {"present": True, "device_bound": True, "record": {}},
    ],
)
def test_a_malformed_presence_answer_is_refused(answer: object) -> None:
    with pytest.raises(RuntimeError, match="no answer"):
        _ = OAuthSignInPresence.from_native(answer)
