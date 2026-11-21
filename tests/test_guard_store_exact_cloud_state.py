"""The native store owns the exact Cloud Review consent rows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-28T00:10:00+00:00"
_CAPABILITY = "guard_exact_cloud_review_capability"
_REVOCATION = "guard_exact_cloud_review_revocation"


def _put_raw(store: GuardStore, key: str, text: str) -> None:
    with store._connect() as connection:
        connection.execute(
            "insert or replace into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
            (key, text, _NOW),
        )


def _events(store: GuardStore, name: str) -> list[dict[str, object]]:
    with store._connect() as connection:
        rows = connection.execute(
            "select payload_json from guard_events where event_name = ? order by event_id",
            (name,),
        ).fetchall()
    return [json.loads(str(row["payload_json"])) for row in rows]


def test_an_empty_store_has_no_consent(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    assert store.exact_cloud_review_state() == {"capability": None, "revocation": None}
    assert store.has_exact_cloud_review_receipt("receipt-1") is False


def test_a_non_object_revocation_still_reads_as_present(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    _put_raw(store, _REVOCATION, '"revoked"')
    _put_raw(store, _CAPABILITY, "not json")
    assert store.exact_cloud_review_state() == {"capability": None, "revocation": "revoked"}


def test_replace_writes_the_rows_and_the_event(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(_REVOCATION, {"revokedAt": "earlier"}, _NOW)
    replaced = store.replace_exact_cloud_review_state(
        capability={"nonce": "n1"},
        revocation=None,
        now=_NOW,
        event_name="cloud_review.exact_capability_issued",
        event_payload={"operation": "review"},
    )
    assert replaced is True
    assert store.exact_cloud_review_state() == {"capability": {"nonce": "n1"}, "revocation": None}
    assert _events(store, "cloud_review.exact_capability_issued") == [{"operation": "review"}]


def test_a_changed_capability_is_not_replaced(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(_CAPABILITY, {"nonce": "n2"}, _NOW)
    replaced = store.replace_exact_cloud_review_state(
        capability=None,
        revocation={"revokedAt": _NOW},
        now=_NOW,
        event_name="cloud_review.exact_capability_revoked",
        event_payload={"reason": "local_disable"},
        expected_capability={"nonce": "n1"},
        require_expected_capability=True,
    )
    assert replaced is False
    assert store.exact_cloud_review_state() == {"capability": {"nonce": "n2"}, "revocation": None}
    assert _events(store, "cloud_review.exact_capability_revoked") == []


def test_a_matching_capability_is_revoked(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(_CAPABILITY, {"nonce": "n1"}, _NOW)
    replaced = store.replace_exact_cloud_review_state(
        capability=None,
        revocation={"revokedAt": _NOW},
        now=_NOW,
        event_name="cloud_review.exact_capability_revoked",
        event_payload={"reason": "local_disable"},
        expected_capability={"nonce": "n1"},
        require_expected_capability=True,
    )
    assert replaced is True
    assert store.exact_cloud_review_state() == {"capability": None, "revocation": {"revokedAt": _NOW}}


def test_a_malformed_replacement_is_refused(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    with pytest.raises(ValueError, match="invalid_event_name"):
        store.replace_exact_cloud_review_state(
            capability={"nonce": "n1"},
            revocation=None,
            now=_NOW,
            event_name="",
            event_payload={},
        )
    assert store.exact_cloud_review_state() == {"capability": None, "revocation": None}
