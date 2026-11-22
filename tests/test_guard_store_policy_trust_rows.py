"""The native store reads the policy bundle trust rows as one view and owns the Review keyring write."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy_trust_rows import PolicyBundleTrustRows

_NOW = "2026-11-21T12:00:00Z"


def test_an_empty_store_reads_an_empty_view(tmp_path: Path) -> None:
    assert GuardStore(tmp_path).policy_bundle_trust_rows() == PolicyBundleTrustRows()


def test_each_row_is_read_from_its_sync_key(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    keys = {
        "policy_bundle": "policy_bundle",
        "policy_bundle_keyring": "policy_bundle_keyring",
        "policy_bundle_acceptance_checkpoint": "acceptance_checkpoint",
        "managed_policy_bundle_keyring_provenance": "managed_keyring_provenance",
        "supply_chain_bundle_keyring": "supply_chain_keyring",
        "guard_review_verification_keyring": "review_verification_keyring",
        "policy_bundle_ack": "policy_bundle_ack",
        "sync_summary": "sync_summary",
        "policy_bundle_last_error": "policy_bundle_last_error",
    }
    for key in keys:
        store.set_sync_payload(key, {"row": key}, _NOW)
    rows = store.policy_bundle_trust_rows()
    for key, field in keys.items():
        assert getattr(rows, field) == {"row": key}
    assert rows.workspace_id is None


def test_the_review_keyring_write_is_read_back(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.record_review_verification_keyring([{"key_id": "k1"}], _NOW)
    assert store.policy_bundle_trust_rows().review_verification_keyring == [{"key_id": "k1"}]
    assert store.get_sync_payload("guard_review_verification_keyring") == [{"key_id": "k1"}]
    store.record_review_verification_keyring([], _NOW)
    assert store.policy_bundle_trust_rows().review_verification_keyring == []


def test_a_malformed_review_keyring_write_stores_nothing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    with pytest.raises(ValueError):
        store.record_review_verification_keyring([{"key_id": "k1"}, "k2"], _NOW)  # pyright: ignore[reportArgumentType]
    with pytest.raises(ValueError):
        store.record_review_verification_keyring([], " ")
    assert store.policy_bundle_trust_rows().review_verification_keyring is None
