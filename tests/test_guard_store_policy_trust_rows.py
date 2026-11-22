"""The native store reads the policy bundle trust rows as one view and owns the Review keyring write."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy_trust_rows import PolicyBundleTrustRows, PolicyTrustRowUnreadableError

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


def test_keys_only_leaves_the_bundle_out(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("policy_bundle", {"bundleVersion": "7"}, _NOW)
    store.set_sync_payload("policy_bundle_keyring", {"keys": []}, _NOW)
    rows = store.policy_bundle_trust_rows(keys_only=True)
    assert rows.policy_bundle is None
    assert rows.policy_bundle_keyring == {"keys": []}
    assert store.policy_bundle_trust_rows().policy_bundle == {"bundleVersion": "7"}


def test_a_bundle_larger_than_one_reply_is_still_read(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    bundle = {"bundleVersion": "8", "rules": "x" * (1536 * 1024)}
    store.set_sync_payload("policy_bundle", bundle, _NOW)
    store.set_sync_payload("policy_bundle_keyring", {"keys": []}, _NOW)
    rows = store.policy_bundle_trust_rows()
    assert rows.policy_bundle == bundle
    assert rows.policy_bundle_keyring == {"keys": []}


def test_last_good_puts_the_last_good_bundle_beside_the_same_keyrings(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("policy_bundle", {"bundleVersion": "9"}, _NOW)
    store.set_sync_payload("policy_bundle_last_good", {"bundleVersion": "7"}, _NOW)
    store.set_sync_payload("policy_bundle_keyring", {"keys": []}, _NOW)
    rows = store.policy_bundle_trust_rows(last_good=True)
    assert rows.policy_bundle == {"bundleVersion": "7"}
    assert rows.policy_bundle_keyring == {"keys": []}
    assert store.policy_bundle_trust_rows().policy_bundle == {"bundleVersion": "9"}


def test_a_last_good_bundle_larger_than_one_reply_is_read_from_its_own_row(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    last_good = {"bundleVersion": "7", "rules": "x" * (1536 * 1024)}
    store.set_sync_payload("policy_bundle", {"bundleVersion": "9"}, _NOW)
    store.set_sync_payload("policy_bundle_last_good", last_good, _NOW)
    rows = store.policy_bundle_trust_rows(last_good=True)
    assert rows.policy_bundle == last_good


def test_trust_rows_that_never_settle_raise_a_retryable_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.store_policy_trust_rows import PolicyTrustRowsUnstableError

    store = GuardStore(tmp_path)
    stamps = iter(range(100))

    def moving(_method: str, _args: object, **_kwargs: object) -> dict[str, object]:
        return {"policy_bundle_deferred": True, "policy_bundle_stamp": {"bytes": next(stamps)}}

    monkeypatch.setattr(store, "_native_store_call", moving)
    monkeypatch.setattr(store, "get_sync_payload", lambda _key: None)
    with pytest.raises(PolicyTrustRowsUnstableError):
        store.policy_bundle_trust_rows()


def test_an_unreadable_bundle_too_large_for_one_reply_reads_as_absent(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("policy_bundle", {"bundleVersion": "8"}, _NOW)
    store.set_sync_payload("policy_bundle_keyring", {"keys": []}, _NOW)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update sync_state set payload_json = ? where state_key = ?",
            ("{" + "x" * (1536 * 1024), "policy_bundle"),
        )
    rows = store.policy_bundle_trust_rows()
    assert rows.policy_bundle is None
    assert rows.policy_bundle_keyring == {"keys": []}


def test_review_key_read_reports_a_store_outage_as_native_unavailable() -> None:
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.native_guard_store import NativeGuardStoreUnavailable
    from codex_plugin_scanner.guard.native_policy_bundle import NATIVE_UNAVAILABLE_REJECTION
    from codex_plugin_scanner.guard.review_oauth_binding import GuardReviewContractError
    from codex_plugin_scanner.guard.review_signature_verification import _anchored_review_verification_keys

    def unavailable(*, keys_only: bool = False) -> PolicyBundleTrustRows:
        raise NativeGuardStoreUnavailable("resident unavailable")

    with pytest.raises(GuardReviewContractError) as raised:
        _anchored_review_verification_keys(SimpleNamespace(policy_bundle_trust_rows=unavailable))
    assert str(raised.value) == NATIVE_UNAVAILABLE_REJECTION
    assert isinstance(raised.value.__cause__, NativeGuardStoreUnavailable)


def test_review_keyring_readiness_is_false_when_the_store_cannot_answer() -> None:
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.native_guard_store import NativeGuardStoreUnavailable
    from codex_plugin_scanner.guard.review_verification_keyring import review_verification_keyring_ready

    def unavailable(*, keys_only: bool = False) -> PolicyBundleTrustRows:
        raise NativeGuardStoreUnavailable("resident unavailable")

    store = SimpleNamespace(
        get_cloud_sync_profile=lambda: {"workspace_id": "workspace-1"},
        policy_bundle_trust_rows=unavailable,
    )
    assert review_verification_keyring_ready(store) is False  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize(
    "state_key",
    [
        "policy_bundle_keyring",
        "policy_bundle_acceptance_checkpoint",
        "managed_policy_bundle_keyring_provenance",
        "supply_chain_bundle_keyring",
        "guard_review_verification_keyring",
    ],
)
def test_a_trust_row_that_is_not_json_refuses_the_snapshot(tmp_path: Path, state_key: str) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(state_key, {"keys": []}, _NOW)
    with sqlite3.connect(store.path) as connection:
        connection.execute("update sync_state set payload_json = 'not-json' where state_key = ?", (state_key,))

    with pytest.raises(PolicyTrustRowUnreadableError, match=state_key):
        store.policy_bundle_trust_rows()
    with pytest.raises(PolicyTrustRowUnreadableError, match=state_key):
        store.policy_bundle_trust_rows(keys_only=True)


def test_a_delivery_row_that_is_not_json_reads_as_absent(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("policy_bundle_ack", {"ok": True}, _NOW)
    with sqlite3.connect(store.path) as connection:
        connection.execute("update sync_state set payload_json = 'not-json' where state_key = 'policy_bundle_ack'")

    assert store.policy_bundle_trust_rows().policy_bundle_ack is None
