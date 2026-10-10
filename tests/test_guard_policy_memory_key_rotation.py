"""Authenticated policy memory survives explicit signer expiry/revocation transitions."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.review_policy_memory_executor import native_review_policy_memory_actions
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_review_signing_helpers import review_verification_keys
from tests.test_guard_review_policy_memory_command import _bundle, _execute, _resign_bundle, _store

_STALE_SIGNING_KEY_ID = "guard-review-stale-key"
_STALE_SIGNER_FIELDS = [{"state": "revoked"}, {"validUntil": "2000-01-01T00:00:00+00:00"}]


def _retain_then_stale_signer(store: GuardStore, stale_fields: dict[str, object]) -> None:
    key = dict(review_verification_keys(workspace_id=None, purpose="unscoped")[0])
    key["keyId"] = _STALE_SIGNING_KEY_ID
    anchored = [*(store.get_sync_payload("policy_bundle_keyring") or []), key]
    store.set_sync_payload("policy_bundle_keyring", anchored, datetime.now(timezone.utc).isoformat())
    bundle = _bundle(store)
    bundle["issuerKeyId"] = _STALE_SIGNING_KEY_ID
    bundle["verificationKeys"] = [key]
    result = _execute(store, {"decisionMemoryBundle": _resign_bundle(bundle)})
    assert result.get("data", {}).get("status") == "accepted", result
    store.set_sync_payload(
        "policy_bundle_keyring",
        [{**entry, **stale_fields} if entry["keyId"] == _STALE_SIGNING_KEY_ID else entry for entry in anchored],
        datetime.now(timezone.utc).isoformat(),
    )


@pytest.mark.parametrize("stale_fields", _STALE_SIGNER_FIELDS, ids=["revoked", "expired"])
def test_fresh_signer_can_revoke_entry_from_stale_signer(tmp_path: Path, stale_fields: dict[str, object]) -> None:
    # A fresh anchored signer must evict a retained entry whose signer has since
    # been revoked or expired; the stale signer cannot veto its own removal.
    store = _store(tmp_path)
    _retain_then_stale_signer(store, stale_fields)

    bundle = _bundle(store)
    bundle["memoryRules"] = []
    bundle["revocations"] = ["review-memory:receipt-1"]
    bundle["policyVersion"] = "policy-version-next"

    result = _execute(store, {"decisionMemoryBundle": _resign_bundle(bundle)})

    assert result["data"]["status"] == "accepted"
    assert store.get_sync_payload("guard_review_memory_registry") == []
    assert store.list_policy_decisions() == []
    assert native_review_policy_memory_actions(store) == []


@pytest.mark.parametrize("stale_fields", _STALE_SIGNER_FIELDS, ids=["revoked", "expired"])
def test_fresh_signer_can_replace_entry_from_stale_signer(tmp_path: Path, stale_fields: dict[str, object]) -> None:
    store = _store(tmp_path)
    _retain_then_stale_signer(store, stale_fields)

    bundle = _bundle(store)
    bundle["memoryRules"][0]["action"] = "block"
    bundle["policyVersion"] = "policy-version-next"
    _resign_bundle(bundle)

    result = _execute(store, {"decisionMemoryBundle": bundle})

    assert result["data"]["status"] == "accepted"
    assert native_review_policy_memory_actions(store)[0]["action"] == "block"


@pytest.mark.parametrize("stale_fields", _STALE_SIGNER_FIELDS, ids=["revoked", "expired"])
def test_unrelated_stale_registry_entry_still_fails_closed(tmp_path: Path, stale_fields: dict[str, object]) -> None:
    # A stale signer entry the fresh bundle does not touch must still fail
    # closed: the whole bundle is rejected and retained state is unchanged.
    store = _store(tmp_path)
    _retain_then_stale_signer(store, stale_fields)
    before_registry = store.get_sync_payload("guard_review_memory_registry")
    before_version = store.get_sync_payload("guard_review_memory_policy_version")
    before_policies = store.list_policy_decisions()

    bundle = _bundle(store)
    bundle["memoryRules"] = []
    bundle["revocations"] = ["review-memory:not-retained"]
    bundle["policyVersion"] = "policy-version-next"

    result = _execute(store, {"decisionMemoryBundle": _resign_bundle(bundle)})

    assert result["failureCode"] == "expired_signing_key"
    assert store.get_sync_payload("guard_review_memory_registry") == before_registry
    assert store.get_sync_payload("guard_review_memory_policy_version") == before_version
    assert store.list_policy_decisions() == before_policies
