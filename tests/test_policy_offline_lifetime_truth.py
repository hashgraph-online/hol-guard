"""Signed cached authority must distinguish absence, rejection and expiry."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import (
    cached_policy_bundle_validation,
    offline_policy_lifetime,
    synced_policy_payload,
    validated_synced_policy_bundle,
)
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
from tests.test_synced_policy import _signed_policy_bundle

_NOW = datetime(2026, 7, 3, tzinfo=timezone.utc).timestamp()
_RECORDED = "2026-07-03T00:00:00Z"


def _bundle(kind: str | None) -> dict[str, object] | None:
    if kind is None:
        return None
    bundle = _signed_policy_bundle()
    if kind == "expired":
        bundle["expiresAt"] = "2026-07-02T00:00:00Z"
        return sign_policy_bundle(bundle)
    if kind == "inactive":
        bundle["rolloutState"] = "draft"
        return sign_policy_bundle(bundle)
    if kind == "wrong-workspace":
        return sign_policy_bundle(bundle, workspace_id="workspace-other")
    if kind == "tampered":
        defaults = bundle["policyDefaults"]
        assert isinstance(defaults, dict)
        defaults["defaultAction"] = "block"
    return bundle


def _store(
    tmp_path: Path, current: str | None, last_good: str | None, *, key_state: str = "active"
) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-1"}, _RECORDED)
    keyring = policy_bundle_test_keyring(workspace_id="workspace-1")
    if key_state == "untrusted":
        keyring = {"keys": []}
    elif key_state == "revoked":
        keys = keyring["keys"]
        assert isinstance(keys, list) and isinstance(keys[0], dict)
        keys[0]["state"] = "revoked"
    store.set_sync_payload("policy_bundle_keyring", keyring, _RECORDED)
    for key, kind in (("policy_bundle", current), ("policy_bundle_last_good", last_good)):
        value = _bundle(kind)
        if value is not None:
            store.set_sync_payload(key, value, _RECORDED)
    store.set_sync_payload("policy", {"defaultAction": "allow"}, _RECORDED)
    return store


@pytest.mark.parametrize(
    ("current", "last_good", "key_state", "state"),
    [
        pytest.param(None, None, "active", "absent", id="no-cached-authority"),
        pytest.param("inactive", None, "active", "rejected", id="inactive-current"),
        pytest.param("wrong-workspace", None, "active", "rejected", id="wrong-workspace"),
        pytest.param("valid", None, "untrusted", "rejected", id="untrusted-signature-key"),
        pytest.param("tampered", None, "active", "rejected", id="tampered-current"),
        pytest.param(None, "inactive", "active", "rejected", id="inactive-last-good"),
        pytest.param("expired", None, "active", "expired", id="expired-current"),
        pytest.param(None, "expired", "active", "expired", id="expired-last-good"),
        pytest.param("expired", "expired", "active", "expired", id="both-expired"),
        pytest.param("expired", "inactive", "active", "rejected", id="expired-and-rejected"),
        pytest.param("inactive", "expired", "active", "rejected", id="rejected-and-expired"),
        pytest.param("valid", "valid", "revoked", "recovery", id="revoked-key"),
    ],
)
def test_unavailable_authority_reports_its_actual_failure_class(
    tmp_path: Path, current: str | None, last_good: str | None, key_state: str, state: str
) -> None:
    store = _store(tmp_path, current, last_good, key_state=key_state)
    current_payload = store.get_sync_payload("policy_bundle")
    last_good_payload = store.get_sync_payload("policy_bundle_last_good")
    current_validated, current_reason = cached_policy_bundle_validation(store, current_payload, now=_NOW)
    last_validated, last_reason = cached_policy_bundle_validation(store, last_good_payload, now=_NOW)
    before = deepcopy((current_payload, last_good_payload))
    assert current_validated is None and last_validated is None
    if current == "expired":
        assert current_reason == "bundle_expired"
    if last_good == "expired":
        assert last_reason == "bundle_expired"
    if current == "inactive":
        assert current_reason == "inactive_rollout_state"
    if current == "wrong-workspace":
        assert current_reason == "wrong_workspace"
    if key_state == "revoked":
        assert current_reason == "signing_key_revoked"
    if state == "rejected":
        assert any(reason and reason != "bundle_expired" for reason in (current_reason, last_reason))

    lifetime = offline_policy_lifetime(store, now=_NOW)

    assert lifetime["active"] is False
    assert lifetime["retained"] is False
    assert lifetime["currentError"] == current_reason
    assert lifetime["lastGoodError"] == last_reason
    assert validated_synced_policy_bundle(store, now=_NOW) is None
    assert synced_policy_payload(store) is None
    assert (store.get_sync_payload("policy_bundle"), store.get_sync_payload("policy_bundle_last_good")) == before
    assert lifetime["state"] == state
    assert lifetime["expired"] is (state == "expired")
    assert lifetime["recovery"] is (state == "recovery")


def test_authenticated_current_bundle_keeps_its_valid_posture(tmp_path: Path) -> None:
    store = _store(tmp_path, "valid", "expired")

    lifetime = offline_policy_lifetime(store, now=_NOW)

    assert lifetime == {
        "state": "current-valid", "active": True, "retained": False, "expired": False, "recovery": False,
    }
    assert validated_synced_policy_bundle(store, now=_NOW) is not None


@pytest.mark.parametrize("current", [None, "expired", "inactive"])
def test_valid_last_good_keeps_retention_separate_from_current_failure(
    tmp_path: Path, current: str | None
) -> None:
    store = _store(tmp_path, current, "valid")
    _, reason = cached_policy_bundle_validation(store, store.get_sync_payload("policy_bundle"), now=_NOW)

    lifetime = offline_policy_lifetime(store, now=_NOW)

    assert lifetime["state"] == "last-good-valid"
    assert lifetime["active"] is True
    assert lifetime["retained"] is True
    assert lifetime["expired"] is (current == "expired")
    assert lifetime["currentError"] == reason
    assert lifetime["recovery"] is False
    assert validated_synced_policy_bundle(store, now=_NOW) is None
    assert synced_policy_payload(store) is None
