from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_cloud_review_consent import NativeCloudReviewConsentError
from codex_plugin_scanner.guard.runtime import exact_cloud_review as exact
from tests.guard_exact_cloud_review_support import connected_exact_review_store


@pytest.fixture
def consent(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    issued = int(datetime.now(timezone.utc).timestamp() * 1000)
    state: dict[str, object] = {
        "schema": "guard-native-cloud-review-consent-result.v1", "version": 1,
        "status": "disabled", "revision": 0, "revocation_epoch": 0,
        "issued_at_ms": 0, "expires_at_ms": 0, "native": True,
    }

    def native_authority(_home: Path, operation: str, **factors: object) -> dict[str, object]:
        if operation == "enable":
            if factors.get("password") != "synthetic-native-factor":
                raise NativeCloudReviewConsentError("approval_gate_invalid_password")
            state.update(
                status="enabled", revision=int(state["revision"]) + 1,
                issued_at_ms=issued, expires_at_ms=issued + int(factors["ttl_seconds"]) * 1000,
            )
        elif operation == "disable":
            state.update(status="disabled", revocation_epoch=int(state["revocation_epoch"]) + 1)
        return dict(state)

    monkeypatch.setattr(exact, "native_cloud_review_consent", native_authority)
    return state


def test_legacy_signed_capability_cannot_grant_native_consent(
    tmp_path: Path, consent: dict[str, object],
) -> None:
    store = connected_exact_review_store(tmp_path)
    exact.enable_exact_cloud_review(store, password="synthetic-native-factor")
    raw = store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    legacy = exact._verify(store, raw)
    legacy.pop("nativeConsentRevision")
    legacy.pop("nativeConsentRevocationEpoch")
    store.set_sync_payload(
        exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY,
        exact._sign(store, legacy, create_key=False),
        datetime.now(timezone.utc).isoformat(),
    )
    assert consent["status"] == "enabled"
    assert exact.exact_cloud_review_operations(store) == ()
    assert exact.exact_cloud_review_status(store)["reason"] == "cloud_review_capability_native_binding_mismatch"


def test_native_revocation_rejects_still_valid_sdk_signature(
    tmp_path: Path, consent: dict[str, object],
) -> None:
    store = connected_exact_review_store(tmp_path)
    exact.enable_exact_cloud_review(store, password="synthetic-native-factor")
    assert exact.exact_cloud_review_operations(store) == (exact.EXACT_CLOUD_REVIEW_OPERATION,)
    consent["revocation_epoch"] = 1
    assert exact.exact_cloud_review_operations(store) == ()
    consent["status"] = "disabled"
    assert exact.exact_cloud_review_status(store)["reason"] == "native_cloud_review_consent_disabled"


def test_missing_native_permission_never_falls_back_to_oauth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = connected_exact_review_store(tmp_path)

    def unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise NativeCloudReviewConsentError("native_cloud_review_consent_unavailable")

    monkeypatch.setattr(exact, "native_cloud_review_consent", unavailable)
    assert exact.exact_cloud_review_operations(store) == ()
    with pytest.raises(exact.ExactCloudReviewError, match="native_cloud_review_consent_unavailable"):
        exact.enable_exact_cloud_review(store, password="synthetic-native-factor")
    assert store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) is None


def test_wrong_native_factor_does_not_issue_sdk_transport(
    tmp_path: Path, consent: dict[str, object],
) -> None:
    store = connected_exact_review_store(tmp_path)
    with pytest.raises(exact.ExactCloudReviewError, match="approval_gate_invalid_password"):
        exact.enable_exact_cloud_review(store, password="wrong-factor")
    assert consent["status"] == "disabled"
    assert exact.exact_cloud_review_operations(store) == ()
    assert store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) is None


def test_disable_revokes_native_state_without_a_password(
    tmp_path: Path, consent: dict[str, object],
) -> None:
    store = connected_exact_review_store(tmp_path)
    exact.enable_exact_cloud_review(store, password="synthetic-native-factor")
    status = exact.disable_exact_cloud_review(store)
    assert status["enabled"] is False
    assert consent["status"] == "disabled"
    assert consent["revocation_epoch"] == 1
    assert exact.exact_cloud_review_operations(store) == ()
