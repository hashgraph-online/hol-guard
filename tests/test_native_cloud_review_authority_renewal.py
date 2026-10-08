"""Saved-authority transitions only; these fixtures are not native crypto proof."""
from __future__ import annotations

import base64
import hashlib
from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import native_cloud_review_v4 as native
from tests.test_native_approval_v4_transport import _challenge, _result


def _renewal() -> tuple[dict[str, object], dict[str, object]]:
    original = _challenge()
    fresh = deepcopy(original)
    fresh.update({"nonce":"c" * 64, "resident_epoch":"d" * 64, "issued_at_ms":original["expires_at_ms"] + 1,
                  "expires_at_ms":original["expires_at_ms"] + 1001,
                  "policy_generation":original["policy_generation"] + 1, "policy_digest":"e" * 64, "request_digest":"f" * 64})
    fresh["webauthn"]["challenge"] = base64.urlsafe_b64encode(bytes.fromhex(fresh["nonce"])).decode().rstrip("=")
    return original, {"schema":"guard-native-cloud-review-renewal-result.v4", "version":4,
        "request_id":original["request_id"], "decision_receipt_id":"saved-decision", "source_claim_hash":"a" * 64,
        "original_nonce_digest":hashlib.sha256(bytes.fromhex(original["nonce"])).hexdigest(),
        "challenge":fresh, "consent_revision":2, "revocation_epoch":0}


@pytest.mark.parametrize("field,value", [
    ("action_digest", "e" * 64), ("harness", "codex"), ("workspace_binding", "f" * 64),
    ("device_binding", "e" * 64), ("installation_binding", "f" * 64),
    ("rule_digest", "f" * 64), ("runtime_binary_identity", "e" * 64),
])
def test_renewal_cannot_replace_frozen_action_or_client_identity(field: str, value: str) -> None:
    original, renewed = _renewal()
    assert native.native_renewal_matches_original(renewed, original)
    renewed["challenge"][field] = value
    assert not native.native_renewal_matches_original(renewed, original)


@pytest.mark.parametrize("field,value", [("credential_id", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"), ("origin", "https://sub.example.com")])
def test_renewal_cannot_replace_frozen_root_webauthn_binding(field: str, value: str) -> None:
    original, renewed = _renewal()
    renewed["challenge"]["webauthn"][field] = value
    assert not native.native_renewal_matches_original(renewed, original)


def test_rotated_key_can_change_only_key_bound_webauthn_fields() -> None:
    original, renewed = _renewal()
    renewed["challenge"]["signing_key_id"] = "e" * 64
    renewed["challenge"]["webauthn"]["credential_id"] = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
    renewed["challenge"]["webauthn"]["algorithm"] = -7 if original["webauthn"]["algorithm"] == -8 else -8
    assert native.native_renewal_matches_original(renewed, original)
    for field, value in (("origin", "https://another.example"), ("rp_id", "another.example")):
        changed = deepcopy(renewed)
        changed["challenge"]["webauthn"][field] = value
        assert not native.native_renewal_matches_original(changed, original)


@pytest.mark.parametrize("code", [
    "native_approval_transport_uncertain", "native_cloud_review_v4_state_unavailable",
    "native_cloud_review_v4_state_invalid", "native_cloud_review_v4_origin_missing",
])
def test_unknown_original_outcome_never_allows_another_authority(code: str, monkeypatch, tmp_path: Path) -> None:
    original, renewed = _renewal()

    def daemon(_home, operation, _request):
        if operation == "approval_consumption_query_v4":
            raise native.NativeCloudReviewV4Error(code)
        return renewed

    monkeypatch.setattr(native, "request_native_cloud_review", daemon)
    with pytest.raises(native.NativeCloudReviewV4Error) as failure:
        native.renew_native_approval_authority(tmp_path, request_id=original["request_id"], decision_receipt_id="saved-decision",
            source_claim_hash="a" * 64, original_challenge=original)
    assert failure.value.code == code


@pytest.mark.parametrize("phase,expected", [
    ("consumed", "native_cloud_review_v4_already_consumed"),
    ("recovery_required", "native_cloud_review_v4_consumption_recovery_required"),
])
def test_saved_consumption_outcome_blocks_new_authority(phase: str, expected: str, monkeypatch, tmp_path: Path) -> None:
    original, renewed = _renewal()
    observed = {"schema":"guard-native-cloud-review-application-result.v4", "version":4,
        "request_id":original["request_id"], "decision_receipt_id":"saved-decision", "source_claim_hash":"a" * 64,
        "phase":phase, "receipt":_result(phase="consumed")["receipt"] if phase == "consumed" else None,
        "consumed_at_ms":1500 if phase == "consumed" else None}

    def daemon(_home, operation, _request):
        return observed if operation == "approval_consumption_query_v4" else renewed

    monkeypatch.setattr(native, "request_native_cloud_review", daemon)
    with pytest.raises(native.NativeCloudReviewV4Error) as failure:
        native.renew_native_approval_authority(tmp_path, request_id=original["request_id"], decision_receipt_id="saved-decision",
            source_claim_hash="a" * 64, original_challenge=original)
    assert failure.value.code == expected
