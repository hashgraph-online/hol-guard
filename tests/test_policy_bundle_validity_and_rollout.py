"""Canonical rollout posture and injected validity clock regressions."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.policy_bundle_parser import (
    _POLICY_BUNDLE_ROLLOUT_STATE_ABSENT,
    policy_bundle_is_enforceable,
)
from codex_plugin_scanner.guard.policy_bundle_rollout import policy_bundle_rollout_state
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import validate_synced_policy_bundle
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    POLICY_BUNDLE_V2_CONTRACT,
    validated_policy_bundle_v2_payload,
)
from codex_plugin_scanner.guard.policy_canonical_rollout import (
    canonical_policy_enforcement_enabled,
    canonical_runtime_posture,
    selected_enforcement_lane,
)
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key


def test_v2_draft_rollout_is_not_enforceable() -> None:
    bundle = {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "payload": {"spec": {"rolloutState": "draft"}},
    }
    assert policy_bundle_rollout_state(bundle) == "draft"
    assert policy_bundle_is_enforceable(bundle) is False


def test_v2_enforcing_rollout_is_live() -> None:
    bundle = {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "payload": {"spec": {"rolloutState": "enforcing"}},
    }
    assert policy_bundle_is_enforceable(bundle) is True


def test_v2_omitted_rollout_is_compat_and_present_null_is_not_enforceable() -> None:
    omitted = {"contractVersion": POLICY_BUNDLE_V2_CONTRACT, "payload": {"spec": {}}}
    present_null = {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "payload": {"spec": {"rolloutState": None}},
    }
    malformed = {"contractVersion": POLICY_BUNDLE_V2_CONTRACT, "payload": "not-an-object"}
    assert policy_bundle_rollout_state(omitted) is _POLICY_BUNDLE_ROLLOUT_STATE_ABSENT
    assert policy_bundle_is_enforceable(omitted) is True
    assert policy_bundle_rollout_state(present_null) is None
    assert policy_bundle_is_enforceable(present_null) is False
    assert policy_bundle_rollout_state(malformed) is None
    assert policy_bundle_is_enforceable(malformed) is False


def test_flag_off_lane_is_legacy_and_v2_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", raising=False)
    posture = canonical_runtime_posture(
        device_id="device-1",
        workspace_id="ws",
        contract_version=POLICY_BUNDLE_V2_CONTRACT,
    )
    assert posture["canonical_policy_enforcement_enabled"] is False
    assert posture["selected_enforcement_lane"] == "unverified"
    assert posture["canonical_incompatibility_reason"] == "canonical_enforcement_disabled"
    assert posture["canonical_rollout_percentage"] == 0
    assert "canonical_policy_enforcement" not in posture
    lane, reason = selected_enforcement_lane(
        device_id="device-1",
        workspace_id="ws",
        protected_authority=True,
        negotiated_capabilities=frozenset(),
        contract_version=POLICY_BUNDLE_V2_CONTRACT,
    )
    assert lane == "unverified"
    assert reason == "canonical_enforcement_disabled"
    assert canonical_policy_enforcement_enabled(device_id="device-1", workspace_id="ws") is False


def test_enabled_lane_is_canonical(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    lane, reason = selected_enforcement_lane(
        device_id="device-1",
        workspace_id="ws",
        protected_authority=True,
        negotiated_capabilities=frozenset(),
        contract_version=POLICY_BUNDLE_V2_CONTRACT,
    )
    assert lane == "canonical"
    assert reason is None


def test_missing_negotiated_capability_is_incompatible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    lane, reason = selected_enforcement_lane(
        device_id="device-1",
        workspace_id="ws",
        protected_authority=True,
        negotiated_capabilities=frozenset(),
        required_capability="custom-extension-continuity.v2",
    )
    assert lane == "incompatible"
    assert reason == "missing_negotiated_capability"


def test_missing_protected_authority_is_incompatible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")
    lane, reason = selected_enforcement_lane(
        device_id="device-1",
        workspace_id="ws",
        protected_authority=False,
        negotiated_capabilities=frozenset(),
        required_capability="policy-extension-targets.v1",
        contract_version=POLICY_BUNDLE_V2_CONTRACT,
    )
    assert lane == "incompatible"
    assert reason == "missing_protected_authority"


def test_v1_and_v2_share_one_injected_clock_for_issue_and_expiry_boundaries() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)
    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=now,
    )
    assert reason is None
    assert validated is not None

    too_early = datetime(2026, 7, 15, 11, 54, tzinfo=timezone.utc)
    rejected, future_reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=too_early,
    )
    assert rejected is None
    assert future_reason == "bundle_not_yet_valid"

    shared, shared_reason, _keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring={"keys": [verification_key.to_dict()]},
        expected_workspace_id="workspace-alpha",
        now=now.timestamp(),
    )
    assert shared_reason is None
    assert validated == shared

    at_expiry = datetime(2030, 7, 15, 12, 0, tzinfo=timezone.utc)
    still_valid, expiry_reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=at_expiry,
    )
    assert still_valid is not None
    assert expiry_reason is None
    after_expiry = datetime(2030, 7, 15, 12, 0, 1, tzinfo=timezone.utc)
    expired, expired_reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=after_expiry,
    )
    assert expired is None
    assert expired_reason == "bundle_expired"
