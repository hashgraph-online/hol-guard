"""Actual signature/parser checks; these are not installed runtime acceptance."""

from __future__ import annotations

import json
import ssl
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from ci.native_runtime.installed_managed_policy_fixture import ManagedPolicyFixture
from ci.native_runtime.installed_scoped_policy_fixture import WORKSPACE
from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    validated_managed_controls_policy_bundle_v2_payload,
)
from codex_plugin_scanner.guard.managed_controls_policy_fields import (
    EXTENSION_CONTROL_LAYER_CAPABILITY,
    HOL_EXTENSION_CONTROLS_FIELD,
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    POLICY_EXTENSION_TARGETS_CAPABILITY,
    is_mapping,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import validate_synced_policy_bundle
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

# Parser input only; these are never advertised or written to runtime state.
PARSER_CAPABILITIES = frozenset(
    {EXTENSION_CONTROL_LAYER_CAPABILITY, MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY, POLICY_EXTENSION_TARGETS_CAPABILITY}
)
PERMISSION = "command.git.permission.force-push"


@pytest.fixture
def fixture(tmp_path: Path) -> Iterator[ManagedPolicyFixture]:
    value = ManagedPolicyFixture(tmp_path)
    try:
        yield value
    finally:
        value.close()


def _parse(fixture: ManagedPolicyFixture, bundle: dict[str, object]):
    return validated_managed_controls_policy_bundle_v2_payload(
        bundle,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=PARSER_CAPABILITIES,
        trusted_verification_keys=(fixture.verification,),
        anchored_verification_keys=(fixture.verification,),
    )


@pytest.mark.parametrize(
    ("target_kind", "target_id", "lockdown"),
    [("permission", PERMISSION, False), ("extension", "command.ollama", False), (None, None, True)],
)
def test_signed_managed_fixture_delivers_without_preinstalling_authority(
    fixture: ManagedPolicyFixture, target_kind: str | None, target_id: str | None, lockdown: bool
) -> None:
    controls = []
    if target_kind is not None and target_id is not None:
        controls.append({"targetKind": target_kind, "targetId": target_id, "state": "disabled"})
    defaults = {"mode": "observe", "defaultAction": "warn"}
    fixture.bundle = fixture.signed_managed_bundle(7, controls=controls, lockdown=lockdown, defaults=defaults)
    # Changes to caller inputs must not invalidate a previously signed payload.
    defaults["mode"] = "enforce"
    if controls:
        controls[0]["state"] = "enabled"
    request = urllib.request.Request(
        fixture.sync_url, data=b"{}", headers={"Authorization": f"Bearer {fixture.token}"}, method="POST"
    )
    with urllib.request.urlopen(
        request, context=ssl.create_default_context(cafile=str(fixture.ca_file)), timeout=2
    ) as response:
        delivered = json.load(response)["policyBundle"]
    assert delivered == fixture.bundle
    assert delivered["payloadHash"] == payload_hash_for_policy_bundle_v2(delivered)
    assert delivered["bundleHash"] == computed_policy_bundle_v2_hash(delivered)
    accepted, reason, _keys = validate_synced_policy_bundle(
        delivered,
        stored_keyring=fixture.store.get_sync_payload("policy_bundle_keyring"),
        expected_workspace_id=WORKSPACE,
    )
    assert accepted is not None and reason is None
    validated, parsed, reason = _parse(fixture, delivered)
    assert validated is not None and parsed is not None and reason is None, reason
    assert parsed.authority_mode == "managed-restrictive"
    assert parsed.managed_global_lockdown is lockdown
    assert [
        (control.target.kind.value, control.target.target_id, control.state.value)
        for control in parsed.managed_controls
    ] == ([(target_kind, target_id, "disabled")] if controls else [])
    payload = delivered["payload"]
    assert payload["spec"]["rules"] == []
    assert payload["spec"]["defaults"] == {"mode": "observe", "defaultAction": "warn"}
    assert payload["metadata"]["revision"] == delivered["bundleVersion"] == 7
    assert ("globalLockdown" in payload[HOL_EXTENSION_CONTROLS_FIELD]) is lockdown
    assert fixture.requests == 1
    for key in ("policy_bundle", "policy_bundle_ack", "native_policy_bundle_ack_acceptance", "managed_controls_active"):
        assert fixture.store.get_sync_payload(key) is None
    assert not fixture.store.list_policy_decisions()


@pytest.mark.parametrize(
    ("authority_mode", "permission", "expected_reason"),
    [
        ("managed-restrictive", PERMISSION, "managed_restrictive_broadening"),
        ("workspace-shared", "command.guard-self-protection.permission.self-authorization", "immutable_floor"),
    ],
)
def test_signed_enable_attempt_passes_signature_and_fails_actual_parser(
    fixture: ManagedPolicyFixture, authority_mode: str, permission: str, expected_reason: str
) -> None:
    bundle = fixture.signed_managed_bundle(
        8,
        controls=[{"targetKind": "permission", "targetId": permission, "state": "enabled"}],
        authority_mode=authority_mode,
    )
    accepted, reason, _keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring=fixture.store.get_sync_payload("policy_bundle_keyring"),
        expected_workspace_id=WORKSPACE,
    )
    assert accepted is not None and reason is None
    validated, parsed, reason = _parse(fixture, bundle)
    assert validated is None and parsed is None and reason == expected_reason
    assert fixture.store.get_sync_payload("managed_controls_active") is None


def test_changes_after_signing_fail_actual_signature_validation(fixture: ManagedPolicyFixture) -> None:
    bundle = fixture.signed_managed_bundle(9, lockdown=True)
    payload = bundle["payload"]
    assert is_mapping(payload)
    controls = payload[HOL_EXTENSION_CONTROLS_FIELD]
    assert is_mapping(controls)
    controls.pop("globalLockdown")
    accepted, reason, _keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring=fixture.store.get_sync_payload("policy_bundle_keyring"),
        expected_workspace_id=WORKSPACE,
    )
    assert accepted is None and reason is not None


def test_managed_negotiation_requires_actual_runtime_session_delivery(
    fixture: ManagedPolicyFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ci.native_runtime.probe_installed_native_extensions import provision
    from codex_plugin_scanner.guard.runtime import runner

    for key in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(key, "true")
    monkeypatch.setenv("SSL_CERT_FILE", str(fixture.ca_file))
    provision(fixture.store)
    assert fixture.negotiated_capabilities == ()
    assert fixture.response_for_request("/api/guard/receipts/sync", {})["managedControlsCapabilities"] == []
    summary = runner.sync_runtime_session(
        fixture.store, session={"harness": "claude-code", "workspace": str(fixture.workspace)}
    )
    assert isinstance(summary["runtime_session_synced_at"], str)
    assert summary["extension_catalog_sync_status"] == "uploaded"
    assert fixture.catalog_uploads == 1
    assert fixture.catalog_digest == summary["extensionCatalogDigest"]
    capabilities = summary["managedControlsCapabilities"]
    assert isinstance(capabilities, list)
    assert frozenset(capabilities) == PARSER_CAPABILITIES | {"extension-catalog.v1"}
    assert frozenset(fixture.negotiated_capabilities) == PARSER_CAPABILITIES
    again = runner.sync_runtime_session(
        fixture.store, session={"harness": "claude-code", "workspace": str(fixture.workspace)}
    )
    assert again["extension_catalog_sync_status"] == "already_known"
    assert fixture.catalog_uploads == 1
    assert fixture.store.get_sync_payload("policy_bundle") is None
    assert fixture.store.get_sync_payload("native_policy_bundle_ack_acceptance") is None


def test_unprotected_runtime_cannot_negotiate_managed_authority(
    fixture: ManagedPolicyFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.runtime import runner

    for key in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(key, "true")
    monkeypatch.setenv("SSL_CERT_FILE", str(fixture.ca_file))
    runner.sync_runtime_session(fixture.store, session={"harness": "claude-code"})
    assert fixture.negotiated_capabilities == ()


def _enable_delivery(fixture: ManagedPolicyFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    from ci.native_runtime.probe_installed_native_extensions import provision

    for key in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
        "GUARD_CANONICAL_POLICY_BUNDLE_V2",
    ):
        monkeypatch.setenv(key, "true")
    monkeypatch.setenv("SSL_CERT_FILE", str(fixture.ca_file))
    provision(fixture.store)


def test_actual_tls_managed_delivery_binds_fresh_runtime_and_preserves_signature(
    fixture: ManagedPolicyFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real receiver application; no native publisher/ACK or installed claim."""
    from codex_plugin_scanner.guard.runtime import runner

    _enable_delivery(fixture, monkeypatch)
    deliveries: list[dict[str, object]] = []
    for version in (1, 2):
        summary = runner.sync_runtime_session(
            fixture.store, session={"harness": "claude-code", "workspace": str(fixture.workspace)}
        )
        fixture.bundle = fixture.signed_managed_bundle(
            version, controls=[{"targetKind": "permission", "targetId": PERMISSION, "state": "disabled"}]
        )
        delivered = fixture.response_for_request("/api/guard/receipts/sync", {})["policyBundleDelivery"]
        assert is_mapping(delivered)
        assert delivered["runtimeSessionId"] == summary["runtime_session_id"]
        assert delivered["deviceId"] == summary["runtime_device_id"]
        for field in ("extensionAuthorityRevision", "effectiveProjectionDigest", "catalogDigest"):
            assert delivered[field] == summary["extensionCatalogDigest" if field == "catalogDigest" else field]
        result = runner.sync_receipts(fixture.store)
        assert result["policy_validation_status"] == "accepted"
        assert result["policy_application_status"] == "applied"
        assert result.get("policy_rejection_reason") is None
        active = fixture.store.get_sync_payload("policy_bundle")
        assert active == fixture.bundle
        assert fixture.store.get_sync_payload("managed_controls_active") is not None
        assert fixture.store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
        deliveries.append(delivered)
    assert deliveries[0]["deliveryId"] != deliveries[1]["deliveryId"]
    assert deliveries[0]["effectiveProjectionDigest"] != deliveries[1]["effectiveProjectionDigest"]
    assert fixture.catalog_uploads == 1


@pytest.mark.parametrize(
    ("authority_mode", "permission", "expected_reason"),
    [
        ("managed-restrictive", PERMISSION, "managed_restrictive_broadening"),
        ("workspace-shared", "command.guard-self-protection.permission.self-authorization", "immutable_floor"),
    ],
)
def test_actual_tls_signed_enable_refusal_preserves_committed_authority(
    fixture: ManagedPolicyFixture,
    monkeypatch: pytest.MonkeyPatch,
    authority_mode: str,
    permission: str,
    expected_reason: str,
) -> None:
    """Real receiver and signatures; native acknowledgement remains unexercised."""
    import copy

    from codex_plugin_scanner.guard.runtime import runner

    _enable_delivery(fixture, monkeypatch)
    session: dict[str, object] = {"harness": "claude-code", "workspace": str(fixture.workspace)}
    _ = runner.sync_runtime_session(fixture.store, session=session)
    fixture.bundle = fixture.signed_managed_bundle(
        1, controls=[{"targetKind": "permission", "targetId": PERMISSION, "state": "disabled"}]
    )
    accepted = runner.sync_receipts(fixture.store)
    assert accepted["policy_validation_status"] == "accepted"
    assert accepted["policy_application_status"] == "applied"
    keys = ("policy_bundle", "policy_bundle_ack", "managed_controls_active", "native_policy_bundle_ack_acceptance")
    retained = {key: copy.deepcopy(fixture.store.get_sync_payload(key)) for key in keys}
    assert retained["policy_bundle"] is not None and retained["managed_controls_active"] is not None
    assert retained["native_policy_bundle_ack_acceptance"] is None

    _ = runner.sync_runtime_session(fixture.store, session=session)
    fixture.bundle = fixture.signed_managed_bundle(
        2,
        controls=[{"targetKind": "permission", "targetId": permission, "state": "enabled"}],
        authority_mode=authority_mode,
    )
    received_before = fixture.requests
    rejected = runner.sync_receipts(fixture.store)
    assert fixture.requests > received_before
    assert rejected["policy_validation_status"] == "rejected"
    assert rejected["policy_rejection_reason"] == expected_reason
    assert {key: fixture.store.get_sync_payload(key) for key in keys} == retained
    _ = runner.sync_runtime_session(fixture.store, session=session)
    fixture.bundle = fixture.signed_managed_bundle(
        2, controls=[{"targetKind": "permission", "targetId": PERMISSION, "state": "disabled"}]
    )
    fresh = runner.sync_receipts(fixture.store)
    assert fresh["policy_validation_status"] == "accepted"
    assert fresh["policy_application_status"] == "applied"
    assert fixture.store.get_sync_payload("policy_bundle") == fixture.bundle
    assert fixture.store.get_sync_payload("native_policy_bundle_ack_acceptance") is None


@pytest.mark.parametrize(
    "field",
    [
        None,
        "runtimeSessionId",
        "deviceId",
        "catalogDigest",
        "extensionAuthorityRevision",
        "effectiveProjectionDigest",
        "extensionProjectionDigest",
    ],
)
def test_actual_tls_receiver_refuses_missing_or_mismatched_managed_delivery(
    fixture: ManagedPolicyFixture, monkeypatch: pytest.MonkeyPatch, field: str | None
) -> None:
    from codex_plugin_scanner.guard.runtime import runner

    _enable_delivery(fixture, monkeypatch)
    runner.sync_runtime_session(fixture.store, session={"harness": "claude-code"})
    fixture.bundle = fixture.signed_managed_bundle(
        1, controls=[{"targetKind": "permission", "targetId": PERMISSION, "state": "disabled"}]
    )
    original = fixture.response_for_request

    def altered_response(path: str, request: dict[str, object]) -> dict[str, object]:
        response = original(path, request)
        if path == "/api/guard/receipts/sync":
            delivery = response.pop("policyBundleDelivery")
            if field is not None:
                assert is_mapping(delivery)
                value = delivery[field]
                if field == "extensionAuthorityRevision":
                    assert isinstance(value, int)
                    delivery[field] = value + 1
                elif field in {"catalogDigest", "effectiveProjectionDigest", "extensionProjectionDigest"}:
                    assert isinstance(value, str)
                    delivery[field] = value[:-1] + ("0" if value[-1] != "0" else "1")
                else:
                    delivery[field] = "different-session-or-device"
                response["policyBundleDelivery"] = delivery
        return response

    monkeypatch.setattr(fixture, "response_for_request", altered_response)
    result = runner.sync_receipts(fixture.store)
    assert result["policy_validation_status"] == "rejected"
    assert result["policy_rejection_reason"] == (
        "missing_policy_bundle_delivery" if field is None else "policy_bundle_delivery_mismatch"
    )
    assert fixture.store.get_sync_payload("policy_bundle") is None
    assert fixture.store.get_sync_payload("managed_controls_active") is None
    assert fixture.store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
