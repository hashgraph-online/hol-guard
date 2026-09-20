"""Real signature, persistent-cache and sync boundaries during signer rotation.

Signature verification and persistent activation use production paths. HTTP
and optional telemetry are isolated. This is not an installed-runtime or
native-hook acceptance matrix.
"""

from __future__ import annotations

import base64
import copy
import urllib.error
from dataclasses import replace
from email.message import Message
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    signed_cloud_extension_projection_digest,
)
from codex_plugin_scanner.guard.policy_bundle_parser import (
    canonical_policy_bundle_payload,
    computed_policy_bundle_hash,
    payload_hash_for_policy_bundle,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    policy_bundle_keyring_payload,
    validate_synced_policy_bundle,
)
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
    validated_policy_bundle_v2_payload,
)
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import MANAGED_CONTROLS_RUNTIME_CAPABILITIES
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import cached_policy_bundle_validation
from tests.managed_controls_activation_support import parse_managed_bundle
from tests.support.native_policy_application import native_policy_consumer as native_policy_consumer
from tests.support.network import stub_authenticated_urlopen
from tests.test_policy_bundle_activation_atomicity import _signed_bundle as _v1_template
from tests.test_policy_bundle_delivery_daemon import _enable, _fixture
from tests.test_policy_bundle_delivery_runtime import _Response
from tests.test_policy_bundle_v2 import _signed_bundle as _v2_template
from tests.test_policy_bundle_v2 import _verification_key
from tests.test_policy_bundle_v2_runtime_admission import _generic_v2_payload

_WORKSPACE = "workspace-alpha"
_TIME = "2026-09-01T12:00:00Z"
_AUTH: dict[str, object] = {
    "sync_url": "https://hol.org/api/guard/receipts/sync",
    "access_token": "disposable-test-token",
    "dpop_key_material": None,
}

pytestmark = pytest.mark.usefixtures("native_policy_consumer")


def _signer(key_id: str) -> tuple[rsa.RSAPrivateKey, PolicyBundleVerificationKey]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private, key_id=key_id, workspace_id=_WORKSPACE)
    return private, replace(key, valid_from="2026-01-01T00:00:00Z", valid_until="2030-01-01T00:00:00Z")


def _record(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _integer(value: object) -> int:
    assert type(value) is int
    return value


def _sign(
    bundle: dict[str, object],
    signer: tuple[rsa.RSAPrivateKey, PolicyBundleVerificationKey],
) -> dict[str, object]:
    private, key = signer
    bundle = copy.deepcopy(bundle)
    bundle["workspaceId"] = _WORKSPACE
    is_v2 = bundle["contractVersion"] == "guard-policy-bundle.v2"
    verifier = {
        "algorithm": "rsa-pss-sha256",
        "keyId": key.key_id,
        ("keyFingerprint" if is_v2 else "fingerprintSha256"): key.fingerprint_sha256,
        "signature": "",
    }
    bundle["verifier"] = verifier
    if is_v2:
        bundle["payloadHash"] = payload_hash_for_policy_bundle_v2(bundle)
    bundle["bundleHash"] = (computed_policy_bundle_v2_hash if is_v2 else computed_policy_bundle_hash)(bundle)
    if not is_v2:
        bundle["payloadHash"] = payload_hash_for_policy_bundle(bundle)
    canonical = (canonical_policy_bundle_v2_payload if is_v2 else canonical_policy_bundle_payload)(bundle)
    signature = private.sign(
        canonical,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH if is_v2 else padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )
    verifier["signature"] = base64.b64encode(signature).decode("ascii")
    return bundle


def _anchors(store: GuardStore, *keys: PolicyBundleVerificationKey) -> None:
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_keyring_payload(keys, workspace_id=_WORKSPACE), _TIME)


def _sync(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    bundle: dict[str, object],
    **extra: object,
) -> dict[str, object]:
    payload = {"syncedAt": _TIME, "receiptsStored": 0, "policyBundle": bundle, **extra}
    stub_authenticated_urlopen(monkeypatch, lambda request, timeout: _Response(payload))
    return runner.sync_receipts(store, auth_context=_AUTH)


def _assert_cached(store: GuardStore, bundle: dict[str, object]) -> None:
    # Reopen the actual persistent store and re-run crypto and workspace checks.
    reopened = GuardStore(store.guard_home)
    assert reopened.get_sync_payload("policy_bundle") == bundle
    assert reopened.get_sync_payload("policy_bundle_last_good") == bundle
    assert cached_policy_bundle_validation(reopened, bundle) == (bundle, None)


def _outage(store: GuardStore, monkeypatch: pytest.MonkeyPatch, bundle: dict[str, object]) -> None:
    before = store.get_sync_payload("policy_bundle_ack")
    headers = Message()
    headers["Retry-After"] = "1"
    for failure in (
        urllib.error.HTTPError(str(_AUTH["sync_url"]), 503, "unavailable", headers, None),
        urllib.error.URLError("disposable transport unavailable"),
    ):
        calls: list[object] = []

        def unavailable(
            request: object, timeout: object, error: Exception = failure, attempts: list[object] = calls
        ) -> None:
            attempts.append(request)
            raise error

        stub_authenticated_urlopen(monkeypatch, unavailable)
        with pytest.raises(RuntimeError):
            runner.sync_receipts(store, auth_context=_AUTH)
        assert len(calls) == (3 if isinstance(failure, urllib.error.HTTPError) else 1)
        _assert_cached(store, bundle)
        assert store.get_sync_payload("policy_bundle_ack") == before


@pytest.fixture
def rotation_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GuardStore:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "true")
    monkeypatch.setattr(runner, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(runner, "sync_guard_events", lambda _store, auth_context=None: 0)
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": _WORKSPACE}, _TIME)
    return store


@pytest.mark.parametrize("version", [1, 2])
def test_rotation_rejects_unverifiable_candidates_and_retains_enforcement(
    rotation_store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    version: int,
) -> None:
    store = rotation_store
    old, new = _signer("old-key"), _signer("new-key")
    assert old[1].fingerprint_sha256 != new[1].fingerprint_sha256
    if version == 1:
        initial = _v1_template(rollout_state="enforcing", bundle_version="policy-2026-09-01.1")
        rules = initial["rules"]
        assert isinstance(rules, list)
        _record(rules[0])["action"] = "block"
        _record(initial["policyDefaults"])["defaultAction"] = "block"
    else:
        initial = _v2_template(
            *old,
            bundle_version=1,
            payload_base=_generic_v2_payload(
                rule_id="rotation-block",
                artifact_id="command:rotation-sentinel",
            ),
        )
    first = _sign(initial, old)
    _anchors(store, old[1])
    accepted = _sync(store, monkeypatch, first)
    assert accepted["policy_application_status"] == "applied", store.get_sync_payload("policy_bundle_last_error")
    _assert_cached(store, first)

    def enforced() -> list[dict[str, object]]:
        return [
            {key: value for key, value in row.items() if key != "decision_id"} for row in store.list_policy_decisions()
        ]

    enforced_rows = enforced()
    assert any(row["action"] == "block" for row in enforced_rows)

    next_bundle = copy.deepcopy(first)
    next_bundle["bundleVersion"] = "policy-2026-09-01.2" if version == 1 else 2
    second = _sign(next_bundle, new)
    # A response can advertise the missing key but cannot turn it into an anchor.
    rejected = _sync(store, monkeypatch, second, policyBundleVerificationKeys=[new[1].to_dict()])
    assert rejected["policy_validation_status"] == "rejected"
    _assert_cached(store, first)
    assert enforced() == enforced_rows
    assert _record(store.get_sync_payload("policy_bundle_last_error"))["reason"] == "untrusted_signing_key"

    overlap_old = replace(old[1], state="grace") if version == 2 else old[1]
    expired = replace(new[1], valid_until="2026-02-01T00:00:00Z")
    _anchors(store, overlap_old, expired)
    rejected = _sync(store, monkeypatch, second)
    assert rejected["policy_validation_status"] == "rejected"
    _assert_cached(store, first)
    assert enforced() == enforced_rows
    _outage(store, monkeypatch, first)

    # Provisioned overlap is real trust; an advertised-only replacement was not.
    _anchors(store, overlap_old, new[1])
    accepted = _sync(store, monkeypatch, second)
    assert accepted["policy_application_status"] == "applied", store.get_sync_payload("policy_bundle_last_error")
    _assert_cached(store, second)
    assert any(row["action"] == "block" for row in store.list_policy_decisions())
    _anchors(store, new[1])
    _outage(store, monkeypatch, second)
    assert _record(store.get_sync_payload("policy_bundle_ack"))["bundleHash"] == second["bundleHash"]


def test_managed_rotation_retains_mandatory_controls_and_never_claims_downgrade(
    rotation_store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = rotation_store
    _enable(monkeypatch)
    template, initial_delivery = _fixture(store)
    template["rollback"] = None
    old, new = _signer("managed-old"), _signer("managed-new")
    _anchors(store, old[1])
    first = _sign(template, old)

    def deliver(bundle: dict[str, object], **extra: object) -> dict[str, object]:
        authority = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
        digest = "sha256:" + ExtensionControlRuntimeSnapshot.from_authority_view(authority).effective_digest
        summary = _record(store.get_sync_payload("runtime_session_summary"))
        summary.update(extensionAuthorityRevision=authority.revision, effectiveProjectionDigest=digest)
        store.set_sync_payload("runtime_session_summary", summary, _TIME)
        delivery = {
            **initial_delivery,
            "workspaceId": _WORKSPACE,
            "bundleVersion": bundle["bundleVersion"],
            "bundleHash": bundle["bundleHash"],
            "payloadHash": bundle["payloadHash"],
            "lastKnownGoodBundleHash": None,
            "extensionAuthorityRevision": authority.revision,
            "effectiveProjectionDigest": digest,
            "deliveryId": f"00000000-0000-4000-8000-{_integer(bundle['bundleVersion']):012d}",
            "extensionProjectionDigest": signed_cloud_extension_projection_digest(
                parse_managed_bundle(bundle),
                catalog_digest=str(initial_delivery["catalogDigest"]),
            ),
        }
        return _sync(
            store,
            monkeypatch,
            bundle,
            policyBundleDelivery=delivery,
            managedControlsCapabilities=sorted(MANAGED_CONTROLS_RUNTIME_CAPABILITIES),
            **extra,
        )

    def mandatory() -> dict[str, object]:
        authority = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
        signed = next(layer for layer in authority.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
        assert signed.controls[0].state is ControlState.DISABLED
        active = _record(store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY))
        assert active["complete"] is True
        return active

    assert deliver(first)["policy_application_status"] == "applied", store.get_sync_payload("policy_bundle_last_error")
    before = mandatory()
    _assert_cached(store, first)
    second = copy.deepcopy(first)
    second["bundleVersion"] = _integer(first["bundleVersion"]) + 1
    second = _sign(second, new)
    for keys in ((old[1],), (replace(old[1], state="grace"), replace(new[1], valid_until="2026-02-01T00:00:00Z"))):
        _anchors(store, *keys)
        rejected = deliver(second, policyBundleVerificationKeys=[new[1].to_dict()])
        assert rejected["policy_validation_status"] == "rejected"
        _assert_cached(store, first)
        assert mandatory() == before
    _outage(store, monkeypatch, first)
    assert mandatory() == before
    _anchors(store, replace(old[1], state="grace"), new[1])
    assert deliver(second)["policy_application_status"] == "applied"
    _assert_cached(store, second)
    after = mandatory()
    assert _record(after["provenance"])["bundleHash"] == second["bundleHash"]
    ack = _record(store.get_sync_payload("policy_bundle_ack"))
    assert ack["status"] == "applied"
    assert ack["bundleHash"] == second["bundleHash"]
    assert _integer(ack["appliedExtensionAuthorityRevision"]) > 0
    _anchors(store, new[1])
    _outage(store, monkeypatch, second)
    assert mandatory() == after


@pytest.mark.parametrize(
    "invalid_anchor",
    [
        {"state": "revoked"},
        {"valid_until": "2026-02-01T00:00:00Z"},
        {"valid_from": "2029-01-01T00:00:00Z"},
    ],
)
def test_v2_advertisement_cannot_reactivate_or_extend_pinned_authority(invalid_anchor: dict[str, str]) -> None:
    signer = _signer("bounded-authority")
    bundle = _sign(_v2_template(*signer), signer)
    anchor = replace(signer[1], **invalid_anchor)
    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(signer[1],),
        anchored_verification_keys=(anchor,),
        now=1788264000.0,
    )
    assert validated is None
    assert reason == "untrusted_signing_key"


@pytest.mark.parametrize("scope", ["purpose", "workspace"])
def test_v2_runtime_refuses_key_authority_from_another_signing_scope(
    rotation_store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
) -> None:
    store = rotation_store
    old, new = _signer("valid-policy-key"), _signer("other-signing-scope")
    first = _sign(
        _v2_template(
            *old,
            bundle_version=1,
            payload_base=_generic_v2_payload(
                rule_id="retained-block",
                artifact_id="command:rotation-sentinel",
            ),
        ),
        old,
    )
    _anchors(store, old[1])
    assert _sync(store, monkeypatch, first)["policy_application_status"] == "applied"
    bad_key = replace(
        new[1],
        **(
            {"purpose": "supply_chain"}
            if scope == "purpose"
            else {
                "workspace_id": "workspace-other",
            }
        ),
    )
    candidate = _sign({**first, "bundleVersion": 2}, (new[0], bad_key))
    # Legacy bare keyrings still reach the production loader. A key's explicit
    # scope must be enforced even without the modern wrapper's consistency check.
    keyring = {"keys": [old[1].to_dict(), bad_key.to_dict()]}
    store.set_sync_payload("policy_bundle_keyring", keyring, _TIME)
    validated, reason, _ = validate_synced_policy_bundle(
        candidate,
        stored_keyring=keyring,
        expected_workspace_id=_WORKSPACE,
    )
    assert validated is None
    assert reason == "untrusted_signing_key"
    summary = _sync(store, monkeypatch, candidate)
    assert summary["policy_validation_status"] == "rejected"
    _assert_cached(store, first)
    assert any(row["action"] == "block" for row in store.list_policy_decisions())
