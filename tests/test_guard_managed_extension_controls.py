from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ExtensionControlLayer,
    ResolverFailureCode,
)
from codex_plugin_scanner.guard.runtime.managed_extension_controls import (
    ManagedPolicyStatus,
    SignedCloudControlPolicy,
    managed_control_audit_payload,
    resolve_signed_cloud_controls,
)

_NOW = datetime(2026, 7, 21, 12, tzinfo=timezone.utc)


class _Resolver:
    def __init__(self, policy: SignedCloudControlPolicy | None = None, *, fails: bool = False) -> None:
        self.policy = policy
        self.fails = fails

    def resolve(self) -> SignedCloudControlPolicy | None:
        if self.fails:
            raise OSError("cloud unavailable")
        return self.policy


def _layer(*, lockdown: bool = False, digest: str | None = None) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.SIGNED_CLOUD,
        catalog_digest=digest or BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=lockdown,
        controls=(),
    )


def _policy(
    *,
    policy_id: str = "managed-policy-1",
    revision: int = 7,
    status: ManagedPolicyStatus = ManagedPolicyStatus.ACTIVE,
    issued_at: datetime = _NOW - timedelta(hours=1),
    valid_until: datetime = _NOW + timedelta(hours=1),
    layer: ExtensionControlLayer | None = None,
) -> SignedCloudControlPolicy:
    return SignedCloudControlPolicy(
        policy_id=policy_id,
        revision=revision,
        issued_at=issued_at,
        valid_until=valid_until,
        signer_key_id="fleet-signing-key-1",
        status=status,
        layer=layer or _layer(),
    )


def test_valid_signed_cloud_policy_preserves_provenance() -> None:
    policy = _policy()

    result = resolve_signed_cloud_controls(_Resolver(policy), BUILT_IN_COMMAND_EXTENSION_REGISTRY, now=_NOW)

    assert result.policy is policy
    assert result.layer.kind is ControlLayerKind.SIGNED_CLOUD
    assert result.failures == ()
    assert result.using_last_known_good is False


@pytest.mark.parametrize(
    ("policy", "failure"),
    [
        (_policy(status=ManagedPolicyStatus.REVOKED), ResolverFailureCode.MANAGED_POLICY_REVOKED),
        (
            _policy(issued_at=_NOW + timedelta(seconds=1), valid_until=_NOW + timedelta(hours=1)),
            ResolverFailureCode.MANAGED_POLICY_NOT_YET_VALID,
        ),
        (_policy(valid_until=_NOW), ResolverFailureCode.MANAGED_POLICY_EXPIRED),
        (_policy(layer=_layer(digest="0" * 64)), ResolverFailureCode.CATALOG_DIGEST_MISMATCH),
    ],
)
def test_invalid_managed_policy_fails_safe(
    policy: SignedCloudControlPolicy,
    failure: ResolverFailureCode,
) -> None:
    result = resolve_signed_cloud_controls(_Resolver(policy), BUILT_IN_COMMAND_EXTENSION_REGISTRY, now=_NOW)

    assert result.layer.global_lockdown is True
    assert result.policy is None
    assert result.failures[0].code is failure


def test_unavailable_resolver_retains_valid_last_known_good_floor() -> None:
    cached = _policy(layer=_layer(lockdown=True))

    result = resolve_signed_cloud_controls(
        _Resolver(fails=True),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        now=_NOW,
        last_known_good=cached,
    )

    assert result.layer is cached.layer
    assert result.policy is cached
    assert result.using_last_known_good is True
    assert result.failures[0].code is ResolverFailureCode.MANAGED_POLICY_UNAVAILABLE


def test_policy_status_must_be_exact_enum() -> None:
    with pytest.raises(ValueError, match="exact ManagedPolicyStatus"):
        _policy(status=cast(ManagedPolicyStatus, "revoked"))


def test_older_candidate_cannot_replace_last_known_good_revision_floor() -> None:
    cached = _policy(revision=7, layer=_layer(lockdown=True))
    candidate = _policy(revision=6)

    result = resolve_signed_cloud_controls(
        _Resolver(candidate),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        now=_NOW,
        last_known_good=cached,
    )

    assert result.policy is cached
    assert result.layer.global_lockdown is True
    assert result.using_last_known_good is True
    assert result.failures[0].code is ResolverFailureCode.MANAGED_POLICY_ROLLBACK


def test_revoked_policy_cannot_restore_same_policy_from_cache() -> None:
    cached = _policy(status=ManagedPolicyStatus.ACTIVE)
    revoked = _policy(status=ManagedPolicyStatus.REVOKED, revision=8)

    result = resolve_signed_cloud_controls(
        _Resolver(revoked),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        now=_NOW,
        last_known_good=cached,
    )

    assert result.policy is None
    assert result.layer.global_lockdown is True
    assert result.using_last_known_good is False
    assert result.failures[0].code is ResolverFailureCode.MANAGED_POLICY_REVOKED


def test_managed_audit_payload_excludes_actor_proof_and_command_data() -> None:
    result = resolve_signed_cloud_controls(_Resolver(_policy()), BUILT_IN_COMMAND_EXTENSION_REGISTRY, now=_NOW)

    payload = managed_control_audit_payload(result, blocked=True, block_source="resolver")
    serialized = repr(payload)

    assert payload["policy_revision"] == 7
    assert payload["block_source"] == "resolver"
    assert "actor" not in serialized
    assert "proof" not in serialized
    assert "command" not in serialized


def test_managed_policy_envelope_rejects_local_layer() -> None:
    local = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(),
    )

    with pytest.raises(ValueError, match="signed-cloud"):
        _policy(layer=local)
