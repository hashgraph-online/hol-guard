"""Strict signed-cloud extension-control policy resolution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol, runtime_checkable

from .command_extensions import CommandSafetyExtensionRegistry
from .extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlResolverFailure,
    ExtensionControlLayer,
    ResolverFailureCode,
)


class ManagedPolicyStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class SignedCloudControlPolicy:
    """Verified policy envelope returned by a platform trust boundary."""

    policy_id: str
    revision: int
    issued_at: datetime
    valid_until: datetime
    signer_key_id: str
    status: ManagedPolicyStatus
    layer: ExtensionControlLayer

    def __post_init__(self) -> None:
        if not self.policy_id or len(self.policy_id) > 128:
            raise ValueError("policy_id must be non-empty and bounded")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("revision must be a positive integer")
        if not self.signer_key_id or len(self.signer_key_id) > 128:
            raise ValueError("signer_key_id must be non-empty and bounded")
        if type(self.status) is not ManagedPolicyStatus:
            raise ValueError("status must be an exact ManagedPolicyStatus")
        if self.issued_at.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("managed policy timestamps must be timezone-aware")
        if self.valid_until <= self.issued_at:
            raise ValueError("managed policy validity window must be ordered")
        if self.layer.kind is not ControlLayerKind.SIGNED_CLOUD:
            raise ValueError("managed policy layer must be signed-cloud")
        if self.layer.schema_version != CONTROL_SCHEMA_VERSION:
            raise ValueError("managed policy control schema is unsupported")


@runtime_checkable
class SignedCloudControlResolver(Protocol):
    """Trust-boundary seam; implementations return only signature-verified policy."""

    def resolve(self) -> SignedCloudControlPolicy | None: ...


@dataclass(frozen=True, slots=True)
class ManagedControlResolution:
    layer: ExtensionControlLayer
    policy: SignedCloudControlPolicy | None
    failures: tuple[ControlResolverFailure, ...]
    using_last_known_good: bool


def resolve_signed_cloud_controls(
    resolver: SignedCloudControlResolver,
    registry: CommandSafetyExtensionRegistry,
    *,
    now: datetime | None = None,
    last_known_good: SignedCloudControlPolicy | None = None,
) -> ManagedControlResolution:
    """Resolve a restrictive managed layer, retaining a valid last-known-good floor."""

    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    failure: ResolverFailureCode | None = None
    try:
        candidate = resolver.resolve()
    except Exception:
        candidate = None
        failure = ResolverFailureCode.MANAGED_POLICY_UNAVAILABLE

    if candidate is not None:
        failure = _policy_failure(candidate, registry, current_time)
        if failure is None:
            if (
                last_known_good is not None
                and candidate.policy_id == last_known_good.policy_id
                and candidate.revision < last_known_good.revision
                and _policy_failure(last_known_good, registry, current_time) is None
            ):
                return ManagedControlResolution(
                    last_known_good.layer,
                    last_known_good,
                    (
                        ControlResolverFailure(
                            ResolverFailureCode.MANAGED_POLICY_ROLLBACK,
                            ControlLayerKind.SIGNED_CLOUD,
                        ),
                    ),
                    True,
                )
            return ManagedControlResolution(candidate.layer, candidate, (), False)
    elif failure is None:
        failure = ResolverFailureCode.MANAGED_POLICY_UNAVAILABLE

    revoked_cached_policy = (
        candidate is not None
        and failure is ResolverFailureCode.MANAGED_POLICY_REVOKED
        and last_known_good is not None
        and candidate.policy_id == last_known_good.policy_id
    )
    if revoked_cached_policy:
        last_known_good = None
    if last_known_good is not None and _policy_failure(last_known_good, registry, current_time) is None:
        return ManagedControlResolution(
            last_known_good.layer,
            last_known_good,
            (ControlResolverFailure(failure, ControlLayerKind.SIGNED_CLOUD),),
            True,
        )
    return ManagedControlResolution(
        _fail_safe_layer(registry.catalog_digest),
        None,
        (ControlResolverFailure(failure, ControlLayerKind.SIGNED_CLOUD),),
        False,
    )


def managed_control_audit_payload(
    resolution: ManagedControlResolution,
    *,
    blocked: bool,
    block_source: str | None,
) -> dict[str, object]:
    """Return bounded, privacy-safe managed-control audit metadata."""

    policy = resolution.policy
    return {
        "schema": "guard.extension-control-managed-audit.v1",
        "policy_id": policy.policy_id if policy is not None else None,
        "policy_revision": policy.revision if policy is not None else None,
        "layer_kind": ControlLayerKind.SIGNED_CLOUD.value,
        "global_lockdown": resolution.layer.global_lockdown,
        "disabled_control_count": sum(control.state.value == "disabled" for control in resolution.layer.controls),
        "using_last_known_good": resolution.using_last_known_good,
        "failure_codes": [failure.code.value for failure in resolution.failures],
        "blocked": blocked,
        "block_source": block_source
        if block_source in {"global-lockdown", "extension", "permission", "resolver"}
        else None,
    }


def _policy_failure(
    policy: SignedCloudControlPolicy,
    registry: CommandSafetyExtensionRegistry,
    now: datetime,
) -> ResolverFailureCode | None:
    if policy.status is ManagedPolicyStatus.REVOKED:
        return ResolverFailureCode.MANAGED_POLICY_REVOKED
    if policy.issued_at.astimezone(timezone.utc) > now:
        return ResolverFailureCode.MANAGED_POLICY_NOT_YET_VALID
    if policy.valid_until.astimezone(timezone.utc) <= now:
        return ResolverFailureCode.MANAGED_POLICY_EXPIRED
    if policy.layer.catalog_digest != registry.catalog_digest:
        return ResolverFailureCode.CATALOG_DIGEST_MISMATCH
    return None


def _fail_safe_layer(catalog_digest: str) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.SIGNED_CLOUD,
        catalog_digest=catalog_digest,
        global_lockdown=True,
        controls=(),
    )
