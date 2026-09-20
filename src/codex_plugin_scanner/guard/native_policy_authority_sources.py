"""Frozen signed source inputs for off-hook native policy compilation.

The caller captures database values and protected key material consistently.
Reconstruction uses the signed sources, never the presence of cached rows.
These values do not establish resident application or native support.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import cast

from .managed_controls_policy_bundle import MANAGED_CONTROLS_ACTIVE_STATE_KEY
from .models import PolicyDecision
from .native_cloud_policy_capabilities import NativeCloudPolicyRequirement, native_cloud_policy_requirements
from .native_policy_authority_blocked import FrozenNativeBlockedCommandAuthority
from .native_policy_authority_command_source import has_canonical_command_expressions, signed_command_native_rows
from .native_policy_authority_managed import FrozenNativeManagedAuthority
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .policy_bundle_decisions import build_policy_bundle_decisions
from .policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY, verified_policy_materialization_time
from .policy_memory_row_authority import current_review_memory_row_identities
from .policy_rule_identity import canonical_rule_identity
from .review_memory_authority import REGISTRY_KEY, VERSION_KEY, bound_registry, memory_oauth_authority, registry_entries
from .runtime.canonical_policy_decisions import build_canonical_policy_bundle_decisions
from .runtime.time_support import parse_utc_timestamp
from .store_base import _canonical_utc_timestamp
from .synced_policy import cached_policy_bundle_validation, policy_defaults_from_validated_bundle

PolicyKeys = tuple[str | None, str | None, str | None, str | None]


@dataclass(frozen=True, slots=True, repr=False)
class FrozenNativePolicySources:
    payloads: Mapping[str, dict[str, object] | list[object] | None]
    device: Mapping[str, str]
    workspace_id: str | None
    credentials: dict[str, object] | None
    key_material: tuple[bytes | None, str | None]
    normalize_keys: Callable[[PolicyDecision], PolicyKeys]
    _guard_source: str

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None:
        return self.payloads.get(state_key)

    def get_cloud_workspace_id(self) -> str | None:
        return self.workspace_id

    def get_device_metadata(self) -> Mapping[str, str]:
        return self.device

    def get_or_create_installation_id(self) -> str:
        # The device already exists in the captured transaction. This
        # compatibility method performs no creation or additional read.
        return self.device["installation_id"]

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object] | None:
        if allow_primary:
            raise NativePolicySnapshotError("native_policy_authority_secondary_read_forbidden")
        return self.credentials

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        if create:
            raise NativePolicySnapshotError("native_policy_authority_mutation_forbidden")
        return self.key_material

    def _normalized_policy_keys(self, decision: PolicyDecision) -> PolicyKeys:
        return self.normalize_keys(decision)


def _identity_row(identity: tuple[object, ...]) -> dict[str, object]:
    fields = (
        "harness",
        "scope",
        "artifact_id",
        "artifact_hash",
        "workspace",
        "publisher",
        "exact_command_sha256",
        "action",
        "reason",
        "owner",
        "source",
        "expires_at",
        "updated_at",
    )
    return dict(zip(fields, identity, strict=True))


def signed_bundle_native_rows(
    state: FrozenNativePolicySources,
    *,
    now: float,
    managed: FrozenNativeManagedAuthority | FrozenNativeBlockedCommandAuthority | None = None,
) -> tuple[list[dict[str, object]], dict[str, object] | None, dict[str, object] | None]:
    """Rebuild the complete targeted generic authority after signature checks."""
    bundle, reason = cached_policy_bundle_validation(state, state.get_sync_payload("policy_bundle"), now=now)
    if reason is not None:
        raise NativePolicySnapshotError("native_policy_authority_bundle_unavailable")
    active_managed = state.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) is not None
    if bundle is None:
        if active_managed:
            raise NativePolicySnapshotError("native_policy_authority_managed_unavailable")
        return [], None, None
    requirements = native_cloud_policy_requirements(bundle)
    if requirements - {NativeCloudPolicyRequirement.SCOPED_RULES, NativeCloudPolicyRequirement.MANAGED_CONTROLS}:
        raise NativePolicySnapshotError("native_policy_authority_bundle_semantics_unsupported")
    if active_managed or NativeCloudPolicyRequirement.MANAGED_CONTROLS in requirements:
        if managed is None:
            raise NativePolicySnapshotError("native_policy_authority_bundle_semantics_unsupported")
        managed.require_signed_bundle(bundle, state.payloads)
    builder = (
        build_canonical_policy_bundle_decisions
        if bundle.get("contractVersion") == "guard-policy-bundle.v2"
        else build_policy_bundle_decisions
    )
    materialized_at = verified_policy_materialization_time(
        state.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY),
        bundle=bundle,
        device_id=state.device["installation_id"],
        key=state.key_material[0],
        key_id=state.key_material[1],
    )
    decisions = (
        []
        if has_canonical_command_expressions(bundle)
        else builder(
            bundle,
            device_id=state.device["installation_id"],
            device_name=state.device["device_label"],
        )
    )
    if decisions and materialized_at is None:
        raise NativePolicySnapshotError("native_policy_authority_materialization_unavailable")
    rows: list[dict[str, object]] = []
    for decision in decisions:
        artifact, digest, workspace, publisher = state.normalize_keys(decision)
        row = _identity_row(
            (
                decision.harness,
                decision.scope,
                artifact,
                digest,
                workspace,
                publisher,
                decision.exact_command_sha256,
                decision.action,
                decision.reason,
                decision.owner,
                decision.source,
                _canonical_utc_timestamp(decision.expires_at) if decision.expires_at is not None else None,
                materialized_at,
            )
        )
        identity = canonical_rule_identity(bundle, decision.owner, installation_id=state.device["installation_id"])
        if identity is not None:
            row["_policy_rule_identity"] = identity.to_selected_row_dict()
        rows.append(row)
    if has_canonical_command_expressions(bundle):
        rows = signed_command_native_rows(state, bundle, materialized_at=materialized_at)
    return (
        rows,
        policy_defaults_from_validated_bundle(bundle),
        {
            "kind": "signed-bundle",
            "revision": bundle["bundleVersion"],
            "digest": bundle["bundleHash"],
            "workspace_id": state.workspace_id,
            "device_id": state.device["installation_id"],
            "expires_at": bundle.get("expiresAt"),
            "materialized_at": materialized_at,
        },
    )


def signed_memory_native_rows(
    state: FrozenNativePolicySources,
    *,
    now: str,
) -> tuple[list[dict[str, object]], dict[str, object] | None]:
    """Reconstruct memory from one signed registry and its active binding."""
    saved = state.get_sync_payload(REGISTRY_KEY)
    version = state.get_sync_payload(VERSION_KEY)
    if saved is None and version is None:
        return [], None
    oauth, binding = memory_oauth_authority(state)
    registry = bound_registry(saved, binding, store=state)
    if registry is None or not isinstance(version, dict):
        raise NativePolicySnapshotError("native_policy_authority_memory_unavailable")
    if any(registry.get(key) != version.get(key) for key in ("policyVersion", "bundleHash")):
        raise NativePolicySnapshotError("native_policy_authority_memory_unavailable")
    selections = registry.get("rules")
    entries = registry_entries(registry, store=state, oauth=oauth, binding=binding, now=now)
    if not isinstance(selections, dict) or any(
        rule_id not in entries and not _memory_selection_expired(registry, rule_id, digest, now=now)
        for rule_id, digest in selections.items()
    ):
        # The authenticated expiry can remove a selected rule. A missing
        # signature, binding, or live rule cannot be projected away.
        raise NativePolicySnapshotError("native_policy_authority_memory_unavailable")
    rows = [_identity_row(identity) for identity in current_review_memory_row_identities(state, now=now)]
    if entries and not rows:
        raise NativePolicySnapshotError("native_policy_authority_memory_unavailable")
    integrity = cast(dict[str, object], registry["integrity"])
    return rows, {
        "kind": "signed-memory",
        "revision": registry["policyVersion"],
        "digest": registry["bundleHash"],
        "registry_digest": integrity["payload_hash"],
        "materialized_at": integrity["signed_at"],
        "workspace_id": oauth.workspace_id,
        "device_id": oauth.installation_id,
    }


def _memory_selection_expired(registry: Mapping[str, object], rule_id: object, digest: object, *, now: str) -> bool:
    """Use only expiry fields already authenticated by the registry MAC."""
    bundles = registry.get("bundles")
    if not isinstance(bundles, dict) or not isinstance(digest, str) or not isinstance(rule_id, str):
        return False
    bundle = cast(dict[str, object], bundles).get(digest)
    if not isinstance(bundle, dict):
        return False
    payload = cast(dict[str, object], bundle)
    bundle_expiry = parse_utc_timestamp(payload.get("expiresAt"))
    current = parse_utc_timestamp(now)
    rules = payload.get("memoryRules")
    if bundle_expiry is None or current is None or not isinstance(rules, list):
        return False
    selected = [
        cast(dict[str, object], rule)
        for rule in cast(list[object], rules)
        if isinstance(rule, dict) and cast(dict[str, object], rule).get("ruleId") == rule_id
    ]
    if len(selected) != 1:
        return False
    expiry_value = selected[0].get("expiresAt")
    rule_expiry = parse_utc_timestamp(expiry_value)
    if expiry_value is not None and rule_expiry is None:
        return False
    expiry = min(bundle_expiry, rule_expiry) if rule_expiry is not None else bundle_expiry
    return expiry <= current


__all__ = ["FrozenNativePolicySources", "signed_bundle_native_rows", "signed_memory_native_rows"]
