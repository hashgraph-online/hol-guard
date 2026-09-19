"""Reconstruct complete literal-expression rules from an authenticated source.

This off-hook adapter never writes selector-only rows to the generic policy
cache. Its caller authenticates the original bundle and local materialization.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .native_command_row_association import materialize_native_command_source_rows
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .policy_command_projection import project_canonical_command_policy
from .policy_document import GuardPolicyDocument
from .policy_publication_binding import PolicyPublicationBinding

if TYPE_CHECKING:
    from .native_policy_authority_sources import FrozenNativePolicySources


def has_canonical_command_expressions(bundle: dict[str, object]) -> bool:
    if bundle.get("contractVersion") != "guard-policy-bundle.v2":
        return False
    payload = bundle.get("payload")
    spec = payload.get("spec") if isinstance(payload, dict) else None
    rules = spec.get("rules") if isinstance(spec, dict) else None
    if not isinstance(rules, list):
        raise NativePolicySnapshotError("native_policy_authority_bundle_semantics_unsupported")
    return any(
        isinstance(rule, dict)
        and rule.get("enabled") is not False
        and rule.get("effect") != "ignore"
        and isinstance(rule.get("match"), dict)
        and "commands" in rule["match"]
        for rule in rules
    )


def signed_command_native_rows(
    state: FrozenNativePolicySources,
    bundle: dict[str, object],
    *,
    materialized_at: str | None,
) -> list[dict[str, object]]:
    if materialized_at is None:
        raise NativePolicySnapshotError("native_policy_authority_materialization_unavailable")
    payload = bundle.get("payload")
    if not isinstance(payload, dict) or state.workspace_id is None:
        raise NativePolicySnapshotError("native_policy_authority_bundle_semantics_unsupported")
    document = GuardPolicyDocument.from_mapping(payload)
    publication = PolicyPublicationBinding.from_mapping(
        {
            "bundleVersion": bundle.get("bundleVersion"),
            "bundleHash": bundle.get("bundleHash"),
            "installationId": state.device["installation_id"],
        }
    )
    if publication is None:
        raise NativePolicySnapshotError("native_policy_authority_bundle_semantics_unsupported")
    # The canonical contract uses installation-ID device selectors. The caller
    # verified this exact local installation in the materialization MAC; OAuth
    # key thumbprints and server runtime-summary IDs are different namespaces.
    target = state.device["installation_id"]
    projection = project_canonical_command_policy(
        document,
        publication=publication,
        workspace_id=state.workspace_id,
        target_device_id=target,
    )
    materialized = materialize_native_command_source_rows(
        projection,
        target_device_id=target,
        normalize_keys=state.normalize_keys,
        materialized_at=materialized_at,
    )
    return [row.source_mapping() for row in materialized.rows]
