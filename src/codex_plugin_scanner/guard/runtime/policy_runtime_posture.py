"""Cloud posture derived from the current authenticated policy and runtime."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..mdm.policy import managed_policy_cache_read_only
from ..native_policy_application import current_native_policy_application
from ..native_policy_snapshot import get_native_policy_snapshot_publisher
from ..policy_bundle_delivery import policy_bundle_has_extension_semantics
from ..policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
from ..policy_canonical_rollout import canonical_runtime_posture
from ..synced_policy import validated_synced_policy_bundle
from .managed_controls_sync import extension_authority_is_protected, managed_controls_lkg_capabilities

if TYPE_CHECKING:
    from ..store import GuardStore

_WIRE_FIELDS = {
    "selected_enforcement_lane": "selectedEnforcementLane",
    "advertised_canonical_capabilities": "advertisedCanonicalCapabilities",
    "effective_canonical_capabilities": "effectiveCanonicalCapabilities",
    "canonical_incompatibility_reason": "canonicalIncompatibilityReason",
    "canonical_rollout_percentage": "canonicalRolloutPercentage",
}


def local_policy_runtime_posture(store: GuardStore, *, device_id: str) -> dict[str, object]:
    """Read authority and application without turning observation into a write."""
    with managed_policy_cache_read_only():
        return _read_local_policy_runtime_posture(store, device_id=device_id)


def _read_local_policy_runtime_posture(store: GuardStore, *, device_id: str) -> dict[str, object]:
    bundle = validated_synced_policy_bundle(store)
    contract = bundle.get("contractVersion") if bundle is not None else None
    managed = bundle is not None and policy_bundle_has_extension_semantics(bundle)
    capabilities: frozenset[str] = (
        managed_controls_lkg_capabilities(store, bundle) if managed and bundle is not None else frozenset()
    )
    posture = canonical_runtime_posture(
        device_id=device_id,
        workspace_id=store.get_cloud_workspace_id(),
        protected_authority=extension_authority_is_protected(store) if managed else False,
        negotiated_capabilities=capabilities,
        contract_version=contract if isinstance(contract, str) else None,
        required_capability="policy-extension-targets.v1" if managed else None,
    )
    if bundle is None and get_native_policy_snapshot_publisher(store).requires_policy_authority:
        # Loss of a required source is not the initial source-free legacy lane.
        # Conservative presence may refuse readiness; it never proves current
        # application and does not rely on a historical applied receipt.
        posture["configured_enforcement_lane"] = posture["selected_enforcement_lane"]
        posture["selected_enforcement_lane"] = "unverified"
        posture["canonical_policy_application_status"] = "unverified"
        posture["canonical_incompatibility_reason"] = "native_policy_authority_unavailable"
    if not managed and bundle is not None and contract == POLICY_BUNDLE_V2_CONTRACT:
        posture["configured_enforcement_lane"] = posture["selected_enforcement_lane"]
        posture["canonical_policy_application_status"] = "unverified"
        if posture["selected_enforcement_lane"] == "canonical":
            accepted, reason = current_native_policy_application(
                get_native_policy_snapshot_publisher(store), bundle=bundle, installation_id=device_id
            )
            if reason == "canonical_enforcement_disabled":
                # A rollout change during observation must not retain the old
                # configured capability marker alongside the new live reason.
                posture = canonical_runtime_posture(
                    device_id=device_id,
                    workspace_id=store.get_cloud_workspace_id(),
                    contract_version=POLICY_BUNDLE_V2_CONTRACT,
                )
                posture["configured_enforcement_lane"] = posture["selected_enforcement_lane"]
                posture["canonical_policy_application_status"] = "unverified"
            if accepted is not None:
                posture["canonical_policy_application_status"] = "current"
                posture["canonical_policy_application_mode"] = accepted.binding.mode
            if reason is not None:
                posture["selected_enforcement_lane"] = "unverified"
                posture["canonical_incompatibility_reason"] = reason
    return posture


def cloud_policy_runtime_posture(store: GuardStore, *, device_id: str) -> dict[str, object]:
    posture = local_policy_runtime_posture(store, device_id=device_id)
    return {wire: posture[local] for local, wire in _WIRE_FIELDS.items() if local in posture}
