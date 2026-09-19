"""Cloud posture derived from the current authenticated policy and runtime."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..policy_bundle_delivery import policy_bundle_has_extension_semantics
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
    bundle = validated_synced_policy_bundle(store)
    contract = bundle.get("contractVersion") if bundle is not None else None
    managed = bundle is not None and policy_bundle_has_extension_semantics(bundle)
    capabilities = managed_controls_lkg_capabilities(store, bundle) if managed and bundle is not None else frozenset()
    return canonical_runtime_posture(
        device_id=device_id,
        workspace_id=store.get_cloud_workspace_id(),
        protected_authority=extension_authority_is_protected(store) if managed else False,
        negotiated_capabilities=capabilities,
        contract_version=contract if isinstance(contract, str) else None,
        required_capability="policy-extension-targets.v1" if managed else None,
    )


def cloud_policy_runtime_posture(store: GuardStore, *, device_id: str) -> dict[str, object]:
    posture = local_policy_runtime_posture(store, device_id=device_id)
    return {wire: posture[local] for local, wire in _WIRE_FIELDS.items() if local in posture}
