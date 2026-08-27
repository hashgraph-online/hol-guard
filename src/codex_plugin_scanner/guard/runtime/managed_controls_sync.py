"""Focused managed-controls projections used by Cloud receipt sync."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from ...version import __version__
from ..managed_controls.feature_flags import (
    CUSTOM_EXTENSION_CONTINUITY_V2_CAPABILITY,
    ManagedControlsFeatureFlags,
)
from ..managed_controls_policy_bundle import (
    parsed_managed_controls_from_validated_policy_bundle,
    signed_cloud_extension_projection_digest,
)
from ..managed_controls_policy_fields import ManagedControlsPolicyError, ParsedManagedControlsPolicy
from ..policy_bundle_delivery import validated_managed_policy_delivery
from ..policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
from ..store_custom_extension_continuity import CustomExtensionContinuityMutation
from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from .custom_extension_continuity import (
    CUSTOM_EXTENSION_CONTINUITY_FIELD,
    CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2,
    CustomExtensionContinuityError,
    prepare_verified_custom_extension_continuity,
)
from .extension_catalog_sync import (
    build_builtin_extension_catalog_wire,
    build_managed_controls_runtime_posture,
)
from .extension_control_authority import AuthorityHealth, ExtensionControlAuthorityView
from .extension_control_runtime import ExtensionControlRuntimeSnapshot

if TYPE_CHECKING:
    from ..store import GuardStore


def validated_managed_controls_candidate(
    policy_bundle: dict[str, object] | None,
    *,
    negotiated_capabilities: frozenset[str],
    delivery_field_provided: bool,
    delivery_payload: object,
    workspace_id: str | None,
    device_id: str,
    runtime_summary: object,
) -> tuple[
    dict[str, object] | None,
    ParsedManagedControlsPolicy | None,
    dict[str, object] | None,
    str | None,
    bool,
]:
    """Parse V2 Extension semantics and bind any required delivery metadata."""

    is_v2 = policy_bundle is not None and policy_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT
    if not is_v2 or policy_bundle is None:
        return policy_bundle, None, None, None, False
    try:
        parsed = parsed_managed_controls_from_validated_policy_bundle(
            policy_bundle,
            registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            negotiated_capabilities=negotiated_capabilities,
        )
    except ManagedControlsPolicyError as error:
        return None, None, None, error.code, True
    candidate = parsed if parsed.has_extension_semantics else None
    delivery_catalog_digest = delivery_payload.get("catalogDigest") if isinstance(delivery_payload, dict) else None
    delivery, error = validated_managed_policy_delivery(
        policy_bundle=policy_bundle,
        delivery_field_provided=delivery_field_provided,
        delivery_payload=delivery_payload,
        workspace_id=workspace_id,
        device_id=device_id,
        runtime_summary=runtime_summary,
        expected_extension_projection_digest=(
            signed_cloud_extension_projection_digest(
                parsed,
                catalog_digest=delivery_catalog_digest,
            )
            if candidate is not None and isinstance(delivery_catalog_digest, str)
            else None
        ),
    )
    return (None if error is not None else policy_bundle), candidate, delivery, error, True


def managed_controls_runtime_sync_posture(
    store: GuardStore,
    *,
    generated_at: str,
) -> dict[str, object]:
    """Advertise only explicitly enabled, locally backed managed capabilities."""

    flags = ManagedControlsFeatureFlags.from_environment()
    if not flags.catalog_sync:
        return {}
    try:
        catalog = build_builtin_extension_catalog_wire(
            guard_version=__version__,
            generated_at=generated_at,
        )
    except (TypeError, ValueError):
        return {"managedControlsCapabilities": []}
    protected, authority_revision, effective_digest = _authority_posture(store, flags=flags)
    return dict(
        build_managed_controls_runtime_posture(
            catalog_digest=catalog["catalogDigest"],
            extension_authority_revision=authority_revision,
            effective_projection_digest=effective_digest,
            capabilities=flags.runtime_capabilities(protected_authority=protected),
        )
    )


def apply_custom_extension_continuity_from_sync(
    store: GuardStore,
    policy_bundle: Mapping[str, object],
    *,
    device_id: str,
    negotiated_capabilities: frozenset[str],
    now: str,
) -> CustomExtensionContinuityMutation | None:
    """Preflight signed continuity for atomic policy activation."""

    if not ManagedControlsFeatureFlags.from_environment().allows_custom_extension_continuity():
        return None
    try:
        payload = policy_bundle.get("payload")
        continuity = payload.get(CUSTOM_EXTENSION_CONTINUITY_FIELD) if isinstance(payload, Mapping) else None
        if isinstance(continuity, dict) and continuity.get("schemaVersion") == CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2:
            if not extension_authority_is_protected(store):
                raise CustomExtensionContinuityError("v2 continuity requires protected extension authority")
            if CUSTOM_EXTENSION_CONTINUITY_V2_CAPABILITY not in negotiated_capabilities:
                raise CustomExtensionContinuityError("v2 continuity capability was not negotiated")
        mutation, _state = prepare_verified_custom_extension_continuity(
            store,
            policy_bundle,
            device_id=device_id,
            now=now,
        )
        return mutation
    except CustomExtensionContinuityError as error:
        store.add_event(
            "custom_extension_continuity/refused",
            {"status": "refused", "reason": str(error)},
            now,
        )
        raise


def _authority_posture(
    store: GuardStore,
    *,
    flags: ManagedControlsFeatureFlags,
) -> tuple[bool, int | None, str | None]:
    if not flags.managed_extension_controls:
        return False, None, None
    authority = _read_protected_authority(store)
    if authority is None:
        return False, None, None
    return (
        True,
        authority.revision,
        f"sha256:{ExtensionControlRuntimeSnapshot.from_authority_view(authority).effective_digest}",
    )


def extension_authority_is_protected(store: GuardStore) -> bool:
    """Return whether the exact local authority can enforce managed controls."""

    return _read_protected_authority(store) is not None


def _read_protected_authority(store: GuardStore) -> ExtensionControlAuthorityView | None:
    try:
        authority = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    except (RuntimeError, TypeError, ValueError):
        return None
    return authority if authority.health is AuthorityHealth.PROTECTED else None
