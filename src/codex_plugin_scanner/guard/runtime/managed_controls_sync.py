"""Focused managed-controls projections used by Cloud receipt sync."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

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
from .custom_extension_continuity import (
    CUSTOM_EXTENSION_CONTINUITY_FIELD,
    CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2,
    CustomExtensionContinuityError,
    prepare_verified_custom_extension_continuity,
)
from .extension_catalog_completion import current_catalog_registry
from .extension_catalog_sync import (
    MANAGED_CONTROLS_RUNTIME_CAPABILITIES,
    build_managed_controls_runtime_posture,
)
from .extension_control_authority import AuthorityHealth, ExtensionControlAuthorityView
from .extension_control_runtime import ExtensionControlRuntimeSnapshot

if TYPE_CHECKING:
    from ..store import GuardStore


def _registry_for_home(guard_home):
    if guard_home is None:
        raise ManagedControlsPolicyError("policy_local_view_invalid", "Explicit Guard home required.")
    from ..store import GuardStore

    return current_catalog_registry(GuardStore(guard_home))


def effective_managed_controls_for_activation(
    store: GuardStore,
    activation_bundle: dict[str, object],
    *,
    validated_policy_bundle: dict[str, object] | None,
    candidate: ParsedManagedControlsPolicy | None,
    candidate_capabilities: frozenset[str],
) -> tuple[ParsedManagedControlsPolicy | None, frozenset[str], str | None]:
    """Resolve current-candidate or authenticated LKG managed semantics."""

    if validated_policy_bundle is not None and activation_bundle.get("bundleHash") == validated_policy_bundle.get(
        "bundleHash"
    ):
        return candidate, candidate_capabilities, None
    capabilities = managed_controls_lkg_capabilities(store, activation_bundle)
    try:
        runtime_summary = store.get_sync_payload("runtime_session_summary")
        if runtime_summary is not None and not isinstance(runtime_summary, dict):
            raise ManagedControlsPolicyError("policy_local_view_invalid", "Runtime session summary must be an object.")
        parsed = parsed_managed_controls_from_validated_policy_bundle(
            activation_bundle,
            registry=current_catalog_registry(store),
            negotiated_capabilities=capabilities,
            guard_home=store.guard_home,
            runtime_summary=runtime_summary,
        )
    except ManagedControlsPolicyError as error:
        return None, capabilities, error.code
    return parsed if parsed.has_extension_semantics else None, capabilities, None


def managed_controls_negotiated_capabilities(
    store: GuardStore,
    sync_payload: dict[str, object] | None,
) -> frozenset[str]:
    """Return only capabilities explicitly confirmed by the current sync contract."""

    raw: object = None
    if isinstance(sync_payload, dict):
        raw = sync_payload.get("managedControlsCapabilities")
        if raw is None:
            raw = sync_payload.get("negotiatedManagedControlsCapabilities")
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        return frozenset()
    flags = ManagedControlsFeatureFlags.from_environment()
    enabled = frozenset(flags.runtime_capabilities(protected_authority=extension_authority_is_protected(store)))
    return frozenset(cast(list[str], raw)).intersection(MANAGED_CONTROLS_RUNTIME_CAPABILITIES).intersection(enabled)


def managed_controls_lkg_capabilities(
    store: GuardStore,
    policy_bundle: dict[str, object],
) -> frozenset[str]:
    """Use cached negotiation only for the exact authenticated LKG activation."""

    flags = ManagedControlsFeatureFlags.from_environment()
    enabled = frozenset(flags.runtime_capabilities(protected_authority=extension_authority_is_protected(store)))
    return (
        store.managed_controls_lkg_capabilities(policy_bundle)
        .intersection(MANAGED_CONTROLS_RUNTIME_CAPABILITIES)
        .intersection(enabled)
    )


def validated_managed_controls_candidate(
    policy_bundle: dict[str, object] | None,
    *,
    negotiated_capabilities: frozenset[str],
    delivery_field_provided: bool,
    delivery_payload: object,
    workspace_id: str | None,
    device_id: str,
    runtime_summary: object,
    guard_home=None,
    registry=None,
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
    delivery_catalog_digest = delivery_payload.get("catalogDigest") if isinstance(delivery_payload, dict) else None
    try:
        parsed = parsed_managed_controls_from_validated_policy_bundle(
            policy_bundle,
            registry=registry if registry is not None else lambda: _registry_for_home(guard_home),
            negotiated_capabilities=negotiated_capabilities,
            guard_home=guard_home,
            runtime_summary=runtime_summary if isinstance(runtime_summary, dict) else None,
            delivery_catalog_digest=delivery_catalog_digest,
        )
    except ManagedControlsPolicyError as error:
        return None, None, None, error.code, True
    candidate = parsed if parsed.has_extension_semantics else None
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
    from .extension_catalog_pages import CAPABILITY, prepare_installed_catalog_view
    from .extension_catalog_sync import ExtensionCatalogLimitError, build_v1_catalog_from_view

    try:
        registry = current_catalog_registry(store)
        view = prepare_installed_catalog_view(
            store.guard_home,
            registry=registry,
            guard_version=__version__,
            generated_at=generated_at,
        )
    except ImportError as error:
        raise RuntimeError("Native complete catalog discovery factory is unavailable") from error
    except (OSError, RuntimeError, TypeError, ValueError):
        # The active registry can be sparse. Its availability does not prove
        # complete discovery, including during staged factory integration.
        return {"managedControlsCapabilities": []}
    manifest = view.manifest
    v2: dict[str, object] = {
        "extensionCatalogViewDigest": manifest["catalogDigest"],
        "extensionCatalogEnforcementDigest": manifest["enforcementCatalogDigest"],
        "extensionCatalogGeneratedAt": manifest["generatedAt"],
        "extensionControlSchemaVersions": [manifest["controlSchemaVersion"]],
    }
    try:
        catalog = build_v1_catalog_from_view(view)
    except ExtensionCatalogLimitError:
        # Complete discovery identity is never substituted for a legacy digest.
        catalog = None
    except (OSError, RuntimeError, TypeError, ValueError):
        # Native cache/resident loss is not a usable complete observation.
        return {"managedControlsCapabilities": []}
    from ..native_command_control_authority_io import hold_command_control_authority_lock
    from .extension_catalog_completion import policy_view_ready

    legacy = {} if catalog is None else {"extensionCatalogDigest": catalog["catalogDigest"]}
    metadata_posture = {**v2, **legacy, "managedControlsCapabilities": [CAPABILITY]}
    try:
        if current_catalog_registry(store).catalog_digest != registry.catalog_digest:
            return {"managedControlsCapabilities": []}
        summary = getattr(store, "get_sync_payload", lambda _: None)("runtime_session_summary")
        if not isinstance(summary, dict) or "policyMetadataIdentity" not in summary:
            return metadata_posture
        # Recheck discovery, the native stamp and committed enforcement while
        # excluding a concurrent activation through readiness construction.
        with hold_command_control_authority_lock(store.guard_home, shared=True):
            current = current_catalog_registry(store)
            if current.catalog_digest != registry.catalog_digest:
                return {"managedControlsCapabilities": []}
            if not policy_view_ready(store=store, registry=current):
                return metadata_posture
            protected, authority_revision, managed_revision, effective_digest = _authority_posture(store, flags=flags)
            posture = dict(
                build_managed_controls_runtime_posture(
                    catalog_digest=None if catalog is None else catalog["catalogDigest"],
                    extension_authority_revision=authority_revision,
                    managed_extension_authority_revision=managed_revision,
                    effective_projection_digest=effective_digest,
                    capabilities=flags.runtime_capabilities(protected_authority=protected),
                )
            )
            posture.update(v2)
            capabilities = posture["managedControlsCapabilities"]
            assert isinstance(capabilities, list)
            posture["managedControlsCapabilities"] = [*capabilities, CAPABILITY]
            return posture
    except (OSError, RuntimeError, TypeError, ValueError):
        return {"managedControlsCapabilities": []}


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
) -> tuple[bool, int | None, int | None, str | None]:
    if not flags.managed_extension_controls:
        return False, None, None, None
    authority = _read_protected_authority(store)
    if authority is None:
        return False, None, None, None
    return (
        True,
        authority.revision,
        authority.managed_revision,
        f"sha256:{ExtensionControlRuntimeSnapshot.from_authority_view(authority).effective_digest}",
    )


def extension_authority_is_protected(store: GuardStore) -> bool:
    """Return whether the exact local authority can enforce managed controls."""

    return _read_protected_authority(store) is not None


def _read_protected_authority(store: GuardStore) -> ExtensionControlAuthorityView | None:
    from ..native_command_control_authority_io import NativeCommandControlAuthorityUnavailableError

    try:
        authority = store.read_extension_control_authority_for_registry(current_catalog_registry(store), read_only=True)
    except NativeCommandControlAuthorityUnavailableError:
        # The lease was busy. This call answers whether managed controls can be
        # enforced right now, and an authority nobody read cannot enforce them.
        return None
    except (RuntimeError, TypeError, ValueError):
        return None
    return authority if authority.health is AuthorityHealth.PROTECTED else None
