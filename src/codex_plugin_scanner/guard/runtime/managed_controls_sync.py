"""Focused managed-controls projections used by Cloud receipt sync."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from ...version import __version__
from ..managed_controls.feature_flags import ManagedControlsFeatureFlags
from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from .custom_extension_continuity import (
    CustomExtensionContinuityError,
    apply_verified_custom_extension_continuity,
)
from .extension_catalog_sync import (
    build_builtin_extension_catalog_wire,
    build_managed_controls_runtime_posture,
)
from .extension_control_authority import AuthorityHealth, ExtensionControlAuthorityView
from .extension_control_runtime import ExtensionControlRuntimeSnapshot

if TYPE_CHECKING:
    from ..store import GuardStore


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
    now: str,
) -> None:
    """Apply signed continuity when enabled and audit bounded refusals."""

    if not ManagedControlsFeatureFlags.from_environment().allows_custom_extension_continuity():
        return
    try:
        apply_verified_custom_extension_continuity(store, policy_bundle, now=now)
    except CustomExtensionContinuityError as error:
        store.add_event(
            "custom_extension_continuity/refused",
            {"status": "refused", "reason": str(error)},
            now,
        )


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
        ExtensionControlRuntimeSnapshot.from_authority_view(authority).effective_digest,
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
