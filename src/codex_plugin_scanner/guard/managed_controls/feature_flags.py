"""Independent Managed Controls rollout switches."""

from __future__ import annotations

import os
from dataclasses import dataclass

GUARD_EXTENSION_CATALOG_SYNC_V1 = "GUARD_EXTENSION_CATALOG_SYNC_V1"
GUARD_POLICY_EXTENSION_TARGETS_V1 = "GUARD_POLICY_EXTENSION_TARGETS_V1"
GUARD_MANAGED_EXTENSION_CONTROLS_V1 = "GUARD_MANAGED_EXTENSION_CONTROLS_V1"
GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1 = "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1"
GUARD_EXTENSION_FIRST_CONTROLS_UI = "GUARD_EXTENSION_FIRST_CONTROLS_UI"

_RUNTIME_CAPABILITIES = (
    "extension-catalog.v1",
    "extension-control-layer.v1",
    "policy-extension-targets.v1",
    "managed-controls-atomic-apply.v1",
    "custom-extension-continuity.v2",
)


def _enabled(value: str | None) -> bool:
    """Only an explicit true enables a production path."""

    return value is not None and value.strip().lower() == "true"


@dataclass(frozen=True, slots=True)
class ManagedControlsFeatureFlags:
    catalog_sync: bool = False
    policy_extension_targets: bool = False
    managed_extension_controls: bool = False
    atomic_apply: bool = False
    extension_first_controls_ui: bool = False
    authoring: bool = False
    compilation: bool = False
    delivery: bool = False
    enforcement: bool = False

    @classmethod
    def from_environment(cls) -> ManagedControlsFeatureFlags:
        return cls(
            catalog_sync=_enabled(os.environ.get(GUARD_EXTENSION_CATALOG_SYNC_V1)),
            policy_extension_targets=_enabled(os.environ.get(GUARD_POLICY_EXTENSION_TARGETS_V1)),
            managed_extension_controls=_enabled(os.environ.get(GUARD_MANAGED_EXTENSION_CONTROLS_V1)),
            atomic_apply=_enabled(os.environ.get(GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1)),
            extension_first_controls_ui=_enabled(os.environ.get(GUARD_EXTENSION_FIRST_CONTROLS_UI)),
        )

    def runtime_capabilities(self, *, protected_authority: bool) -> tuple[str, ...]:
        """Return only enabled capabilities whose prerequisites are available."""

        if not self.catalog_sync:
            return ()
        capabilities = [_RUNTIME_CAPABILITIES[0]]
        if not protected_authority or not self.managed_extension_controls:
            return tuple(capabilities)
        capabilities.append(_RUNTIME_CAPABILITIES[1])
        if not self.policy_extension_targets:
            return tuple(capabilities)
        capabilities.append(_RUNTIME_CAPABILITIES[2])
        if self.atomic_apply:
            capabilities.append(_RUNTIME_CAPABILITIES[3])
            if self.extension_first_controls_ui:
                capabilities.append(_RUNTIME_CAPABILITIES[4])
        return tuple(capabilities)

    def allows_custom_extension_continuity(self) -> bool:
        """Continuity is a signed managed-control UI/runtime feature."""

        return (
            self.catalog_sync
            and self.policy_extension_targets
            and self.managed_extension_controls
            and self.atomic_apply
            and self.extension_first_controls_ui
        )

    def validate(self) -> None:
        if self.enforcement and not self.compilation:
            raise ValueError("enforcement requires compilation")
        if self.delivery and not self.compilation:
            raise ValueError("delivery requires compilation")
