"""Delegated enforcement compilation for Package Firewall Extensions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EnforcementPlane(str, Enum):
    COMMAND = "command"
    PACKAGE_FIREWALL = "package_firewall"


class DelegationError(ValueError):
    """Raised when delegated protection is compiled into the wrong plane."""


@dataclass(frozen=True, slots=True)
class CompiledExtensionControl:
    extension_id: str
    permission_id: str | None
    blocked: bool
    enforcement_plane: EnforcementPlane


def compile_delegated_control(
    *,
    extension_id: str,
    permission_id: str | None,
    delegated_protection: str | None,
    blocked: bool,
) -> CompiledExtensionControl:
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)
    if extension is None:
        raise DelegationError("extension is not present in the canonical registry")
    canonical_delegation = extension.delegated_protection
    if delegated_protection != canonical_delegation:
        if canonical_delegation == "package-firewall" and delegated_protection is None:
            raise DelegationError("package extension is missing delegated protection")
        raise DelegationError("delegated protection does not match the canonical registry")
    if canonical_delegation == "package-firewall":
        plane = EnforcementPlane.PACKAGE_FIREWALL
    elif canonical_delegation is None:
        plane = EnforcementPlane.COMMAND
    else:
        raise DelegationError("unsupported delegated protection")
    return CompiledExtensionControl(
        extension.extension_id,
        permission_id,
        blocked,
        plane,
    )


def require_package_firewall_path(control: CompiledExtensionControl) -> None:
    if control.enforcement_plane is not EnforcementPlane.PACKAGE_FIREWALL:
        raise DelegationError("package control did not use Package Firewall")
