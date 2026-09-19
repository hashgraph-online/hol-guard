"""User-facing catalog upgrade guidance for managed permission mismatches."""

from __future__ import annotations

from .command_extensions import CommandSafetyExtensionRegistry
from .extension_control_contract import ControlResolution, ResolverFailureCode


def catalog_upgrade_status(
    resolution: ControlResolution,
    *,
    registry: CommandSafetyExtensionRegistry,
    runtime_version: str,
    missing_permission_ids: tuple[str, ...] = (),
    missing_extension_ids: tuple[str, ...] = (),
) -> dict[str, object]:
    """Explain why a policy cannot claim applied against another catalog."""

    codes = tuple(failure.code.value for failure in resolution.failures)
    digest_mismatch = ResolverFailureCode.CATALOG_DIGEST_MISMATCH.value in codes
    unknown_permission = ResolverFailureCode.UNKNOWN_PERMISSION_TARGET.value in codes
    unknown_extension = ResolverFailureCode.UNKNOWN_EXTENSION_TARGET.value in codes
    applied = not resolution.failures
    if digest_mismatch:
        next_action = (
            "Update this device to a runtime that supports the policy's catalog, "
            "or change the Cloud rule so it matches the installed catalog."
        )
    elif unknown_permission:
        listed = ", ".join(missing_permission_ids) or "the named permission"
        next_action = f"Change the Cloud rule away from {listed}, or upgrade the device catalog."
    elif unknown_extension:
        listed = ", ".join(missing_extension_ids) or "the named extension"
        next_action = f"Restore {listed} on this device, or remove it from the Cloud policy."
    else:
        next_action = "No catalog upgrade is required."
    return {
        "applied": applied,
        "runtime_version": runtime_version,
        "catalog_digest": registry.catalog_digest,
        "failure_codes": codes,
        "missing_permission_ids": missing_permission_ids,
        "missing_extension_ids": missing_extension_ids,
        "preserve_approved_restrictions": True,
        "next_action": next_action,
    }
