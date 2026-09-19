"""Reject signed policy semantics absent from the native snapshot contract."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import cast

from .native_policy_snapshot_constants import NativePolicySnapshotError


class NativeCloudPolicyRequirement(str, Enum):
    SCOPED_RULES = "scoped-rules"
    MANAGED_CONTROLS = "managed-controls"
    CLOUD_EXCEPTIONS = "cloud-exceptions"
    CUSTOM_EXTENSIONS = "custom-extensions"


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise NativePolicySnapshotError("native_cloud_policy_contract_invalid")
    return cast(Mapping[str, object], value)


def native_cloud_policy_requirements(bundle: Mapping[str, object]) -> frozenset[NativeCloudPolicyRequirement]:
    """Inspect an authenticated bundle without projecting away required authority."""

    requirements: set[NativeCloudPolicyRequirement] = set()
    if bundle.get("contractVersion") == "guard-policy-bundle.v2":
        payload = _mapping(bundle.get("payload"))
        spec = _mapping(payload.get("spec"))
        rules = spec.get("rules")
        if not isinstance(rules, list):
            raise NativePolicySnapshotError("native_cloud_policy_contract_invalid")
        if "x-hol-extension-controls" in payload:
            requirements.add(NativeCloudPolicyRequirement.MANAGED_CONTROLS)
        if "x-hol-custom-extension-continuity" in payload:
            requirements.add(NativeCloudPolicyRequirement.CUSTOM_EXTENSIONS)
        for raw_rule in cast(list[object], rules):
            rule = _mapping(raw_rule)
            if rule.get("enabled") is False or rule.get("effect") == "ignore":
                continue
            requirement = (
                NativeCloudPolicyRequirement.MANAGED_CONTROLS
                if "x-hol-extension-targets" in rule
                else NativeCloudPolicyRequirement.SCOPED_RULES
            )
            requirements.add(requirement)
    elif bundle.get("contractVersion") == "guard-policy-bundle.v1":
        rules = bundle.get("rules")
        if not isinstance(rules, list):
            raise NativePolicySnapshotError("native_cloud_policy_contract_invalid")
        if any(_mapping(rule).get("action") != "ignore" for rule in cast(list[object], rules)):
            requirements.add(NativeCloudPolicyRequirement.SCOPED_RULES)
        if bundle.get("cloudExceptions"):
            requirements.add(NativeCloudPolicyRequirement.CLOUD_EXCEPTIONS)
    else:
        raise NativePolicySnapshotError("native_cloud_policy_contract_invalid")
    return frozenset(requirements)


def require_native_v3_cloud_policy_support(
    bundle: Mapping[str, object], *, command_controls_bound: bool = False
) -> None:
    """V3 consumes defaults and an independently authenticated command binding.

    The caller must authenticate the complete managed activation and compare
    its exact control snapshot with the packaged command binding. This flag
    only permits reading defaults during that process; it is not application
    evidence and cannot represent any scoped, targeted or delegated rule.
    """

    requirements = native_cloud_policy_requirements(bundle)
    if command_controls_bound:
        requirements -= {NativeCloudPolicyRequirement.MANAGED_CONTROLS}
    if requirements:
        raise NativePolicySnapshotError("native_cloud_policy_semantics_unsupported")


__all__ = [
    "NativeCloudPolicyRequirement",
    "native_cloud_policy_requirements",
    "require_native_v3_cloud_policy_support",
]
