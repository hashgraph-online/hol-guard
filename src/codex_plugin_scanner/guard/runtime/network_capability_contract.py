"""Platform capability profiles for network mediation backends."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import cast

from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    BackendCapability,
    EnforcementGrade,
    grade_required_capabilities,
    require_id,
)


class PlatformFamily(str, Enum):
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    KUBERNETES = "kubernetes"


@dataclass(frozen=True, slots=True)
class PlatformCapabilityProfile:
    platform: PlatformFamily
    backend_id: str
    capabilities: frozenset[BackendCapability]
    maximum_grade: EnforcementGrade
    requires_privilege: bool
    production_ready: bool
    reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.platform), PlatformFamily):
            raise ValueError("platform must be exact")
        require_id(self.backend_id, "backend_id")
        if any(not isinstance(item, BackendCapability) for item in self.capabilities):
            raise ValueError("capabilities must be exact")
        if not isinstance(cast(object, self.maximum_grade), EnforcementGrade):
            raise ValueError("maximum_grade must be exact")
        missing_for_grade = grade_required_capabilities(self.maximum_grade) - self.capabilities
        if missing_for_grade:
            raise ValueError("maximum_grade exceeds verified capabilities")
        if type(self.requires_privilege) is not bool or type(self.production_ready) is not bool:
            raise ValueError("boolean capability fields must be exact")
        require_id(self.reason_code, "reason_code")


def default_platform_profiles() -> tuple[PlatformCapabilityProfile, ...]:
    """Return honest alpha capabilities; unsupported platforms remain non-ready."""

    return (
        PlatformCapabilityProfile(
            platform=PlatformFamily.LINUX,
            backend_id="linux.oci-proxy",
            capabilities=frozenset(
                {
                    BackendCapability.DENY_ALL,
                    BackendCapability.PROXY_ONLY,
                    BackendCapability.PROCESS_TREE,
                    BackendCapability.ATOMIC_POLICY,
                    BackendCapability.RECEIPTS,
                }
            ),
            maximum_grade=EnforcementGrade.PROXY_ONLY,
            requires_privilege=True,
            production_ready=False,
            reason_code="alpha-not-validated",
        ),
        PlatformCapabilityProfile(
            platform=PlatformFamily.MACOS,
            backend_id="macos.observe",
            capabilities=frozenset({BackendCapability.OBSERVE}),
            maximum_grade=EnforcementGrade.OBSERVE,
            requires_privilege=False,
            production_ready=False,
            reason_code="feasibility-pending",
        ),
        PlatformCapabilityProfile(
            platform=PlatformFamily.WINDOWS,
            backend_id="windows.observe",
            capabilities=frozenset({BackendCapability.OBSERVE}),
            maximum_grade=EnforcementGrade.OBSERVE,
            requires_privilege=False,
            production_ready=False,
            reason_code="feasibility-pending",
        ),
        PlatformCapabilityProfile(
            platform=PlatformFamily.KUBERNETES,
            backend_id="kubernetes.network-policy",
            capabilities=frozenset({BackendCapability.DENY_ALL, BackendCapability.RECEIPTS}),
            maximum_grade=EnforcementGrade.DENY_ALL,
            requires_privilege=True,
            production_ready=False,
            reason_code="provider-pending",
        ),
    )


def enforcement_grade_rank(value: EnforcementGrade) -> int:
    return {
        EnforcementGrade.UNAVAILABLE: 0,
        EnforcementGrade.OBSERVE: 1,
        EnforcementGrade.DENY_ALL: 2,
        EnforcementGrade.PROXY_ONLY: 3,
        EnforcementGrade.TCP_IP_DESTINATION_ENFORCED: 4,
        EnforcementGrade.UDP_DNS_DESTINATION_ENFORCED: 5,
        EnforcementGrade.DESTINATION_ENFORCED: 6,
    }[value]
