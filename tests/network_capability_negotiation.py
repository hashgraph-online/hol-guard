"""Capability negotiation, failure and privacy shapes the network contract tests pin."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import cast

from codex_plugin_scanner.guard.runtime.network_capability_contract import (
    PlatformCapabilityProfile,
    enforcement_grade_rank,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    NETWORK_PRIVACY_SCHEMA_VERSION,
    BackendCapability,
    EnforcementGrade,
    grade_required_capabilities,
    require_digest,
    require_id,
)
from tests.network_policy_model import FailureMode


class BackendState(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    STALE = "stale"
    TAMPERED = "tampered"
    DEGRADED = "degraded"


class RecoveryAction(str, Enum):
    NONE = "none"
    RETRY = "retry"
    REPAIR = "repair"
    REQUIRE_ADMIN = "require-admin"
    ROLLBACK = "rollback"


class ControlPlaneRoute(str, Enum):
    POLICY = "policy"
    HEALTH = "health"
    UPDATE = "update"
    REVOCATION = "revocation"


@dataclass(frozen=True, slots=True)
class CapabilityRequirement:
    capabilities: frozenset[BackendCapability]
    minimum_grade: EnforcementGrade

    def __post_init__(self) -> None:
        if not self.capabilities or any(not isinstance(item, BackendCapability) for item in self.capabilities):
            raise ValueError("capabilities must contain exact values")
        if not isinstance(cast(object, self.minimum_grade), EnforcementGrade):
            raise ValueError("minimum_grade must be exact")
        missing_for_grade = grade_required_capabilities(self.minimum_grade) - self.capabilities
        if missing_for_grade:
            raise ValueError("minimum_grade exceeds required capabilities")


@dataclass(frozen=True, slots=True)
class FailureDisposition:
    backend_state: BackendState
    policy_mode: FailureMode
    effective_grade: EnforcementGrade
    permit_workload_network: bool
    recovery: RecoveryAction
    reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.backend_state), BackendState):
            raise ValueError("backend_state must be exact")
        if not isinstance(cast(object, self.policy_mode), FailureMode):
            raise ValueError("policy_mode must be exact")
        if not isinstance(cast(object, self.effective_grade), EnforcementGrade):
            raise ValueError("effective_grade must be exact")
        if type(self.permit_workload_network) is not bool:
            raise ValueError("permit_workload_network must be exact")
        if not isinstance(cast(object, self.recovery), RecoveryAction):
            raise ValueError("recovery must be exact")
        require_id(self.reason_code, "reason_code")
        if self.backend_state is not BackendState.AVAILABLE and self.permit_workload_network:
            raise ValueError("unhealthy enforcement cannot permit workload networking")
        if self.permit_workload_network and self.effective_grade in {
            EnforcementGrade.UNAVAILABLE,
            EnforcementGrade.OBSERVE,
        }:
            raise ValueError("non-enforcing grades cannot permit workload networking")


@dataclass(frozen=True, slots=True)
class ControlPlaneEscapeHatch:
    installation_id: str
    routes: frozenset[ControlPlaneRoute]
    endpoint_digests: tuple[str, ...]
    executable_digest: str
    expires_at_epoch_ms: int
    inheritable_by_workload: bool = False

    def __post_init__(self) -> None:
        require_id(self.installation_id, "installation_id")
        if not self.routes or any(not isinstance(item, ControlPlaneRoute) for item in self.routes):
            raise ValueError("routes must contain exact values")
        if not self.endpoint_digests:
            raise ValueError("endpoint_digests cannot be empty")
        for digest in self.endpoint_digests:
            require_digest(digest, "endpoint_digest")
        require_digest(self.executable_digest, "executable_digest")
        if type(self.expires_at_epoch_ms) is not int or self.expires_at_epoch_ms <= 0:
            raise ValueError("expires_at_epoch_ms must be positive")
        if self.inheritable_by_workload is not False:
            raise ValueError("control-plane routes cannot be inherited by workloads")
        object.__setattr__(self, "endpoint_digests", tuple(sorted(set(self.endpoint_digests))))


@dataclass(frozen=True, slots=True)
class NetworkPrivacyPolicy:
    raw_destination_enabled: bool
    retention_seconds: int
    maximum_events: int
    include_process_arguments: bool = False
    include_url_components: bool = False
    include_payload_bytes: bool = False
    schema_version: str = NETWORK_PRIVACY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != NETWORK_PRIVACY_SCHEMA_VERSION:
            raise ValueError("unsupported network privacy schema version")
        for name, value in (
            ("raw_destination_enabled", self.raw_destination_enabled),
            ("include_process_arguments", self.include_process_arguments),
            ("include_url_components", self.include_url_components),
            ("include_payload_bytes", self.include_payload_bytes),
        ):
            if type(value) is not bool:
                raise ValueError(f"{name} must be exact")
        if type(self.retention_seconds) is not int or not 60 <= self.retention_seconds <= 2_592_000:
            raise ValueError("retention_seconds must be within 60..2592000")
        if type(self.maximum_events) is not int or not 1 <= self.maximum_events <= 1_000_000:
            raise ValueError("maximum_events must be within 1..1000000")
        if self.include_process_arguments or self.include_url_components or self.include_payload_bytes:
            raise ValueError("sensitive flow fields are prohibited")
        if self.raw_destination_enabled and self.retention_seconds > 86_400:
            raise ValueError("raw destination retention cannot exceed one day")


def negotiate_capability(
    profile: PlatformCapabilityProfile,
    requirement: CapabilityRequirement,
) -> EnforcementGrade:
    """Return the verified grade or unavailable; never infer missing capability."""

    if not profile.production_ready or not requirement.capabilities.issubset(profile.capabilities):
        return EnforcementGrade.UNAVAILABLE
    if not grade_required_capabilities(requirement.minimum_grade).issubset(profile.capabilities):
        return EnforcementGrade.UNAVAILABLE
    if enforcement_grade_rank(profile.maximum_grade) < enforcement_grade_rank(requirement.minimum_grade):
        return EnforcementGrade.UNAVAILABLE
    return profile.maximum_grade


def failure_disposition(
    *,
    backend_state: BackendState,
    policy_mode: FailureMode,
) -> FailureDisposition:
    if backend_state is BackendState.AVAILABLE:
        raise ValueError("available backend disposition requires verified runtime grade")
    recovery = {
        BackendState.UNAVAILABLE: RecoveryAction.RETRY,
        BackendState.STALE: RecoveryAction.REPAIR,
        BackendState.TAMPERED: RecoveryAction.REQUIRE_ADMIN,
        BackendState.DEGRADED: RecoveryAction.ROLLBACK,
    }[backend_state]
    grade = EnforcementGrade.DENY_ALL if policy_mode is FailureMode.OFFLINE else EnforcementGrade.UNAVAILABLE
    return FailureDisposition(
        backend_state=backend_state,
        policy_mode=policy_mode,
        effective_grade=grade,
        permit_workload_network=False,
        recovery=recovery,
        reason_code=f"backend-{backend_state.value}",
    )
