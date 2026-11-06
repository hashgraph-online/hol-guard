"""Versioned, backend-neutral contracts for Guard network mediation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Final, cast

NETWORK_BACKEND_SCHEMA_VERSION: Final = "guard.network-backend.v1"
NETWORK_PRIVACY_SCHEMA_VERSION: Final = "guard.network-privacy.v1"

_SHA256: Final = re.compile(r"[0-9a-f]{64}")
_STABLE_ID: Final = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")


class NetworkAction(str, Enum):
    DENY = "deny"
    APPROVE = "approve"
    ALLOW = "allow"


class EnforcementGrade(str, Enum):
    UNAVAILABLE = "unavailable"
    OBSERVE = "observe"
    DENY_ALL = "deny-all"
    PROXY_ONLY = "proxy-only"
    TCP_IP_DESTINATION_ENFORCED = "tcp-ip-destination-enforced"
    UDP_DNS_DESTINATION_ENFORCED = "udp-dns-destination-enforced"
    DESTINATION_ENFORCED = "destination-enforced"


class BackendCapability(str, Enum):
    OBSERVE = "observe"
    DENY_ALL = "deny-all"
    TCP_DESTINATION = "tcp-destination"
    UDP_DESTINATION = "udp-destination"
    DNS_CORRELATION = "dns-correlation"
    PROXY_ONLY = "proxy-only"
    PROCESS_TREE = "process-tree"
    ATOMIC_POLICY = "atomic-policy"
    RECEIPTS = "receipts"
    FORCED_BROKER_ROUTING = "forced-broker-routing"
    RESOLVER_ROUTE_ATTESTATION = "resolver-route-attestation"
    DOH_CLASSIFICATION_OR_APP_INTENT = "doh-classification-or-app-intent"


_UDP_DNS_CAPABILITIES: Final[frozenset[BackendCapability]] = frozenset(
    {
        BackendCapability.DENY_ALL,
        BackendCapability.TCP_DESTINATION,
        BackendCapability.UDP_DESTINATION,
        BackendCapability.DNS_CORRELATION,
        BackendCapability.PROCESS_TREE,
        BackendCapability.ATOMIC_POLICY,
        BackendCapability.RECEIPTS,
        BackendCapability.FORCED_BROKER_ROUTING,
        BackendCapability.RESOLVER_ROUTE_ATTESTATION,
        BackendCapability.DOH_CLASSIFICATION_OR_APP_INTENT,
    }
)


_GRADE_REQUIREMENTS: Final[dict[EnforcementGrade, frozenset[BackendCapability]]] = {
    EnforcementGrade.UNAVAILABLE: frozenset(),
    EnforcementGrade.OBSERVE: frozenset({BackendCapability.OBSERVE}),
    EnforcementGrade.DENY_ALL: frozenset({BackendCapability.DENY_ALL}),
    EnforcementGrade.PROXY_ONLY: frozenset({BackendCapability.PROXY_ONLY, BackendCapability.PROCESS_TREE}),
    EnforcementGrade.TCP_IP_DESTINATION_ENFORCED: frozenset(
        {
            BackendCapability.DENY_ALL,
            BackendCapability.TCP_DESTINATION,
            BackendCapability.PROCESS_TREE,
            BackendCapability.ATOMIC_POLICY,
            BackendCapability.RECEIPTS,
        }
    ),
    EnforcementGrade.UDP_DNS_DESTINATION_ENFORCED: _UDP_DNS_CAPABILITIES,
    EnforcementGrade.DESTINATION_ENFORCED: _UDP_DNS_CAPABILITIES,
}


def grade_required_capabilities(grade: EnforcementGrade) -> frozenset[BackendCapability]:
    if not isinstance(grade, EnforcementGrade):
        raise ValueError("grade must be exact")
    return _GRADE_REQUIREMENTS[grade]


@dataclass(frozen=True, slots=True)
class BackendAdvertisement:
    backend_id: str
    backend_digest: str
    capabilities: frozenset[BackendCapability]
    maximum_grade: EnforcementGrade
    healthy_until_epoch_ms: int
    schema_version: str = NETWORK_BACKEND_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != NETWORK_BACKEND_SCHEMA_VERSION:
            raise ValueError("unsupported backend schema version")
        require_id(self.backend_id, "backend_id")
        require_digest(self.backend_digest, "backend_digest")
        if not self.capabilities or any(not isinstance(item, BackendCapability) for item in self.capabilities):
            raise ValueError("capabilities must contain exact values")
        if not isinstance(cast(object, self.maximum_grade), EnforcementGrade):
            raise ValueError("maximum_grade must be exact")
        if not grade_required_capabilities(self.maximum_grade).issubset(self.capabilities):
            raise ValueError("maximum_grade exceeds verified capabilities")
        if type(self.healthy_until_epoch_ms) is not int or self.healthy_until_epoch_ms <= 0:
            raise ValueError("healthy_until_epoch_ms must be positive")


def require_id(value: object, name: str) -> None:
    if not isinstance(value, str) or _STABLE_ID.fullmatch(value) is None:
        raise ValueError(f"{name} must be a stable identifier")


def require_digest(value: object, name: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
