"""DNS correlation, backend receipts, and bounded broker budgets."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum

from .network_policy_contract import (
    NETWORK_BACKEND_SCHEMA_VERSION,
    NETWORK_BROKER_SCHEMA_VERSION,
    BackendCapability,
    DestinationKind,
    EnforcementGrade,
    NetworkAction,
    NetworkProtocol,
    ProcessTreeIdentity,
    canonical_destination,
    canonical_digest,
    grade_required_capabilities,
    require_digest,
    require_id,
)


class CorrelationStatus(str, Enum):
    MATCHED = "matched"
    EXPIRED = "expired"
    BEFORE_RESOLUTION = "before-resolution"
    PROCESS_MISMATCH = "process-mismatch"
    ADDRESS_MISMATCH = "address-mismatch"
    MISSING = "missing"


class ReceiptTrust(str, Enum):
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class DnsResolutionBinding:
    binding_id: str
    process_tree_digest: str
    query_name: str
    canonical_name: str
    addresses: tuple[str, ...]
    observed_at_epoch_ms: int
    expires_at_epoch_ms: int
    resolver_digest: str
    schema_version: str = NETWORK_BROKER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != NETWORK_BROKER_SCHEMA_VERSION:
            raise ValueError("unsupported broker schema version")
        require_digest(self.process_tree_digest, "process_tree_digest")
        require_digest(self.resolver_digest, "resolver_digest")
        require_id(self.binding_id, "binding_id")
        for name, value in (("query_name", self.query_name), ("canonical_name", self.canonical_name)):
            if value != canonical_destination(DestinationKind.HOST, value):
                raise ValueError(f"{name} must be a canonical ASCII host")
        if not self.addresses:
            raise ValueError("addresses cannot be empty")
        canonical = tuple(sorted({ipaddress.ip_address(value).compressed for value in self.addresses}))
        if type(self.observed_at_epoch_ms) is not int or self.observed_at_epoch_ms <= 0:
            raise ValueError("observed_at_epoch_ms must be positive")
        if type(self.expires_at_epoch_ms) is not int or self.expires_at_epoch_ms <= self.observed_at_epoch_ms:
            raise ValueError("expires_at_epoch_ms must follow observation")
        object.__setattr__(self, "addresses", canonical)

    @property
    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class ConnectionObservation:
    flow_id: str
    process_tree: ProcessTreeIdentity
    remote_address: str
    remote_port: int
    protocol: NetworkProtocol
    observed_at_epoch_ms: int

    def __post_init__(self) -> None:
        require_id(self.flow_id, "flow_id")
        if not isinstance(self.process_tree, ProcessTreeIdentity):
            raise ValueError("process_tree must be exact")
        object.__setattr__(self, "remote_address", ipaddress.ip_address(self.remote_address).compressed)
        if type(self.remote_port) is not int or not 1 <= self.remote_port <= 65535:
            raise ValueError("remote_port must be within 1..65535")
        if self.protocol not in (NetworkProtocol.TCP, NetworkProtocol.UDP):
            raise ValueError("connections support only TCP or UDP")
        if type(self.observed_at_epoch_ms) is not int or self.observed_at_epoch_ms <= 0:
            raise ValueError("observed_at_epoch_ms must be positive")


def correlate_dns_connection(
    observation: ConnectionObservation,
    binding: DnsResolutionBinding | None,
) -> CorrelationStatus:
    if binding is None:
        return CorrelationStatus.MISSING
    if binding.process_tree_digest != observation.process_tree.digest:
        return CorrelationStatus.PROCESS_MISMATCH
    if observation.observed_at_epoch_ms < binding.observed_at_epoch_ms:
        return CorrelationStatus.BEFORE_RESOLUTION
    if observation.observed_at_epoch_ms >= binding.expires_at_epoch_ms:
        return CorrelationStatus.EXPIRED
    if observation.remote_address not in binding.addresses:
        return CorrelationStatus.ADDRESS_MISMATCH
    return CorrelationStatus.MATCHED


@dataclass(frozen=True, slots=True)
class BackendReceipt:
    receipt_id: str
    backend_id: str
    backend_digest: str
    process_tree_digest: str
    policy_digest: str
    generation: int
    flow_digest: str
    action: NetworkAction
    achieved_grade: EnforcementGrade
    capabilities: frozenset[BackendCapability]
    applied_at_epoch_ms: int
    valid_until_epoch_ms: int
    signature_key_id: str
    signature: str
    schema_version: str = NETWORK_BACKEND_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != NETWORK_BACKEND_SCHEMA_VERSION:
            raise ValueError("unsupported backend schema version")
        for name in ("receipt_id", "backend_id", "signature_key_id"):
            require_id(getattr(self, name), name)
        for name in ("backend_digest", "process_tree_digest", "policy_digest", "flow_digest"):
            require_digest(getattr(self, name), name)
        if type(self.generation) is not int or self.generation < 1:
            raise ValueError("generation must be positive")
        if not isinstance(self.action, NetworkAction) or not isinstance(self.achieved_grade, EnforcementGrade):
            raise ValueError("receipt enums must be exact")
        if any(not isinstance(item, BackendCapability) for item in self.capabilities):
            raise ValueError("receipt capabilities must be exact")
        if BackendCapability.RECEIPTS not in self.capabilities:
            raise ValueError("receipt capability must be asserted")
        if not grade_required_capabilities(self.achieved_grade).issubset(self.capabilities):
            raise ValueError("achieved_grade exceeds receipt capabilities")
        if type(self.applied_at_epoch_ms) is not int or self.applied_at_epoch_ms <= 0:
            raise ValueError("applied_at_epoch_ms must be positive")
        if type(self.valid_until_epoch_ms) is not int or self.valid_until_epoch_ms <= self.applied_at_epoch_ms:
            raise ValueError("valid_until_epoch_ms must follow apply time")
        if not self.signature or len(self.signature) > 4096:
            raise ValueError("signature must be present and bounded")

    @property
    def signed_payload_digest(self) -> str:
        values = {field: getattr(self, field) for field in self.__dataclass_fields__ if field != "signature"}
        return canonical_digest(values)


@dataclass(frozen=True, slots=True)
class ReceiptVerification:
    receipt_digest: str
    verifier_id: str
    trust: ReceiptTrust
    verified_at_epoch_ms: int
    reason_code: str

    def __post_init__(self) -> None:
        require_digest(self.receipt_digest, "receipt_digest")
        require_id(self.verifier_id, "verifier_id")
        if not isinstance(self.trust, ReceiptTrust):
            raise ValueError("trust must be exact")
        if type(self.verified_at_epoch_ms) is not int or self.verified_at_epoch_ms <= 0:
            raise ValueError("verified_at_epoch_ms must be positive")
        require_id(self.reason_code, "reason_code")


def receipt_authority_current(
    receipt: BackendReceipt,
    verification: ReceiptVerification | None,
    *,
    now_epoch_ms: int,
) -> bool:
    """Treat a signature as authority only after external cryptographic verification."""

    if type(now_epoch_ms) is not int or now_epoch_ms <= 0 or verification is None:
        return False
    return (
        verification.trust is ReceiptTrust.VERIFIED
        and verification.receipt_digest == canonical_digest(receipt)
        and receipt.applied_at_epoch_ms <= verification.verified_at_epoch_ms <= now_epoch_ms
        and now_epoch_ms < receipt.valid_until_epoch_ms
    )


@dataclass(frozen=True, slots=True)
class BrokerPerformanceBudget:
    decision_p95_ms: int = 20
    decision_p99_ms: int = 50
    approval_dedup_window_ms: int = 2_000
    maximum_pending_flows: int = 1_024
    maximum_evidence_bytes: int = 16_384
    maximum_prompts_per_logical_flow: int = 1
    primary_view_usable_ms: int = 1_000

    def __post_init__(self) -> None:
        values = tuple(getattr(self, field) for field in self.__dataclass_fields__)
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("performance budgets must be positive integers")
        if self.decision_p95_ms > self.decision_p99_ms:
            raise ValueError("p95 cannot exceed p99")
        if self.maximum_prompts_per_logical_flow != 1:
            raise ValueError("one logical flow permits at most one prompt")
        if self.primary_view_usable_ms > 1_000:
            raise ValueError("primary view budget cannot exceed one second")
