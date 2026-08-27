"""Shared typed contracts for the execution-assurance local core.

Implements the frozen wave-one contract set (``guard.atomic-guarantee.v1``,
``guard.isolation-provider.v1``, and the three-contract context model) as
immutable, strictly validated types. These types are the single source for the
local core; providers, receipts, and the CLI consume them. Wave-two builds the
runtime behavior against these frozen shapes.

Design rules:
- Immutable frozen/slots dataclasses and ``str, Enum`` value types.
- Strict ``__post_init__`` validation that fails closed on malformed input.
- No secret values: only opaque ``SecretHandle`` references cross a boundary.
- Unknown guarantee kinds parse forward-compatibly but never satisfy a
  requirement (``AtomicGuaranteeKind.known``).
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Final, TypeVar, cast

EXECUTION_ASSURANCE_SCHEMA_VERSION: Final = "1.0.0-alpha.1"
_T = TypeVar("_T")

_SHA256_HEX_LENGTH: Final = 64
_MAX_FIELD_LENGTH: Final = 512
_MAX_GUARANTEE_EVIDENCE_REFS: Final = 64
_MAX_STREAM_DIGESTS: Final = 8
_MAX_OUTPUT_BYTES: Final = 64 * 1024


def _require_str(value: object, label: str, *, max_length: int = _MAX_FIELD_LENGTH) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError(f"{label} must be a non-empty string of at most {max_length} characters")
    return value


def _require_sha256(value: object, label: str) -> str:
    text = _require_str(value, label, max_length=_SHA256_HEX_LENGTH)
    if len(text) != _SHA256_HEX_LENGTH or any(c not in "0123456789abcdef" for c in text):
        raise ValueError(f"{label} must be a lowercase SHA-256 hex digest")
    return text


def _require_enum(value: object, enum_type: type[Enum], label: str) -> None:
    if not isinstance(value, enum_type):
        raise ValueError(f"{label} must be a {enum_type.__name__}")


def _require_instance(value: object, expected_type: type[_T], label: str) -> _T:
    if not isinstance(value, expected_type):
        raise ValueError(f"{label} must be a {expected_type.__name__}")
    return value


def _require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a bool")
    return value


def _require_stream_count(value: object, label: str) -> int:
    """Validate a per-stream byte count field (rejects bool and negatives)."""

    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _require_exit_code(value: object, label: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an int or None")
    return value


def _require_positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _frame_scalar(value: object) -> object:
    """Normalize supported JSON-shaped values to a canonical stable form."""

    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("digest fields require finite floats")
        return value
    if isinstance(value, (tuple, list)):
        return [_frame_scalar(item) for item in cast(Iterable[object], value)]
    if isinstance(value, Mapping):
        keys = list(value)
        if not all(isinstance(key, str) for key in keys):
            raise ValueError("digest field mappings require string keys")
        string_keys = cast(list[str], keys)
        return {key: _frame_scalar(value[key]) for key in sorted(string_keys)}
    raise ValueError(f"unsupported digest field type: {type(value).__name__}")


def framed_digest(domain: str, fields: Mapping[str, object]) -> str:
    """Deterministic framed SHA-256 digest over a domain and field mapping.

    Each field is length-prefixed so concatenation cannot alias across fields.
    """

    digest = hashlib.sha256()
    domain_bytes = domain.encode("utf-8")
    digest.update(len(domain_bytes).to_bytes(8, "big"))
    digest.update(domain_bytes)
    for key in sorted(fields):
        key_bytes = key.encode("utf-8")
        digest.update(len(key_bytes).to_bytes(8, "big"))
        digest.update(key_bytes)
        value = json.dumps(
            _frame_scalar(fields[key]),
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


class GuardExecutionAssuranceBoundary(str, Enum):
    """Execution isolation boundary, ordered weakest to strongest."""

    OBSERVED_HOST = "observed_host"
    CONTROLLED_HOST = "controlled_host"
    OS_ISOLATED = "os_isolated"
    HARDWARE_ISOLATED = "hardware_isolated"


class GuardExecutionAttestationTrust(str, Enum):
    """Trust tier of an attestation statement."""

    UNATTESTED = "unattested"
    SELF_ATTESTED = "self_attested"
    VERIFIED = "verified"


class AtomicGuaranteeKind(str, Enum):
    """Frozen atomic guarantee kinds (``guard.atomic-guarantee.v1``)."""

    FILESYSTEM = "filesystem"
    SECRET = "secret"
    NETWORK = "network"
    PROCESS = "process"
    PRIVILEGE = "privilege"
    RESOURCE = "resource"
    KERNEL_HARDWARE = "kernel_hardware"
    IDENTITY = "identity"
    OUTPUT = "output"
    CLEANUP = "cleanup"
    TENANT = "tenant"

    @classmethod
    def known(cls, value: object) -> bool:
        return isinstance(value, cls)


@dataclass(frozen=True, slots=True)
class AtomicGuarantee:
    """One atomic guarantee with its enforcement record."""

    kind: AtomicGuaranteeKind
    enforced: bool
    boundary: GuardExecutionAssuranceBoundary
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_enum(self.kind, AtomicGuaranteeKind, "kind")
        _ = _require_bool(self.enforced, "enforced")
        _require_enum(self.boundary, GuardExecutionAssuranceBoundary, "boundary")
        if len(self.evidence_refs) > _MAX_GUARANTEE_EVIDENCE_REFS:
            raise ValueError("too many evidence refs")
        for ref in self.evidence_refs:
            _ = _require_str(ref, "evidence_ref")


class ProviderHealthState(str, Enum):
    """Provider health state machine."""

    UNKNOWN = "unknown"
    VERIFYING = "verifying"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    REVOKED = "revoked"
    INCOMPATIBLE = "incompatible"


@dataclass(frozen=True, slots=True)
class ProviderIdentity:
    """Pinned provider identity."""

    provider_kind: str
    implementation_version: str
    binary_or_image_digest: str
    signing_identity: str
    trust_domain: str

    def __post_init__(self) -> None:
        _ = _require_str(self.provider_kind, "provider_kind")
        _ = _require_str(self.implementation_version, "implementation_version")
        _ = _require_sha256(self.binary_or_image_digest, "binary_or_image_digest")
        _ = _require_str(self.signing_identity, "signing_identity")
        _ = _require_str(self.trust_domain, "trust_domain")

    def thumbprint(self) -> str:
        return framed_digest(
            "guard.provider-identity.v1",
            {
                "provider_kind": self.provider_kind,
                "implementation_version": self.implementation_version,
                "binary_or_image_digest": self.binary_or_image_digest,
                "signing_identity": self.signing_identity,
                "trust_domain": self.trust_domain,
            },
        )


@dataclass(frozen=True, slots=True)
class SecretHandle:
    """Opaque reference to a secret. Never carries the secret value."""

    handle_id: str
    scope: str

    def __post_init__(self) -> None:
        _ = _require_str(self.handle_id, "handle_id")
        _ = _require_str(self.scope, "scope")


@dataclass(frozen=True, slots=True)
class ExecutionLease:
    """Fenced execution lease binding a launch to one instance."""

    plan_digest: str
    provider_thumbprint: str
    fencing_generation: int
    lease_expiry_epoch_seconds: int
    attempt_nonce: str
    input_manifest_digest: str

    def __post_init__(self) -> None:
        _ = _require_sha256(self.plan_digest, "plan_digest")
        _ = _require_sha256(self.provider_thumbprint, "provider_thumbprint")
        _ = _require_positive_int(self.fencing_generation, "fencing_generation")
        _ = _require_positive_int(self.lease_expiry_epoch_seconds, "lease_expiry_epoch_seconds")
        _ = _require_str(self.attempt_nonce, "attempt_nonce")
        _ = _require_sha256(self.input_manifest_digest, "input_manifest_digest")


class ExecutionOutcome(str, Enum):
    """Terminal execution outcome."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown_outcome"


@dataclass(frozen=True, slots=True)
class TerminalStatement:
    """Bound terminal execution record (``guard.execution-statement.v1``)."""

    outcome: ExecutionOutcome
    exit_code: int | None
    stream_byte_counts: tuple[tuple[str, int], ...]
    stream_digests: tuple[tuple[str, str], ...]
    truncated: bool
    declared_output_digests: tuple[str, ...]
    cleanup_complete: bool
    execution_instance: str
    attestation_trust: GuardExecutionAttestationTrust

    def __post_init__(self) -> None:
        _require_enum(self.outcome, ExecutionOutcome, "outcome")
        _ = _require_exit_code(self.exit_code, "exit_code")
        if len(self.stream_digests) > _MAX_STREAM_DIGESTS:
            raise ValueError("too many stream digests")
        names = {name for name, _ in self.stream_byte_counts}
        if {name for name, _ in self.stream_digests} != names:
            raise ValueError("stream digests must cover every stream byte count")
        for name, count in self.stream_byte_counts:
            _ = _require_str(name, "stream name")
            _ = _require_stream_count(count, "stream byte count")
        for name, digest in self.stream_digests:
            _ = _require_str(name, "stream name")
            _ = _require_sha256(digest, "stream digest")
        _ = _require_bool(self.truncated, "truncated")
        for digest in self.declared_output_digests:
            _ = _require_sha256(digest, "declared output digest")
        _ = _require_bool(self.cleanup_complete, "cleanup_complete")
        _ = _require_str(self.execution_instance, "execution_instance")
        _require_enum(self.attestation_trust, GuardExecutionAttestationTrust, "attestation_trust")


@dataclass(frozen=True, slots=True)
class DecisionContext:
    """Privacy-safe, digest-bound decision inputs (no raw content)."""

    repository_digest: str
    workspace_digest: str
    executable_digest: str
    action_class: str
    context_digest: str = ""

    def __post_init__(self) -> None:
        _ = _require_sha256(self.repository_digest, "repository_digest")
        _ = _require_sha256(self.workspace_digest, "workspace_digest")
        _ = _require_sha256(self.executable_digest, "executable_digest")
        _ = _require_str(self.action_class, "action_class")
        if self.context_digest:
            object.__setattr__(self, "context_digest", _require_sha256(self.context_digest, "context_digest"))
        else:
            object.__setattr__(
                self,
                "context_digest",
                framed_digest(
                    "guard.decision-context.v1",
                    {
                        "repository_digest": self.repository_digest,
                        "workspace_digest": self.workspace_digest,
                        "executable_digest": self.executable_digest,
                        "action_class": self.action_class,
                    },
                ),
            )


@dataclass(frozen=True, slots=True)
class EvidenceSummary:
    """Privacy-safe bounded decision/evidence summary."""

    context_digest: str
    guarantee_kinds: tuple[str, ...]
    achieved_boundary: GuardExecutionAssuranceBoundary
    degraded_reason: str | None = None

    def __post_init__(self) -> None:
        _ = _require_sha256(self.context_digest, "context_digest")
        for kind in self.guarantee_kinds:
            _ = _require_str(kind, "guarantee_kind")
        _require_enum(self.achieved_boundary, GuardExecutionAssuranceBoundary, "achieved_boundary")
        if self.degraded_reason is not None:
            _ = _require_str(self.degraded_reason, "degraded_reason")


def require_guarantees_satisfied(
    required: Iterable[AtomicGuaranteeKind],
    provided: Iterable[AtomicGuarantee],
    minimum_boundary: GuardExecutionAssuranceBoundary,
) -> tuple[str, ...]:
    """Return unsatisfied required guarantee kinds.

    A required kind is satisfied only if an enforced guarantee at or above the
    minimum boundary is present. Boundary never substitutes for a missing
    guarantee.
    """

    _require_enum(minimum_boundary, GuardExecutionAssuranceBoundary, "minimum_boundary")
    boundary_order = (
        GuardExecutionAssuranceBoundary.OBSERVED_HOST,
        GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
        GuardExecutionAssuranceBoundary.OS_ISOLATED,
        GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED,
    )
    minimum_index = boundary_order.index(minimum_boundary)
    satisfied: set[AtomicGuaranteeKind] = set()
    for guarantee in provided:
        _ = _require_instance(guarantee, AtomicGuarantee, "guarantee")
        if not guarantee.enforced:
            continue
        if boundary_order.index(guarantee.boundary) < minimum_index:
            continue
        satisfied.add(guarantee.kind)
    unsatisfied = [kind for kind in required if kind not in satisfied]
    for kind in unsatisfied:
        _require_enum(kind, AtomicGuaranteeKind, "required kind")
    return tuple(kind.value for kind in unsatisfied)


__all__ = [
    "EXECUTION_ASSURANCE_SCHEMA_VERSION",
    "AtomicGuarantee",
    "AtomicGuaranteeKind",
    "DecisionContext",
    "EvidenceSummary",
    "ExecutionLease",
    "ExecutionOutcome",
    "GuardExecutionAssuranceBoundary",
    "GuardExecutionAttestationTrust",
    "ProviderHealthState",
    "ProviderIdentity",
    "SecretHandle",
    "TerminalStatement",
    "framed_digest",
    "require_guarantees_satisfied",
]
