"""Structured Guard evidence and decision models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

SignalFamily = Literal[
    "network",
    "filesystem",
    "secret",
    "execution",
    "publisher",
    "prompt",
    "policy",
    "provenance",
]
EvidenceSource = Literal["artifact", "prompt", "history", "cloud"]
TransportKind = Literal["local", "remote", "hybrid"]
ProvenanceSourceKind = Literal["none", "self-declared", "signed", "attested", "curated"]
PublisherTrust = Literal["unknown", "known-good", "revoked", "flagged"]
GuardVerdictAction = Literal["allow", "warn", "block", "require_reapproval", "sandbox_required"]
CapabilityDeltaType = Literal[
    "new_network_host",
    "publisher_changed",
    "transport_changed",
    "secret_scope_expanded",
    "filesystem_scope_expanded",
    "subprocess_added",
    "approval_surface_changed",
    "interpreter_changed",
]
ReviewPriority = Literal["low", "medium", "high", "critical"]
PromptRequestClass = Literal[
    "secret_read",
    "exfil_intent",
    "destructive_intent",
    "subprocess_intent",
    "guard_bypass_intent",
]
RemediationActionKind = Literal[
    "approve_once",
    "allow_until_expiry",
    "allow_publisher_until_expiry",
    "block_and_remove",
    "review_network_destination",
    "rotate_exposed_secret",
    "open_investigation",
    "run_in_sandbox",
    "defer_and_notify_team",
]


@dataclass(frozen=True, slots=True)
class GuardSignal:
    """Single explainable signal produced by Guard detection."""

    signal_id: str
    family: SignalFamily
    severity: int
    confidence: float
    evidence_source: EvidenceSource
    matched_text: str | None
    explanation: str
    remediation: str | None
    rule_version: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CapabilitySet:
    """Normalized artifact capabilities used for delta scoring."""

    network_hosts: tuple[str, ...] = ()
    network_schemes: tuple[str, ...] = ()
    filesystem_paths: tuple[str, ...] = ()
    secret_classes: tuple[str, ...] = ()
    subprocess_invocation: bool = False
    interpreters: tuple[str, ...] = ()
    shell_wrappers: tuple[str, ...] = ()
    publisher: str | None = None
    transport: TransportKind = "local"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CapabilityDelta:
    """Semantic change in artifact capability between two versions."""

    delta_type: CapabilityDeltaType
    before: str | None
    after: str | None
    severity: int
    explanation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProvenanceBundle:
    """Publisher and attestation context used to enrich local decisions."""

    source_kind: ProvenanceSourceKind = "none"
    publisher_trust: PublisherTrust = "unknown"
    signature_verified: bool = False
    attestation_verified: bool = False
    evidence_refs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class HistoryContext:
    """Prior local history for an artifact and publisher."""

    first_seen_at: str | None = None
    last_seen_at: str | None = None
    prior_approvals: int = 0
    prior_incidents: int = 0
    prior_blocks: int = 0
    publisher_trust: PublisherTrust = "unknown"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RemediationAction:
    """Suggested next step attached to a verdict."""

    kind: RemediationActionKind
    label: str
    detail: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PromptRequest:
    """Typed runtime prompt intent that can be scored like an artifact."""

    request_id: str
    request_class: PromptRequestClass
    summary: str
    matched_text: str
    severity: int
    confidence: float
    remediation: tuple[RemediationAction, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["remediation"] = [item.to_dict() for item in self.remediation]
        return payload


@dataclass(frozen=True, slots=True)
class GuardVerdict:
    """Final explainable decision prior to scoped policy override."""

    action: GuardVerdictAction
    severity: int
    confidence: float
    reasons: tuple[str, ...]
    recommended_next_actions: tuple[str, ...]
    suppressible: bool
    review_priority: ReviewPriority
    evidence_sources: tuple[EvidenceSource, ...]
    provenance_state: ProvenanceSourceKind
    capability_delta: tuple[CapabilityDelta, ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["capability_delta"] = [item.to_dict() for item in self.capability_delta]
        return payload
