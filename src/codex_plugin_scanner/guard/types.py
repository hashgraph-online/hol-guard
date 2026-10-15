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
GuardVerdictAction = Literal["allow", "warn", "block", "require_reapproval", "sandbox_required"]
ReviewPriority = Literal["low", "medium", "high", "critical"]
PromptRequestClass = Literal[
    "secret_read",
    "exfil_intent",
    "destructive_intent",
    "subprocess_intent",
    "guard_bypass_intent",
    "prompt_injection_intent",
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
