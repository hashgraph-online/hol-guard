"""Trust provenance data models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class TrustComponentScore:
    """One scored trust component inside an adapter."""

    key: str
    score: float
    rationale: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TrustAdapterScore:
    """Weighted adapter score inside a trust domain."""

    adapter_id: str
    label: str
    weight: float
    score: float
    components: tuple[TrustComponentScore, ...]


@dataclass(frozen=True, slots=True)
class TrustDomainScore:
    """One trust domain such as plugin, skills, or MCP."""

    domain: str
    label: str
    spec_id: str
    spec_version: str
    spec_path: str
    derived_from: tuple[str, ...]
    score: float
    adapters: tuple[TrustAdapterScore, ...]


@dataclass(frozen=True, slots=True)
class TrustReport:
    """Overall trust report emitted alongside scan results."""

    total: float
    domains: tuple[TrustDomainScore, ...] = ()


@dataclass(frozen=True, slots=True)
class TrustAdapterSpec:
    """Definition of a trust adapter and its components."""

    adapter_id: str
    label: str
    weight: float
    component_keys: tuple[str, ...]
    default_component_key: str = "score"


@dataclass(frozen=True, slots=True)
class TrustSpecDefinition:
    """Definition of a trust scoring specification."""

    spec_id: str
    version: str
    label: str
    spec_path: str
    derived_from: tuple[str, ...]
    adapters: tuple[TrustAdapterSpec, ...] = field(default_factory=tuple)
