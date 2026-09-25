"""Shared immutable harness setup and protection data contracts.

The protection contract predates the event capability report below.  The
report types are deliberately additive: callers that only need the existing
setup or summary table can continue to construct and consume
``HarnessProtectionContract`` with the original fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

CapabilityDeploymentHealth = Literal["unverified", "healthy", "degraded", "unavailable", "unknown"]
CapabilityEvidenceLevel = Literal[
    "not_run",
    "source_review",
    "unit_test",
    "synthetic_canary",
    "live_block",
    "independent_review",
]
CapabilityLocalHosted = Literal["local", "hosted", "unknown"]
CAPABILITY_DECLARED_ACTIONS = frozenset(
    {
        "inspect",
        "observe",
        "block",
        "approval",
        "suggest",
        "rewrite",
        "redact-before-forward",
        "inventory",
        "unavailable",
    }
)


@dataclass(frozen=True, slots=True)
class HarnessEventCapability:
    """Versioned declaration for one adapter event boundary.

    These fields describe what an adapter declares it can do.  Deployment
    health and proof level stay on the row as separate values, and default to
    ``unverified``/``not_run`` so a source declaration cannot be mistaken for
    an observed live block.
    """

    harness: str
    adapter: str
    host_version_scope: str
    os_arch: str
    local_hosted: CapabilityLocalHosted
    event: str
    transport: str
    mode: str
    declared_actions: tuple[str, ...]
    error_behavior: str
    mandatory_compatibility: str
    known_blind_spots: tuple[str, ...]
    source_reference: str
    deployment_health: CapabilityDeploymentHealth = "unverified"
    evidence_level: CapabilityEvidenceLevel = "not_run"
    observed_at: str | None = None
    expires_at: str | None = None
    evidence_reference: str | None = None
    evidence_build: str | None = None
    evidence_host_version_scope: str | None = None
    evidence_os_arch: str | None = None
    denied_witness_reference: str | None = None
    allowed_witness_reference: str | None = None
    compatibility_verified: bool = False

    def __post_init__(self) -> None:
        """Reject malformed source declarations before they reach JSON."""

        required_text = {
            "harness": self.harness,
            "adapter": self.adapter,
            "host_version_scope": self.host_version_scope,
            "os_arch": self.os_arch,
            "event": self.event,
            "transport": self.transport,
            "mode": self.mode,
            "error_behavior": self.error_behavior,
            "mandatory_compatibility": self.mandatory_compatibility,
            "source_reference": self.source_reference,
        }
        for field, value in required_text.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be a non-empty string")
        if self.local_hosted not in {"local", "hosted", "unknown"}:
            raise ValueError(f"unsupported local_hosted value: {self.local_hosted!r}")
        if self.deployment_health not in {"unverified", "healthy", "degraded", "unavailable", "unknown"}:
            raise ValueError(f"unsupported deployment_health value: {self.deployment_health!r}")
        if self.evidence_level not in {
            "not_run",
            "source_review",
            "unit_test",
            "synthetic_canary",
            "live_block",
            "independent_review",
        }:
            raise ValueError(f"unsupported evidence_level value: {self.evidence_level!r}")
        if not isinstance(self.compatibility_verified, bool):
            raise ValueError("compatibility_verified must be a bool")
        if not isinstance(self.declared_actions, tuple) or any(
            not isinstance(action, str) or not action.strip() for action in self.declared_actions
        ):
            raise ValueError("declared_actions must be a tuple of non-empty strings")
        unsupported_actions = set(self.declared_actions) - CAPABILITY_DECLARED_ACTIONS
        if unsupported_actions:
            raise ValueError(f"unsupported declared action(s): {sorted(unsupported_actions)!r}")
        if not isinstance(self.known_blind_spots, tuple) or any(
            not isinstance(blind_spot, str) or not blind_spot.strip() for blind_spot in self.known_blind_spots
        ):
            raise ValueError("known_blind_spots must be a tuple of non-empty strings")
        if self.evidence_level == "not_run" and any(
            value is not None
            for value in (
                self.observed_at,
                self.expires_at,
                self.evidence_reference,
                self.evidence_build,
                self.evidence_host_version_scope,
                self.evidence_os_arch,
                self.denied_witness_reference,
                self.allowed_witness_reference,
                self.compatibility_verified if self.compatibility_verified else None,
            )
        ):
            raise ValueError("not_run evidence cannot carry an observation timestamp or proof reference")

    def to_dict(self) -> dict[str, object]:
        """Serialize one row using the stable machine report keys."""

        return {
            "harness": self.harness,
            "adapter": self.adapter,
            "host_version_scope": self.host_version_scope,
            "os_arch": self.os_arch,
            "local_hosted": self.local_hosted,
            "event": self.event,
            "transport": self.transport,
            "mode": self.mode,
            "declared_actions": list(self.declared_actions),
            "error_behavior": self.error_behavior,
            "mandatory_compatibility": self.mandatory_compatibility,
            "known_blind_spots": list(self.known_blind_spots),
            "source_reference": self.source_reference,
            "deployment_health": self.deployment_health,
            "evidence_level": self.evidence_level,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "evidence_reference": self.evidence_reference,
            "evidence_build": self.evidence_build,
            "evidence_host_version_scope": self.evidence_host_version_scope,
            "evidence_os_arch": self.evidence_os_arch,
            "denied_witness_reference": self.denied_witness_reference,
            "allowed_witness_reference": self.allowed_witness_reference,
            "compatibility_verified": self.compatibility_verified,
        }


# The shorter name is useful to callers that do not need the harness prefix.
CapabilityEvent = HarnessEventCapability


@dataclass(frozen=True, slots=True)
class HarnessCapabilityReport:
    """Machine-readable event capability report metadata and rows."""

    schema_version: str = "harness-capability-report.v1"
    build: str = "unknown"
    commit: str = "unknown"
    requested_host: str | None = None
    capabilities: tuple[HarnessEventCapability, ...] = ()

    @property
    def build_id(self) -> str:
        """Compatibility alias for callers that call the build input an ID."""

        return self.build

    def to_dict(self) -> dict[str, object]:
        """Serialize the report without injecting wall-clock values."""

        return {
            "schema_version": self.schema_version,
            "build": self.build,
            "commit": self.commit,
            "requested_host": self.requested_host,
            "capabilities": [capability.to_dict() for capability in self.capabilities],
        }

    def to_json(self) -> str:
        """Render the deterministic machine representation."""

        from .capability_report import render_capability_report_json

        return render_capability_report_json(self)

    def to_markdown(self) -> str:
        """Render the deterministic Markdown representation."""

        from .capability_report import render_capability_report_markdown

        return render_capability_report_markdown(self)


CapabilityReport = HarnessCapabilityReport


@dataclass(frozen=True, slots=True)
class HarnessProtectionContract:
    """Static protection profile for one AI coding harness.

    Attributes:
        harness: Canonical harness identifier (matches adapter `harness` field).
        install_aliases: All strings accepted by `hol-guard install <alias>`.
        config_paths: Glob-style paths where the harness stores config
            (relative to ``$HOME`` unless absolute).
        event_surfaces: Hook event types the harness exposes
            (e.g. "shell", "prompt", "mcp_tool", "file_read").
        native_approval: True if the harness has a first-class native approval
            prompt that Guard can intercept without a browser fallback.
        browser_fallback: True if Guard falls back to a browser approval page
            when native approval is unavailable.
        resume_support: True if the harness can resume the original command
            after an async approval completes.
        known_blind_spots: Human-readable description of event types or
            surfaces that Guard cannot currently observe for this harness.
        smoke_command: Shell command an operator can run to confirm Guard is
            active for this harness.
    """

    harness: str
    install_aliases: tuple[str, ...]
    config_paths: tuple[str, ...]
    event_surfaces: tuple[str, ...]
    native_approval: bool
    browser_fallback: bool
    resume_support: bool
    known_blind_spots: str
    smoke_command: str
    surface_capabilities: tuple[str, ...] = ()
    supported_actions: tuple[str, ...] = ()
    docs_path: str | None = None
    icon_label: str | None = None
    capability_events: tuple[HarnessEventCapability, ...] = ()

    @property
    def capability_report(self) -> tuple[HarnessEventCapability, ...]:
        """Compatibility alias for the additive per-event report rows."""

        return self.capability_events

    @property
    def event_capabilities(self) -> tuple[HarnessEventCapability, ...]:
        """Compatibility alias for callers using the event-oriented name."""

        return self.capability_events


@dataclass(frozen=True, slots=True)
class HarnessSetupStep:
    """Plain-language action for connecting or checking one harness."""

    step_id: str
    title: str
    body: str
    command: tuple[str, ...] = ()
    writes_config: bool = False
    requires_confirmation: bool = False

    def to_dict(self) -> dict[str, object]:
        """Serialize the setup contract using the existing public payload keys."""
        return {
            "step_id": self.step_id,
            "title": self.title,
            "body": self.body,
            "command": list(self.command),
            "writes_config": self.writes_config,
            "requires_confirmation": self.requires_confirmation,
        }


@dataclass(frozen=True, slots=True)
class HarnessCoverageSummary:
    """Summary of what Guard can and cannot observe for one harness."""

    native_hooks: bool
    browser_fallback: bool
    mcp_proxy: bool
    prompt_hooks: bool
    blind_spots: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize the setup contract using the existing public payload keys."""
        return {
            "native_hooks": self.native_hooks,
            "browser_fallback": self.browser_fallback,
            "mcp_proxy": self.mcp_proxy,
            "prompt_hooks": self.prompt_hooks,
            "blind_spots": list(self.blind_spots),
        }


@dataclass(frozen=True, slots=True)
class HarnessSetupContract:
    """Dashboard and CLI setup contract for one supported harness."""

    harness: str
    display_name: str
    install_aliases: tuple[str, ...]
    setup_steps: tuple[HarnessSetupStep, ...]
    verify_steps: tuple[HarnessSetupStep, ...]
    repair_steps: tuple[HarnessSetupStep, ...]
    coverage: HarnessCoverageSummary
    surface_capabilities: tuple[str, ...] = ()
    supported_actions: tuple[str, ...] = ()
    docs_path: str | None = None
    icon_label: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the setup contract using the existing public payload keys."""
        payload: dict[str, object] = {
            "harness": self.harness,
            "display_name": self.display_name,
            "install_aliases": list(self.install_aliases),
            "setup_steps": [step.to_dict() for step in self.setup_steps],
            "verify_steps": [step.to_dict() for step in self.verify_steps],
            "repair_steps": [step.to_dict() for step in self.repair_steps],
            "coverage": self.coverage.to_dict(),
        }
        if self.surface_capabilities:
            payload["surface_capabilities"] = list(self.surface_capabilities)
        if self.supported_actions:
            payload["supported_actions"] = list(self.supported_actions)
        if self.docs_path is not None:
            payload["docs_path"] = self.docs_path
        if self.icon_label is not None:
            payload["icon_label"] = self.icon_label
        return payload
