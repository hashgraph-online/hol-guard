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
    an observed live block. The native runtime validates every row it hands
    over; nothing is checked here.
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
    # Tool names (a trailing ``*`` matches any suffix) when one hook event is
    # split into rows by tool; empty when the row covers the whole event.
    tools: tuple[str, ...] = ()
    # The product surface (for example ``cli`` or ``cloud_agent``) when one
    # event is published as several rows by surface; ``None`` otherwise.
    surface: str | None = None
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
            **({"tools": list(self.tools)} if self.tools else {}),
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
