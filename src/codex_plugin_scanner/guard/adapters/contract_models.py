"""Shared immutable harness setup and protection data contracts."""

from __future__ import annotations

from dataclasses import dataclass


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
