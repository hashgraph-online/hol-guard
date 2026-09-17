"""Structured rules and metadata for Routed commands."""

from __future__ import annotations

from .command_common_extension_helpers import rule
from .command_extension_matchers import executable_matcher
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher

_ROUTED_GLOBAL_FLAGS = frozenset({"--json", "-q", "--quiet"})
_ROUTED_GLOBAL_OPTIONS = frozenset({"--host", "--workspace", "--filter"})
_ROUTED_FORBIDDEN_FLAGS = frozenset({"--help", "-h"})

ROUTED_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "routed adapter mutation command": ("destructive_shell",),
    "routed doctor reconciliation command": ("destructive_shell",),
    "routed uninstall command": ("destructive_shell",),
    "routed update command": ("execution", "network_egress"),
}


def _routed_matcher(
    *subcommands: str,
    required_flags: frozenset[str] = frozenset(),
    forbidden_flags: frozenset[str] = frozenset(),
) -> AnyMatcher:
    """Construct an AnyMatcher for the Routed CLI with optional subcommands and flag filters."""
    return AnyMatcher(
        matchers=(
            executable_matcher(
                "routed",
                *subcommands,
                required_flags=required_flags,
                forbidden_flags=_ROUTED_FORBIDDEN_FLAGS | forbidden_flags,
                global_flags=_ROUTED_GLOBAL_FLAGS,
                global_options_with_values=_ROUTED_GLOBAL_OPTIONS,
            ),
        )
    )


_ROUTED_DOCTOR_FIX = _routed_matcher("doctor", required_flags=frozenset({"--fix"}))
_ROUTED_ADAPTERS_INSTALL = _routed_matcher("adapters", "install")
_ROUTED_ADAPTERS_UNINSTALL = _routed_matcher("adapters", "uninstall")
_ROUTED_UNINSTALL = _routed_matcher("uninstall", forbidden_flags=frozenset({"--dry-run"}))
_ROUTED_UPDATE = AnyMatcher(
    matchers=(
        executable_matcher(
            "routed",
            "update",
            forbidden_flags=_ROUTED_FORBIDDEN_FLAGS | frozenset({"--check"}),
            global_flags=_ROUTED_GLOBAL_FLAGS,
            global_options_with_values=_ROUTED_GLOBAL_OPTIONS,
        ),
        executable_matcher(
            "routed",
            "upgrade",
            forbidden_flags=_ROUTED_FORBIDDEN_FLAGS | frozenset({"--check"}),
            global_flags=_ROUTED_GLOBAL_FLAGS,
            global_options_with_values=_ROUTED_GLOBAL_OPTIONS,
        ),
    )
)

ROUTED_COMMAND_RULES = (
    rule(
        rule_id="command.routed.doctor-fix",
        title="Routed doctor reconciliation",
        description="Identifies Routed doctor reconciliation commands that modify host configuration or adapters.",
        matcher=_ROUTED_DOCTOR_FIX,
        action_class="Routed doctor reconciliation command",
        risk_classes=("destructive_shell",),
        safer_alternative="Run routed doctor without --fix first to review diagnostics before repairing.",
        example_command="routed doctor --fix",
    ),
    rule(
        rule_id="command.routed.adapters-install",
        title="Routed adapter installation",
        description="Identifies host adapter installation across AI coding environments.",
        matcher=_ROUTED_ADAPTERS_INSTALL,
        action_class="Routed adapter mutation command",
        risk_classes=("destructive_shell",),
        safer_alternative="Review detected environments with routed adapters before installing new adapters.",
        example_command="routed adapters install",
    ),
    rule(
        rule_id="command.routed.adapters-uninstall",
        title="Routed adapter removal",
        description="Identifies host adapter removal from AI coding environments.",
        matcher=_ROUTED_ADAPTERS_UNINSTALL,
        action_class="Routed adapter mutation command",
        risk_classes=("destructive_shell",),
        safer_alternative="Check installed adapter status with routed adapters before uninstalling.",
        example_command="routed adapters uninstall cursor",
    ),
    rule(
        rule_id="command.routed.uninstall",
        title="Routed complete uninstallation",
        description="Identifies complete removal of Routed and its host environment adapters.",
        matcher=_ROUTED_UNINSTALL,
        action_class="Routed uninstall command",
        risk_classes=("destructive_shell",),
        safer_alternative="Run routed uninstall --dry-run first to preview changes before removing Routed.",
        example_command="routed uninstall",
    ),
    rule(
        rule_id="command.routed.update",
        title="Routed CLI update",
        description="Identifies in-place updates to the Routed CLI installation and binary.",
        matcher=_ROUTED_UPDATE,
        action_class="Routed update command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Run routed update --check to preview available updates before installing.",
        example_command="routed update",
    ),
)

ROUTED_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.routed",
        name="Routed command protection",
        description="Reviews host adapter changes, environment reconciliation, and updates through the Routed CLI.",
        action_classes=(
            "Routed adapter mutation command",
            "Routed doctor reconciliation command",
            "Routed uninstall command",
            "Routed update command",
        ),
        risk_classes=("destructive_shell", "execution", "network_egress"),
        safer_alternatives=(
            "Run routed doctor without --fix, routed uninstall with --dry-run, or routed update with --check to inspect state before applying changes.",
        ),
        reference_urls=("https://github.com/bshea-1/routed#readme",),
        ecosystem_ids=("routed",),
        executables=("routed",),
    ),
)
