"""Structured rules and metadata for the AgentBurp command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_AGENTBURP_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("agentburp",),
    ("agentburp.exe",),
)

_AGENTBURP_PROJECT_MODIFICATION = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "project",
            subcommand,
            allow_leading_options=False,
        )
        for launcher in _AGENTBURP_LAUNCHERS
        for subcommand in ("create", "open", "delete")
    )
)

AGENTBURP_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.agentburp.project-modify",
        title="AgentBurp project modification",
        description=(
            "Identifies AgentBurp commands that create, open, or delete a project."
        ),
        severity="medium",
        risk_classes=("data_modification",),
        action_classes=("agentburp project management command",),
        safer_alternatives=(
            "Use 'agentburp project list' to view existing projects before modifying.",
        ),
        matcher=_AGENTBURP_PROJECT_MODIFICATION,
        default_mode="review",
    ),
)

AGENTBURP_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.agentburp",
        name="AgentBurp command protection",
        description=(
            "Reviews AgentBurp commands that modify projects."
        ),
        action_classes=(
            "agentburp project management command",
        ),
        risk_classes=("data_modification",),
        safer_alternatives=(
            "Use 'agentburp project list' to view existing projects before modifying.",
        ),
        reference_urls=("https://github.com/msdbg/AgentBurp",),
    ),
)
