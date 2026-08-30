"""Structured rules and metadata for Noodle commands."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_NOODLE_RUN = AnyMatcher(
    matchers=(
        executable_matcher("noodle", "request", "run"),
        executable_matcher("noodle", "collection", "run"),
    )
)

NOODLE_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.noodle.run",
        title="Noodle request execution",
        description="Identifies execution of one or more HTTP requests from a Noodle collection.",
        severity="high",
        risk_classes=("execution", "network_egress"),
        action_classes=("Noodle request execution command",),
        safer_alternatives=(
            "Inspect the resolved method, URL, environment, authentication, and selected targets before running.",
        ),
        matcher=_NOODLE_RUN,
        safe_variants=(safe_flag_variant(_NOODLE_RUN, variant_id="help", title="Command help", flag="--help"),),
        example_command="noodle request run users/get --collection ./my-api",
    ),
)

NOODLE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.noodle",
        name="Noodle command protection",
        description="Reviews request and collection execution through the Noodle terminal REST client.",
        action_classes=("Noodle request execution command",),
        risk_classes=("execution", "network_egress"),
        safer_alternatives=("Inspect the resolved requests and selected environment before execution.",),
        reference_urls=("https://github.com/wilfredinni/noodle",),
    ),
)
