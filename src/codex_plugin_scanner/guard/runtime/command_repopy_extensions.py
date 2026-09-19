"""Repopy CLI safety extension rules and specifications."""

from __future__ import annotations

from .command_extension_matchers import executable_names
from .command_extension_specs import CommandExtensionSpec
from .command_operand_matchers import OperandGatedFlagMatcher
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    ExecutableMatcher,
)

_REPOPY_EXECUTABLES = executable_names("repopy")

_REPOPY_OPTIONS_WITH_VALUES = frozenset({"-t", "--theme", "-l", "--link", "-m", "--message"})

_REPOPY_INSTALL_LONG_MATCHER = OperandGatedFlagMatcher(
    executables=frozenset(_REPOPY_EXECUTABLES),
    required_flags=frozenset({"--install"}),
    options_with_values=_REPOPY_OPTIONS_WITH_VALUES,
    minimum_operands=2,
    forbidden_flags=frozenset({"-h", "--help"}),
    excluded_first_arguments=frozenset({"init", "link"}),
)

_REPOPY_INSTALL_SHORT_MATCHER = OperandGatedFlagMatcher(
    executables=frozenset(_REPOPY_EXECUTABLES),
    required_flags=frozenset({"-i"}),
    options_with_values=_REPOPY_OPTIONS_WITH_VALUES,
    minimum_operands=2,
    forbidden_flags=frozenset({"-h", "--help"}),
    excluded_first_arguments=frozenset({"init", "link"}),
)

_REPOPY_INSTALL_MATCHER = AnyMatcher(
    matchers=(
        _REPOPY_INSTALL_LONG_MATCHER,
        _REPOPY_INSTALL_SHORT_MATCHER,
    )
)

_REPOPY_LINK_SUBCOMMAND_MATCHER = ExecutableMatcher(
    executables=frozenset(_REPOPY_EXECUTABLES),
    subcommands=("link",),
    options_with_values=_REPOPY_OPTIONS_WITH_VALUES,
    forbidden_flags=frozenset({"-h", "--help"}),
)

_REPOPY_LINK_LONG_FLAG_MATCHER = OperandGatedFlagMatcher(
    executables=frozenset(_REPOPY_EXECUTABLES),
    required_flags=frozenset({"--link"}),
    options_with_values=_REPOPY_OPTIONS_WITH_VALUES,
    minimum_operands=1,
    forbidden_flags=frozenset({"-h", "--help"}),
    excluded_first_arguments=frozenset({"clone"}),
)

_REPOPY_LINK_SHORT_FLAG_MATCHER = OperandGatedFlagMatcher(
    executables=frozenset(_REPOPY_EXECUTABLES),
    required_flags=frozenset({"-l"}),
    options_with_values=_REPOPY_OPTIONS_WITH_VALUES,
    minimum_operands=1,
    forbidden_flags=frozenset({"-h", "--help"}),
    excluded_first_arguments=frozenset({"clone"}),
)

_REPOPY_LINK_MATCHER = AnyMatcher(
    matchers=(
        _REPOPY_LINK_SUBCOMMAND_MATCHER,
        _REPOPY_LINK_LONG_FLAG_MATCHER,
        _REPOPY_LINK_SHORT_FLAG_MATCHER,
    )
)

_REPOPY_INSTALL_RULE = CommandSafetyRule(
    rule_id="command.repopy.install",
    title="Repopy dependency installation",
    description="Identifies --install flag that automatically install dependencies from the cloned repository.",
    severity="high",
    risk_classes=("execution",),
    action_classes=("repopy install command",),
    safer_alternatives=("Run 'repopy clone <url> --no-install' to inspect dependencies safely before installation.",),
    default_mode="review",
    matcher=_REPOPY_INSTALL_MATCHER,
    example_command="repopy clone https://github.com/user/repo.git --install",
)

_REPOPY_LINK_RULE = CommandSafetyRule(
    rule_id="command.repopy.link",
    title="Repopy remote linkage",
    description=(
        "Identifies link command and flags that automatically stage, commit, "
        "and push work to newly initiated remote repository."
    ),
    severity="high",
    risk_classes=(
        "destructive_shell",
        "network_egress",
    ),
    action_classes=("repopy link command",),
    safer_alternatives=("Inspect staged changes with 'git status' and push explicitly via standard Git commands.",),
    default_mode="review",
    matcher=_REPOPY_LINK_MATCHER,
    example_command="repopy link https://github.com/user/repo.git",
)

REPOPY_COMMAND_RULES = (
    _REPOPY_INSTALL_RULE,
    _REPOPY_LINK_RULE,
)

REPOPY_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.repopy",
        name="Repopy CLI protection",
        description=(
            "Reviews repopy CLI operations across repository cloning, "
            "installations with build hooks and remote git linkage."
        ),
        action_classes=(
            "repopy install command",
            "repopy link command",
        ),
        risk_classes=(
            "destructive_shell",
            "execution",
            "network_egress",
        ),
        safer_alternatives=(
            "Run 'repopy clone <url> --no-install' to inspect dependencies safely before installation.",
            "Inspect staged changes with 'git status' and push explicitly via standard Git commands.",
        ),
        reference_urls=("https://pypi.org/project/repopy/", "https://github.com/manatunga/repopy"),
    ),
)
