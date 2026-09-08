"""Opt-in essh execution and cache removal protection."""

from __future__ import annotations

from .command_database_matchers import LeadingSubcommandMatcher
from .command_extension_matchers import executable_names
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_ESSH_GLOBAL_OPTIONS = frozenset({"--theme"})
_ESSH_EXIT_ONLY_FLAGS = frozenset({"-h", "--help", "-V", "--version"})
_ESSH_GROUP_EXECUTION = LeadingSubcommandMatcher(
    executables=executable_names("essh"),
    subcommands=("run",),
    options_with_values=_ESSH_GLOBAL_OPTIONS,
    interleaved_options_with_values=_ESSH_GLOBAL_OPTIONS,
    forbidden_flags_before_delimiter=_ESSH_EXIT_ONLY_FLAGS,
)
_ESSH_CACHE_REMOVAL = AnyMatcher(
    matchers=tuple(
        LeadingSubcommandMatcher(
            executables=executable_names("essh"),
            subcommands=subcommands,
            options_with_values=_ESSH_GLOBAL_OPTIONS,
            interleaved_options_with_values=_ESSH_GLOBAL_OPTIONS,
            forbidden_flags_before_delimiter=_ESSH_EXIT_ONLY_FLAGS,
        )
        for subcommands in (("hosts", "remove"), ("keys", "remove"), ("workspace", "remove"))
    )
)

ESSH_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.remote.essh.group-execution",
        example_command="essh run web -- sudo systemctl restart api",
        title="essh host group execution",
        description="Identifies essh run invocations that execute a command across every host in a group.",
        matcher=_ESSH_GROUP_EXECUTION,
        action_classes=("essh group execution command",),
        safer_alternatives=(
            "Inspect the group membership with essh hosts list and run the command against a single host first.",
        ),
        severity="critical",
        risk_classes=("execution", "network_egress"),
        compatibility_fallback=True,
    ),
    CommandSafetyRule(
        rule_id="command.remote.essh.cache-removal",
        example_command="essh keys remove deploy-key",
        title="essh cached credential and host removal",
        description="Identifies essh remove verbs that delete cached hosts, keys, or saved workspaces.",
        matcher=_ESSH_CACHE_REMOVAL,
        action_classes=("essh cache removal command",),
        safer_alternatives=(
            "List the cached entry first with essh hosts list, essh keys list, or essh workspace list "
            "and confirm the name before removing it.",
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        compatibility_fallback=True,
    ),
)

ESSH_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.remote.essh",
        name="essh group execution and cache removal protection",
        description=(
            "Reviews essh invocations that execute commands across a host group or delete cached "
            "hosts, keys, and workspaces."
        ),
        action_classes=("essh group execution command", "essh cache removal command"),
        risk_classes=("destructive_shell", "execution", "network_egress"),
        safer_alternatives=("Inspect group membership and cached entries before running or removing anything.",),
        reference_urls=("https://github.com/matthart1983/essh",),
    ),
)
