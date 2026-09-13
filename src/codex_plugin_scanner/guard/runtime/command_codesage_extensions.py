"""Structured rules and metadata for CodeSage setup commands."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_SETUP_COMMANDS = (
    (
        "install-hooks",
        "CodeSage hook installation command",
        "Installs Git hooks for automatic CodeSage reindexing and optional repository leak checks.",
        frozenset({"--strict", "--with-leak-check"}),
        "Inspect existing Git hooks and review codesage install-hooks --help before installing hooks.",
        "codesage install-hooks",
    ),
    (
        "install",
        "CodeSage MCP registration command",
        "Writes CodeSage MCP registration to project-local or user-level agent configuration.",
        frozenset({"--global"}),
        "Review the target agent configuration and the scope of --global before registering CodeSage.",
        "codesage install codex",
    ),
    (
        "uninstall",
        "CodeSage MCP unregistration command",
        "Removes CodeSage MCP registration from project-local or user-level agent configuration.",
        frozenset({"--global"}),
        "Review the target agent configuration and the scope of --global before unregistering CodeSage.",
        "codesage uninstall codex",
    ),
)

CODESAGE_COMMAND_RULES = tuple(
    CommandSafetyRule(
        rule_id=f"command.codesage.{subcommand}",
        title=action_class,
        description=description,
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=(action_class,),
        safer_alternatives=(guidance,),
        matcher=AnyMatcher(
            matchers=(
                *help_matcher.matchers,
                executable_matcher(
                    "xargs",
                    "codesage",
                    subcommand,
                    global_flags=flags,
                    allow_leading_options=True,
                    leading_options_with_values=frozenset({"-n", "-P", "-I", "-L", "-s"}),
                    fail_secure_unknown_options=True,
                ),
            )
        ),
        default_mode="review",
        # xargs placeholders can replace help flags before CodeSage executes.
        safe_variants=(
            safe_flag_variant(help_matcher, variant_id="help", title="CodeSage command help", flag="--help"),
            safe_flag_variant(help_matcher, variant_id="short-help", title="CodeSage command help", flag="-h"),
        ),
        example_command=example,
    )
    for subcommand, action_class, description, flags, guidance, example in _SETUP_COMMANDS
    for help_matcher in (
        AnyMatcher(
            matchers=(
                executable_matcher("codesage", subcommand, global_flags=flags, fail_secure_unknown_options=True),
                executable_matcher(
                    "exec",
                    "codesage",
                    subcommand,
                    global_flags=flags,
                    allow_leading_options=True,
                    leading_options_with_values=frozenset({"-a"}),
                    fail_secure_unknown_options=True,
                ),
            )
        ),
    )
)

CODESAGE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.codesage",
        name="CodeSage Python reference rules",
        description=(
            "Python reference rules for CodeSage hook installation and MCP registration. "
            "Production native hooks do not consume these rules. "
            "Enabling the extension does not make doctor, status, or search automatic."
        ),
        action_classes=tuple(item[1] for item in _SETUP_COMMANDS),
        risk_classes=("destructive_shell",),
        safer_alternatives=tuple(item[4] for item in _SETUP_COMMANDS),
        reference_urls=("https://github.com/iliaal/codesage",),
        ecosystem_ids=("codesage",),
        executables=("codesage",),
    ),
)
