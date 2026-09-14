"""Opt-in shellroute routed execution, proxy lifecycle, and API key reveal protection."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_SHELLROUTE_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("shellroute",),
    ("exec", "shellroute"),
    ("xargs", "shellroute"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})
# Persistent flags accepted before any subcommand.
_SHELLROUTE_GLOBAL_OPTIONS_WITH_VALUES = frozenset({"--api-key"})
_SHELLROUTE_GLOBAL_FLAGS = frozenset({"--skip-version-check"})
_SHELLROUTE_RUN_OPTIONS_WITH_VALUES = frozenset({"--country", "--city", "--iptype"})
_SHELLROUTE_PROXY_OPTIONS_WITH_VALUES = frozenset({"--country", "--city", "--iptype", "--format"})


def _subcommand_matcher(subcommand: str, options_with_values: frozenset[str]) -> AnyMatcher:
    """Match one shellroute subcommand through every supported launcher."""

    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                *launcher,
                subcommand,
                global_options_with_values=_SHELLROUTE_GLOBAL_OPTIONS_WITH_VALUES,
                global_flags=_SHELLROUTE_GLOBAL_FLAGS,
                allow_leading_options=launcher[0] in ("exec", "xargs"),
                leading_options_with_values=(
                    _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
                ),
                options_with_values=options_with_values,
                fail_secure_unknown_options=True,
            )
            for launcher in _SHELLROUTE_LAUNCHERS
        )
    )


# 1. run: opens a metered proxy session and executes the command after `--` through it
_SHELLROUTE_RUN = _subcommand_matcher("run", _SHELLROUTE_RUN_OPTIONS_WITH_VALUES)

# 2. proxy / proxy stop: starts a persistent local proxy session, or stops the ones tracked on this machine
_SHELLROUTE_PROXY = _subcommand_matcher("proxy", _SHELLROUTE_PROXY_OPTIONS_WITH_VALUES)

# 3. reveal-key: prints the stored account API key
_SHELLROUTE_REVEAL_KEY = _subcommand_matcher("reveal-key", frozenset())

SHELLROUTE_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "shellroute routed command execution": ("execution", "network_egress"),
    "shellroute proxy lifecycle command": ("destructive_shell", "network_egress"),
    "shellroute api key reveal": ("local_secret_read",),
}

SHELLROUTE_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.shellroute.run",
        example_command="shellroute run US -- curl https://example.com",
        title="shellroute routed command execution",
        description=(
            "Identifies `shellroute run`, which opens a metered proxy session and executes the command "
            "after `--` with its HTTP traffic routed through a proxy in the selected country."
        ),
        severity="medium",
        risk_classes=("execution", "network_egress"),
        action_classes=("shellroute routed command execution",),
        safer_alternatives=(
            "Check the available countries and the account balance first with `shellroute countries` "
            "and `shellroute balance`.",
            "Run the command without shellroute when it does not need a country-specific route.",
        ),
        matcher=_SHELLROUTE_RUN,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _SHELLROUTE_RUN,
                variant_id="help",
                title="shellroute run command help",
                flag="--help",
            ),
        ),
        compatibility_fallback=True,
    ),
    CommandSafetyRule(
        rule_id="command.shellroute.proxy",
        example_command="shellroute proxy --country DE",
        title="shellroute proxy start and stop",
        description=(
            "Identifies `shellroute proxy`, which starts a persistent metered local proxy session, and "
            "`shellroute proxy stop`, which stops the persistent proxy sessions tracked on this machine."
        ),
        severity="medium",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=("shellroute proxy lifecycle command",),
        safer_alternatives=(
            "Inspect running sessions with `shellroute status` before starting or stopping a proxy.",
        ),
        matcher=_SHELLROUTE_PROXY,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _SHELLROUTE_PROXY,
                variant_id="help",
                title="shellroute proxy command help",
                flag="--help",
            ),
        ),
        compatibility_fallback=True,
    ),
    CommandSafetyRule(
        rule_id="command.shellroute.reveal-key",
        example_command="shellroute reveal-key",
        title="shellroute API key reveal",
        description="Identifies `shellroute reveal-key`, which prints the stored account API key to the terminal.",
        severity="high",
        risk_classes=("local_secret_read",),
        action_classes=("shellroute API key reveal",),
        safer_alternatives=(
            "Give automation the key through the platform's secret store as `SHELLROUTE_API_KEY` "
            "instead of printing it in a session.",
        ),
        matcher=_SHELLROUTE_REVEAL_KEY,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _SHELLROUTE_REVEAL_KEY,
                variant_id="help",
                title="shellroute reveal-key command help",
                flag="--help",
            ),
        ),
        compatibility_fallback=True,
    ),
)

SHELLROUTE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.shellroute",
        name="shellroute proxied execution protection",
        description=(
            "Reviews shellroute routed command execution, persistent proxy start and stop, and API key "
            "reveal while leaving status, balance, and country listings automatic."
        ),
        action_classes=(
            "shellroute routed command execution",
            "shellroute proxy lifecycle command",
            "shellroute API key reveal",
        ),
        risk_classes=("destructive_shell", "execution", "local_secret_read", "network_egress"),
        safer_alternatives=(
            "Check status, balance, and countries before routing traffic, and keep the API key in a secret store.",
        ),
        reference_urls=("https://github.com/shellroute/shellroute-cli",),
    ),
)
