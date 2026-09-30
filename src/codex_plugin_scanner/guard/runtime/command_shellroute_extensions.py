"""Opt-in shellroute routed execution, proxy lifecycle, and API key reveal protection."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_launcher_floors import XARGS_VALUE_OPTIONS
from .command_rules import AnyMatcher, CommandSafetyRule

# The direct launcher gets portable names from executable_matcher; wrapped
# launchers must spell them out because the wrapped name is matched literally.
# Process wrappers: the shellroute executable follows the wrapper and its options.
# exec -a takes the argv[0] value, setsid takes only switches, and xargs reuses
# Guard's shared launcher grammar so the two cannot drift apart.
_WRAPPER_PREFIXES: dict[str, frozenset[str]] = {
    "exec": frozenset({"-a"}),
    "setsid": frozenset(),
    "xargs": XARGS_VALUE_OPTIONS,
}
# npm-style runners name shellroute as the package to execute. These reach
# command.package.node for supply-chain review, which does not cover what the
# resulting shellroute command then does.
_RUNNER_PREFIXES: tuple[tuple[str, ...], ...] = (
    ("npx",),
    ("bunx",),
    ("pnpm",),
    ("yarn",),
    ("npm", "exec"),
    ("pnpm", "exec"),
    ("pnpm", "dlx"),
    ("yarn", "dlx"),
)
_RUNNER_OPTIONS_WITH_VALUES = frozenset(
    {"--cache", "--call", "--dir", "--filter", "--package", "--reporter", "--workspace", "-C", "-F", "-c", "-p", "-w"}
)
_RUNNER_FLAGS = frozenset(
    {"--aggregate-output", "--silent", "--stream", "--use-stderr", "--workspace-root", "--yes", "-y"}
)
# Each form is (tokens before the subcommand, leading options with values, leading flags).
_SHELLROUTE_LAUNCHERS: tuple[tuple[tuple[str, ...], frozenset[str], frozenset[str]], ...] = (
    (("shellroute",), frozenset(), frozenset()),
    *(
        ((wrapper, name), options, frozenset())
        for wrapper, options in _WRAPPER_PREFIXES.items()
        for name in sorted(executable_names("shellroute"))
    ),
    *(
        ((*runner, name), _RUNNER_OPTIONS_WITH_VALUES, _RUNNER_FLAGS)
        for runner in _RUNNER_PREFIXES
        for name in sorted(executable_names("shellroute"))
    ),
)
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
                *tokens,
                subcommand,
                global_options_with_values=_SHELLROUTE_GLOBAL_OPTIONS_WITH_VALUES | leading_options,
                global_flags=_SHELLROUTE_GLOBAL_FLAGS | leading_flags,
                allow_leading_options=len(tokens) > 1,
                leading_options_with_values=leading_options,
                options_with_values=options_with_values,
                fail_secure_unknown_options=True,
            )
            for tokens, leading_options, leading_flags in _SHELLROUTE_LAUNCHERS
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
        safer_alternatives=("Inspect running sessions with `shellroute status` before starting or stopping a proxy.",),
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
