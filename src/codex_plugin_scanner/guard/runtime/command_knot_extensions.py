"""Structured rules and metadata for the Knot synchronization tool extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_KNOT_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("knot",),
    ("exec", "knot"),
    ("xargs", "knot"),
)

_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})

_KNOT_INIT = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "init",
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=False,
        )
        for launcher in _KNOT_LAUNCHERS
    )
)

_KNOT_SYNC = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "sync",
            options_with_values=frozenset({"-c", "--config-path"}),
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=False,
        )
        for launcher in _KNOT_LAUNCHERS
    )
)

KNOT_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.knot.init",
        title="knot init",
        description="Identifies `knot init`, which initializes the configuration file with CLI.",
        severity="low",
        risk_classes=("destructive_shell",),
        action_classes=("knot initialization command",),
        # I don't think it's necessary to say explicitly to check .knot* folders,
        # because Knot itself asks if you are sure to rewrite existing configuration.
        safer_alternatives=(
            "Verify the current working directory, before initializing the configuration.",
        ),
        matcher=_KNOT_INIT,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(_KNOT_INIT, variant_id="help", title="knot init help", flag="--help"),
            safe_flag_variant(_KNOT_INIT, variant_id="help-short", title="knot init -h", flag="-h"),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.knot.sync",
        title="knot sync",
        description="Identifies `knot sync`, which synchronizes directory trees across configured knots.",
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("knot synchronization command",),
        safer_alternatives=(
            "Verify existing configuration, current and targeted environments.",
        ),
        matcher=_KNOT_SYNC,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(_KNOT_SYNC, variant_id="help", title="knot sync help", flag="--help"),
            safe_flag_variant(_KNOT_SYNC, variant_id="help-short", title="knot sync -h", flag="-h"),
        ),
    ),
)

KNOT_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.knot",
        name="knot command for directory synchronization",
        description="Reviews knot init and sync commands.",
        action_classes=(
            "knot initialization command",
            "knot synchronization command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Verify the working directory and target environments before running knot commands.",),
        reference_urls=("https://github.com/kyncl/knot",),
    ),
)
