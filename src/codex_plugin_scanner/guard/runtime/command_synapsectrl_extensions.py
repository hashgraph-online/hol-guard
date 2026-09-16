"""Structured rules and metadata for the SynapseCTRL command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

# SynapseCTRL supports a console-script entry point and ``python -m synapsectrl``.
# The additional launchers below cover common Python and uv execution forms so
# agents cannot avoid the same policy simply by choosing a different launcher.
_SYNAPSECTRL_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("synapsectrl",),
    ("python", "-m", "synapsectrl"),
    ("python3", "-m", "synapsectrl"),
    ("py", "-m", "synapsectrl"),
    ("uv", "run", "synapsectrl"),
    ("uv", "run", "python", "-m", "synapsectrl"),
    ("uv", "run", "python3", "-m", "synapsectrl"),
    ("uv", "tool", "run", "synapsectrl"),
    ("uvx", "synapsectrl"),
    ("exec", "synapsectrl"),
    ("exec", "python", "-m", "synapsectrl"),
    ("exec", "python3", "-m", "synapsectrl"),
    ("exec", "py", "-m", "synapsectrl"),
    ("xargs", "synapsectrl"),
    ("xargs", "python", "-m", "synapsectrl"),
    ("xargs", "python3", "-m", "synapsectrl"),
    ("xargs", "py", "-m", "synapsectrl"),
)

_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})
_SYNAPSECTRL_GLOBAL_FLAGS = frozenset({"--json"})
_SYNAPSECTRL_GLOBAL_OPTIONS_WITH_VALUES = frozenset({"--port", "--timeout", "--connect-timeout"})


def _synapsectrl_matcher(*subcommands: str) -> AnyMatcher:
    """Match one SynapseCTRL command path through its supported launch forms."""

    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                *launcher,
                *subcommands,
                global_flags=_SYNAPSECTRL_GLOBAL_FLAGS,
                global_options_with_values=_SYNAPSECTRL_GLOBAL_OPTIONS_WITH_VALUES,
                allow_leading_options=launcher[0] in ("exec", "xargs"),
                leading_options_with_values=(
                    _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
                ),
            )
            for launcher in _SYNAPSECTRL_LAUNCHERS
        )
    )


_SYNAPSECTRL_SWITCH = _synapsectrl_matcher("switch")
_SYNAPSECTRL_HOOK_MUTATION = AnyMatcher(
    matchers=tuple(
        child
        for action in ("install", "repair", "uninstall")
        for child in _synapsectrl_matcher("hook", action).matchers
    )
)

SYNAPSECTRL_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.synapsectrl.switch",
        title="SynapseCTRL profile switch",
        description=(
            "Identifies `synapsectrl switch`, which changes the active software profile "
            "for a Razer Synapse device."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("SynapseCTRL profile switch command",),
        safer_alternatives=(
            "Inspect the current device and profile state with SynapseCTRL status, devices, or profiles first.",
        ),
        matcher=_SYNAPSECTRL_SWITCH,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _SYNAPSECTRL_SWITCH,
                variant_id="help",
                title="SynapseCTRL switch command help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.synapsectrl.hook-mutation",
        title="SynapseCTRL launch hook mutation",
        description=(
            "Identifies SynapseCTRL hook install, repair, and uninstall commands, "
            "which modify the persistent Synapse launch-hook setup."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("SynapseCTRL hook mutation command",),
        safer_alternatives=(
            "Run `synapsectrl hook status` first to inspect the current launch-hook state.",
        ),
        matcher=_SYNAPSECTRL_HOOK_MUTATION,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _SYNAPSECTRL_HOOK_MUTATION,
                variant_id="help",
                title="SynapseCTRL hook mutation command help",
                flag="--help",
            ),
        ),
    ),
)

SYNAPSECTRL_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.synapsectrl",
        name="SynapseCTRL command protection",
        description=(
            "Reviews SynapseCTRL commands that change the active Razer Synapse profile "
            "or modify the persistent Synapse launch hook."
        ),
        action_classes=(
            "SynapseCTRL profile switch command",
            "SynapseCTRL hook mutation command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Inspect device and profile state with SynapseCTRL's read-only commands before switching profiles.",
            "Inspect the launch-hook state with `synapsectrl hook status` before changing it.",
        ),
        reference_urls=("https://github.com/gabrielzv1233/SynapseCTRL",),
    ),
)
