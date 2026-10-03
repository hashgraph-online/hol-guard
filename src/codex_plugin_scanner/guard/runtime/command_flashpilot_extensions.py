"""Structured rules and metadata for FlashPilot firmware flashing command extensions."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_FLASH_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("flashpilot-bridge",),
    ("flashpilot",),
    ("python", "-m", "flashpilot"),
    ("python3", "-m", "flashpilot"),
)

_FLASHPILOT_DESTRUCTIVE_COMMANDS: tuple[str, ...] = (
    "odin-flash",
    "odin-flash-multi",
    "mtk-flash-firmware",
    "mtk-flash-part",
    "mtk-flash-samsung",
    "qcom-flash-one",
    "spd-flash",
)

_FLASHPILOT_MUTATION = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            subcommand,
            allow_leading_options=True,
            fail_secure_unknown_options=True,
        )
        for launcher in _FLASH_LAUNCHERS
        for subcommand in _FLASHPILOT_DESTRUCTIVE_COMMANDS
    )
)

FLASHPILOT_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.flashpilot.destructive-flash",
        title="FlashPilot firmware flashing command",
        description=(
            "Identifies FlashPilot destructive firmware writing commands "
            "(`odin-flash`, `mtk-flash-*`, `qcom-flash-one`, `spd-flash`), "
            "which overwrite device partition storage and require human review."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("FlashPilot firmware flashing command",),
        safer_alternatives=(
            "Verify device target and partition mappings before flashing.",
            "Ensure a full device backup is available prior to firmware writes.",
        ),
        matcher=_FLASHPILOT_MUTATION,
        default_mode="review",
    ),
)

FLASHPILOT_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.flashpilot",
        name="FlashPilot command protection",
        description=(
            "Reviews FlashPilot firmware flashing commands that write or overwrite "
            "device partition storage."
        ),
        action_classes=(
            "FlashPilot firmware flashing command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Verify device target and partition mappings before flashing.",
        ),
        reference_urls=("https://github.com/Legendary-Brilliantforous/flashpilot",),
    ),
)
