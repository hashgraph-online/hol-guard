"""Structured FlashPilot command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from tests.command_extension_contracts import (
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

FLASHPILOT_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "flashpilot-bridge odin-flash target pit part image",
        "FlashPilot firmware flashing command",
        "command.flashpilot.destructive-flash",
    ),
    (
        "flashpilot-bridge mtk-flash-part target da part=file",
        "FlashPilot firmware flashing command",
        "command.flashpilot.destructive-flash",
    ),
    (
        "flashpilot-bridge qcom-flash-one target part image 0 100",
        "FlashPilot firmware flashing command",
        "command.flashpilot.destructive-flash",
    ),
    (
        "flashpilot-bridge spd-flash target fdl1 0x8000 part=file",
        "FlashPilot firmware flashing command",
        "command.flashpilot.destructive-flash",
    ),
)


def test_flashpilot_destructive_commands_require_review(tmp_path: Path) -> None:
    assert_reviewed_command_cases(FLASHPILOT_REVIEW_CASES, tmp_path)


FLASHPILOT_SAFE_COMMANDS: tuple[str, ...] = (
    "flashpilot-bridge detect",
    "flashpilot-bridge adb-devices",
    "flashpilot-bridge odin-pit target",
    "flashpilot-bridge mtk-detect",
    "flashpilot-bridge qcom-detect",
    "flashpilot-bridge spd-detect",
)


def test_flashpilot_preview_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(FLASHPILOT_SAFE_COMMANDS, tmp_path)


def test_flashpilot_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.flashpilot")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
