"""Structured blkcp command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)
from tests.native_command_test_support import real_native_command_evaluation

BLKCP_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "blkcp image.raw /dev/sda",
        "blkcp raw block device write command",
        "command.blkcp.device-write",
    ),
    (
        "blkcp /home/user/disk.img /dev/nvme0n1",
        "blkcp raw block device write command",
        "command.blkcp.device-write",
    ),
    (
        "blkcp backup.bin /dev/sdb1",
        "blkcp raw block device write command",
        "command.blkcp.device-write",
    ),
    (
        "blkcp disk.raw /dev/loop0",
        "blkcp raw block device write command",
        "command.blkcp.device-write",
    ),
    (
        "blkcp file1.bin file2.bin --force",
        "blkcp forced execution command",
        "command.blkcp.force",
    ),
    (
        "blkcp file1.bin file2.bin -f",
        "blkcp forced execution command",
        "command.blkcp.force",
    ),
    (
        "blkcp file1.bin file2.bin -b 1M --force",
        "blkcp forced execution command",
        "command.blkcp.force",
    ),
    (
        "blkcp file1.bin file2.bin -p -f",
        "blkcp forced execution command",
        "command.blkcp.force",
    ),
    (
        "blkcp -i file1.bin -o file2.bin --force",
        "blkcp forced execution command",
        "command.blkcp.force",
    ),
    (
        "blkcp -i file1.bin -o file2.bin -f",
        "blkcp forced execution command",
        "command.blkcp.force",
    ),
)


def test_blkcp_review_cases_reach_review_and_attribute(tmp_path: Path) -> None:
    """Target device writes and forced invocations trigger review."""

    for command, expected_action_class, expected_rule in BLKCP_REVIEW_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            controls=(("extension", "command.blkcp", "enabled"),),
        ).evaluation
        assert evaluation.command.confidence == "exact", (
            f"Expected exact confidence for command: {command}, got {evaluation.command.confidence} "
            f"({evaluation.command.uncertainty_reason})"
        )
        observations = evaluation.extension_observations
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.blkcp"}
        assert expected_rule in matched, f"Expected {expected_rule} in {matched} for command: {command}"
        action_classes = {
            cls
            for item in observations
            if item.extension.extension_id == "command.blkcp"
            for cls in item.rule.action_classes
        }
        assert expected_action_class in action_classes, (
            f"Expected {expected_action_class} in {action_classes} for command: {command}"
        )


BLKCP_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("exec blkcp file1.bin file2.bin --force", "command.blkcp.force"),
    ("exec blkcp file1.bin file2.bin -f", "command.blkcp.force"),
    ("xargs blkcp file1.bin file2.bin --force", "command.blkcp.force"),
    ("xargs -n 1 blkcp file1.bin file2.bin --force", "command.blkcp.force"),
    ("xargs -n 1 blkcp file1.bin file2.bin -f", "command.blkcp.force"),
)


def test_blkcp_wrapper_invocations_reach_review(tmp_path: Path) -> None:
    """Indirect shell wrapper invocations reach review and attribute to blkcp rules or trigger fail-safe review."""

    for command, expected_rule in BLKCP_WRAPPER_REVIEW_COMMANDS:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            controls=(("extension", "command.blkcp", "enabled"),),
        ).evaluation
        if evaluation.command.confidence == "exact":
            observations = evaluation.extension_observations
            matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.blkcp"}
            assert expected_rule in matched, f"Expected {expected_rule} in {matched} for command: {command}"
        else:
            assert evaluation.command.uncertainty_reason is not None
            assert evaluation.minimum_action in ("review", "block"), (
                f"Expected fail-safe review or block for uncertain wrapper command: {command}, got {evaluation.minimum_action}"
            )


def test_blkcp_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    """Rules do not fire when the extension is not enabled in controls."""

    for command, _action_class, rule_id in BLKCP_REVIEW_CASES:
        evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.blkcp" for item in evaluation.extension_observations)


BLKCP_SAFE_COMMANDS: tuple[str, ...] = (
    "blkcp file1.bin file2.bin",  # ordinary file-to-file copy stays safe
    "blkcp /tmp/source.img /home/user/target.img",
    "blkcp -i file1.bin -o file2.bin",
    "blkcp file1.bin file2.bin -b 1M",
    "blkcp file1.bin file2.bin -p",
    "blkcp file1.bin file2.bin -q",
    "blkcp file1.bin file2.bin --direct",
    "blkcp file1.bin file2.bin --nocache",
    "blkcp file1.bin file2.bin --hash",
    "blkcp --help",
    "blkcp -h",
    "blkcp --version",
    "blkcp -v",
)


def test_blkcp_file_copies_and_help_commands_remain_safe(tmp_path: Path) -> None:
    """Plain file-to-file copies and informational help/version commands stay safe."""

    assert_safe_command_cases(BLKCP_SAFE_COMMANDS, tmp_path)


def test_blkcp_extension_publishes_official_reference() -> None:
    """Extension metadata defines official repository references."""

    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.blkcp")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
