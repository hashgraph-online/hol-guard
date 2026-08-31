"""Structured Storage Clearer command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

STORAGE_CLEARER_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "./storage-clearer.sh run",
        "Storage Clearer cleanup command",
        "command.storage-clearer.cleanup",
    ),
    (
        "./storage-clearer.sh run A",
        "Storage Clearer cleanup command",
        "command.storage-clearer.cleanup",
    ),
    (
        "storage-clearer.sh run B",
        "Storage Clearer cleanup command",
        "command.storage-clearer.cleanup",
    ),
    (
        "storage-clearer.sh app-run A",
        "Storage Clearer cleanup command",
        "command.storage-clearer.cleanup",
    ),
    (
        "'/Applications/Storage Clearer.app/Contents/Resources/storage-clearer.sh' app-run B",
        "Storage Clearer cleanup command",
        "command.storage-clearer.cleanup",
    ),
)


def test_storage_clearer_cleanup_commands_feed_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(STORAGE_CLEARER_REVIEW_CASES, tmp_path)


STORAGE_CLEARER_SAFE_COMMANDS = (
    "./storage-clearer.sh",
    "./storage-clearer.sh audit",
    "./storage-clearer.sh explain all",
    "./storage-clearer.sh reason docker-build-cache",
    "./storage-clearer.sh plan A",
    "./storage-clearer.sh plan B",
    "./storage-clearer.sh explore docker",
    "./storage-clearer.sh app-data",
    "./storage-clearer.sh help",
    "./storage-clearer.sh version",
    "grep 'storage-clearer.sh run|storage-clearer.sh app-run' docs",
)


def test_storage_clearer_read_only_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(STORAGE_CLEARER_SAFE_COMMANDS, tmp_path)


def test_storage_clearer_extension_publishes_reference_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.storage-clearer")

    assert extension is not None
    assert extension.reference_urls == ("https://github.com/khiemnd777/storage-clearer/blob/main/storage-clearer.sh",)
    assert extension.executables == ("storage-clearer.sh",)
    assert all(value in extension.rules[0].description for value in ("Docker prune", "simctl", "tmutil"))
    assert risk_classes_for_command_action("Storage Clearer cleanup command") == ("destructive_shell",)
