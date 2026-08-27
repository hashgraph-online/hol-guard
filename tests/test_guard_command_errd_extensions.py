"""Tests for the errd command safety extension."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command


def test_errd_extension_is_registered() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.errd")

    assert extension is not None
    assert extension.executables == ("errd",)
    assert extension.action_classes == ("errd local analysis command",)
    assert extension.risk_classes == ("local_secret_read",)
    assert extension.reference_urls == (
        "https://pypi.org/project/errd/",
        "https://github.com/Das-R10/errd",
    )
    assert [rule.rule_id for rule in extension.rules] == ["command.errd.analyze"]


def test_errd_analyze_is_registered_with_expected_rule(tmp_path: Path) -> None:
    payload = inspect_command(
        "errd analyze traceback.log",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert payload["status"] == "review"
    assert payload["controlling_rule_id"] == "command.errd.analyze"

    classification = payload["classification"]
    assert isinstance(classification, dict)
    assert classification["action_class"] == "errd local analysis command"

    assert "command.errd" in {
        extension["extension_id"]
        for extension in payload["extensions"]
        if isinstance(extension, dict)
    }


def test_errd_analyze_options_are_recognized(tmp_path: Path) -> None:
    commands = (
        "errd analyze traceback.log --budget 4000",
        "errd analyze traceback.log -b 4000",
        "errd analyze traceback.log --output ./context.md",
        "errd analyze traceback.log -o ./context.md",
        "errd analyze traceback.log --repo .",
        "errd analyze traceback.log -r .",
    )

    for command in commands:
        payload = inspect_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
        )

        assert payload["controlling_rule_id"] == "command.errd.analyze"


def test_errd_version_remains_informational(tmp_path: Path) -> None:
    payload = inspect_command(
        "errd version",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert payload["status"] == "no_match"
    assert payload["controlling_rule_id"] is None
