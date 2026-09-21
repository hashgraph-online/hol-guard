"""Structured HashDup command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)
from tests.native_command_test_support import real_native_command_evaluation

_DELETE_ACTION = "HashDup permanent deletion command"
_DELETE_RULE = "command.hashdup.delete"

HASHDUP_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("hashdup /workspace --delete", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup --delete /workspace", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup -d /workspace", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup /workspace -d", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup /workspace -a sha256 --delete", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup /workspace --algo md5 --delete", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup /workspace -t /tmp/trash --delete", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup /workspace --trash /tmp/trash --delete", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup /workspace --no-zero --delete", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup --unknown-flag /workspace --delete", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup /workspace --delete --unknown-flag", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup.exe /workspace --delete", _DELETE_ACTION, _DELETE_RULE),
    ("hashdup.cmd /workspace --delete", _DELETE_ACTION, _DELETE_RULE),
)

HASHDUP_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("xargs hashdup /workspace --delete", _DELETE_RULE),
    ("xargs -n 1 hashdup /workspace --delete", _DELETE_RULE),
    ("xargs -I {} hashdup {} --delete", _DELETE_RULE),
    ("exec hashdup /workspace --delete", _DELETE_RULE),
    ("exec hashdup --delete /workspace", _DELETE_RULE),
    ("xargs -n 1 hashdup --delete /workspace", _DELETE_RULE),
)


def test_hashdup_commands_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in HASHDUP_REVIEW_CASES:
        evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.hashdup" for item in evaluation.extension_observations)


def test_hashdup_direct_invocations_reach_review_when_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in HASHDUP_REVIEW_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            controls=(("extension", "command.hashdup", "enabled"),),
        ).evaluation
        observations = evaluation.extension_observations
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.hashdup"}
        assert rule_id in matched, command


def test_hashdup_wrapper_invocations_reach_review_or_uncertainty(tmp_path: Path) -> None:
    for command, expected_rule in HASHDUP_WRAPPER_REVIEW_COMMANDS:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            controls=(("extension", "command.hashdup", "enabled"),),
        ).evaluation
        if evaluation.command.confidence != "exact":
            assert evaluation.command.uncertainty_reason is not None
            continue
        observations = evaluation.extension_observations
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.hashdup"}
        assert expected_rule in matched, command


HASHDUP_SAFE_COMMANDS: tuple[str, ...] = (
    "hashdup /workspace",
    "hashdup /workspace -a sha256",
    "hashdup /workspace --algo md5",
    "hashdup /workspace -t /tmp/trash",
    "hashdup /workspace --trash /tmp/trash",
    "hashdup /workspace --no-zero",
    "hashdup --help",
    "hashdup -h",
    "hashdup --version",
    "hashdup -V",
    "hashdup /workspace --delete --help",
    "grep 'hashdup --delete' docs",
)


def test_hashdup_safe_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(HASHDUP_SAFE_COMMANDS, tmp_path)


def test_hashdup_extension_publishes_reference_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.hashdup")
    assert extension is not None
    assert extension.reference_urls == ("https://github.com/mahdyarmonfared/hashdup-cli",)
    assert risk_classes_for_command_action(_DELETE_ACTION) == ("destructive_shell",)
