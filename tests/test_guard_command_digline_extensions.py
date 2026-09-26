"""Structured digline command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from tests.command_extension_contracts import (
    assert_safe_command_cases,
    enable_local_admin_extension_layer,
)
from tests.native_command_test_support import real_native_command_evaluation

_RUN_RULE = "command.digline.run"
_REJUDGE_RULE = "command.digline.rejudge"
_PROMOTE_RULE = "command.digline.promote"
_REGISTER_RULE = "command.digline.register"
_MIGRATE_RULE = "command.digline.migrate"
_VIEW_RULE = "command.digline.view"
_DIGLINE_RULES = frozenset({_RUN_RULE, _REJUDGE_RULE, _PROMOTE_RULE, _REGISTER_RULE, _MIGRATE_RULE, _VIEW_RULE})

DIGLINE_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "digline run --suite evals/suite.py",
        "digline suite run command",
        _RUN_RULE,
    ),
    (
        "digline run --suite evals/suite.py --resume",
        "digline suite run command",
        _RUN_RULE,
    ),
    (
        "digline run --suite evals/suite.py --resume 20260924T101500Z",
        "digline suite run command",
        _RUN_RULE,
    ),
    (
        "digline rejudge --suite evals/suite.py --run 20260924T101500Z",
        "digline rejudge command",
        _REJUDGE_RULE,
    ),
    (
        "digline rejudge --suite evals/suite.py --run 20260924T101500Z --judge-samples 3",
        "digline rejudge command",
        _REJUDGE_RULE,
    ),
    (
        "digline promote --suite evals/suite.py --run 20260924T101500Z",
        "digline baseline promotion command",
        _PROMOTE_RULE,
    ),
    (
        "digline register --suite evals/suite.py --run 20260924T101500Z --disposition accepted",
        "digline disposition record command",
        _REGISTER_RULE,
    ),
    (
        "digline migrate --suite evals/suite.py",
        "digline store migration command",
        _MIGRATE_RULE,
    ),
    (
        "digline migrate --suite evals/suite.py $DRY_RUN",
        "digline store migration command",
        _MIGRATE_RULE,
    ),
    (
        "digline migrate --suite evals/suite.py --unknown-flag --dry-run",
        "digline store migration command",
        _MIGRATE_RULE,
    ),
    (
        "digline view --suite evals/suite.py",
        "digline review UI command",
        _VIEW_RULE,
    ),
    (
        "digline view --suite evals/suite.py --host 127.0.0.1 --port 7373",
        "digline review UI command",
        _VIEW_RULE,
    ),
    (
        "python -m digline.cli promote --suite evals/suite.py --run 20260924T101500Z",
        "digline baseline promotion command",
        _PROMOTE_RULE,
    ),
    (
        "python3 -m digline.cli run --suite evals/suite.py",
        "digline suite run command",
        _RUN_RULE,
    ),
)

# Forms the command parser does not yet normalize; each must stay uncertain for the stated reason.
DIGLINE_UNCERTAIN_CASES: tuple[tuple[str, str], ...] = (
    (
        "exec digline promote --suite evals/suite.py --run 20260924T101500Z",
        "nested_command_executor_not_yet_supported",
    ),
    (
        "xargs -n 1 digline rejudge --suite evals/suite.py",
        "nested_command_executor_not_yet_supported",
    ),
)


def test_digline_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    commands = [command for command, _action_class, _rule_id in DIGLINE_REVIEW_CASES]
    commands.extend(command for command, _reason in DIGLINE_UNCERTAIN_CASES)
    for command in commands:
        evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert evaluation.controlling_rule_id not in _DIGLINE_RULES, command
        assert all(item.extension.extension_id != "command.digline" for item in evaluation.extension_observations)


def test_enabled_digline_writes_and_spending_reach_review(tmp_path: Path) -> None:
    for command, action_class, rule_id in DIGLINE_REVIEW_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.digline"),),
        )
        assert evaluation.evaluation.command.confidence == "exact", command
        matched = {
            item.rule.rule_id
            for item in evaluation.evaluation.extension_observations
            if item.extension.extension_id == "command.digline"
        }
        assert rule_id in matched, command
        assert evaluation.evaluation.controlling_rule_id == rule_id, command
        assert any(item.match.action_class == action_class for item in evaluation.evaluation.matches), command
        assert evaluation.native_minimum_action == "review", command


def test_enabled_digline_declared_uncertain_forms_stay_uncertain(tmp_path: Path) -> None:
    for command, reason in DIGLINE_UNCERTAIN_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.digline"),),
        ).evaluation
        assert evaluation.command.confidence != "exact", command
        assert evaluation.command.uncertainty_reason == reason, command


DIGLINE_SAFE_COMMANDS: tuple[str, ...] = (
    "digline compare --suite evals/suite.py --run 20260924T101500Z",
    "digline diff --suite evals/suite.py 20260924T101500Z 20260924T111500Z",
    "digline explain --suite evals/suite.py --run 20260924T101500Z",
    "digline log --suite evals/suite.py --since 2026-09-14",
    "digline list --suite evals/suite.py",
    "digline report --suite evals/suite.py --run 20260924T101500Z --locale en",
    "digline report --suite evals/suite.py --run 20260924T101500Z --locale en --out report.html",
    "digline migrate --suite evals/suite.py --dry-run",
    "digline --help",
    "digline --version",
    "digline run --help",
    "digline rejudge --help",
    "digline promote --help",
    "digline register --help",
    "digline migrate --help",
    "digline view --help",
    "echo digline promote --suite evals/suite.py --run 20260924T101500Z",
)


def test_digline_read_preview_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(DIGLINE_SAFE_COMMANDS, tmp_path)


def test_enabled_digline_read_preview_and_help_commands_do_not_review(tmp_path: Path) -> None:
    for command in DIGLINE_SAFE_COMMANDS:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.digline"),),
        ).evaluation
        assert evaluation.controlling_rule_id not in _DIGLINE_RULES, command
        assert all(
            not item.effective_evidence
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.digline"
        ), command


def test_digline_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.digline")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
