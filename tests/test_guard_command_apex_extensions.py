"""Structured apex command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)
from tests.native_command_test_support import real_native_command_evaluation

APEX_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "apex $ACTION ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex \"$ACTION\" ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex ${ACTION} ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex $(echo compress) ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex `echo compress` ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "python -m apex $ACTION ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "exec apex $ACTION ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs apex $ACTION ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex compress ./src -o backup.apx",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex c ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apexcompress compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "python -m apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex extract archive.apx -d ./out",
        "apex decompress command",
        "command.apex.decompress",
    ),
    (
        "apex x archive.apx",
        "apex decompress command",
        "command.apex.decompress",
    ),
    (
        "apex decompress archive.apx",
        "apex decompress command",
        "command.apex.decompress",
    ),
    (
        "apex repair damaged.apx",
        "apex repair command",
        "command.apex.repair",
    ),
    (
        "apex fix damaged.apx",
        "apex repair command",
        "command.apex.repair",
    ),
    (
        "exec apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "exec -c apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs -P 4 apex $ACTION ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex -t 4 $ACTION ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "python -m apex -t 4 $ACTION ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "exec apex -t 4 $ACTION ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs -P 4 apex -t 4 $ACTION ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex compress ./src $DEST",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "exec /usr/local/bin/apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs /usr/local/bin/apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "exec python -m apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs python -m apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs -p apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs -d , apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs -p python -m apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs -P 4 python -m apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "exec python -m apex $ACTION ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs python -m apex $ACTION ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "exec /usr/local/bin/apex decompress archive.apx",
        "apex decompress command",
        "command.apex.decompress",
    ),
    (
        "xargs /usr/local/bin/apex repair damaged.apx",
        "apex repair command",
        "command.apex.repair",
    ),
)


def test_apex_module_and_wrapper_invocations_reach_review(tmp_path: Path) -> None:
    """Indirect module and wrapper invocations reach review and attribute to apex rules."""
    for command, _action_class, expected_rule in APEX_REVIEW_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            controls=(("extension", "command.apex", "enabled"),),
        ).evaluation
        if evaluation.command.confidence != "exact":
            assert evaluation.command.uncertainty_reason is not None
            continue
        observations = evaluation.extension_observations
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.apex"}
        assert expected_rule in matched, f"{command} failed to match {expected_rule}"


def test_apex_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in APEX_REVIEW_CASES:
        evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.apex" for item in evaluation.extension_observations)


APEX_SAFE_COMMANDS: tuple[str, ...] = (
    "apex list",
    "apex test",
    "apex diff a.apx b.apx",
    "apex info",
    "apex benchmark f --full",
    "apex compress --help",
    "apex --help",
    "apex compress -h",
    "apex decompress --help",
    "apex repair --help",
)


def test_apex_preview_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(APEX_SAFE_COMMANDS, tmp_path)


def test_apex_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.apex")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)


def test_enabled_apex_mutating_commands_reach_review(tmp_path: Path) -> None:
    for command, _action_class, rule_id in APEX_REVIEW_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.apex", "enabled"),),
        ).evaluation
        if evaluation.command.confidence != "exact":
            assert evaluation.command.uncertainty_reason is not None
            continue
        assert evaluation.controlling_rule_id == rule_id


def test_enabled_apex_preview_and_help_commands_remain_safe(tmp_path: Path) -> None:
    for command in APEX_SAFE_COMMANDS:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.apex", "enabled"),),
        ).evaluation
        assert evaluation.controlling_rule_id not in {
            "command.apex.compress",
            "command.apex.decompress",
            "command.apex.repair",
        }
        assert all(
            not item.effective_evidence
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.apex"
        )


def test_apex_unresolved_expansion_matches_when_compress_permission_disabled(tmp_path: Path) -> None:
    """When compress permission is disabled, unresolved expansion still matches decompress and repair rules."""
    command = "apex $ACTION ./src"
    evaluation = real_native_command_evaluation(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        controls=(
            ("extension", "command.apex", "enabled"),
            ("permission", "command.apex.permission.compress", "disabled"),
        ),
    ).evaluation
    observed_rules = {
        item.rule.rule_id
        for item in evaluation.extension_observations
        if item.extension.extension_id == "command.apex" and item.effective_evidence
    }
    assert "command.apex.decompress" in observed_rules
    assert "command.apex.repair" in observed_rules


def test_apex_unresolved_expansion_matches_when_compress_and_decompress_disabled(tmp_path: Path) -> None:
    """When compress and decompress permissions are disabled, repair rule still observes unresolved expansion."""
    command = "apex $ACTION ./src"
    evaluation = real_native_command_evaluation(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        controls=(
            ("extension", "command.apex", "enabled"),
            ("permission", "command.apex.permission.compress", "disabled"),
            ("permission", "command.apex.permission.decompress", "disabled"),
        ),
    ).evaluation
    observed_rules = {
        item.rule.rule_id
        for item in evaluation.extension_observations
        if item.extension.extension_id == "command.apex" and item.effective_evidence
    }
    assert "command.apex.repair" in observed_rules

