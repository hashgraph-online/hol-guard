"""Structured Ollama CLI command extension tests."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from tests.command_extension_contracts import (
    assert_safe_command_cases,
    enable_local_admin_extension_layer,
)
from tests.native_command_test_support import real_native_command_evaluation, real_native_review_fixture

_PUSH_ACTION = "Ollama model publication command"
_RM_ACTION = "Ollama model removal command"
_PUSH_RULE = "command.ollama.push"
_RM_RULE = "command.ollama.rm"
_SENSITIVE_TOKENS = ("my-model", "alice/my-model", "llama3", "mistral", "example")

OLLAMA_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("ollama push my-model", _PUSH_ACTION, _PUSH_RULE),
    ("ollama push alice/my-model", _PUSH_ACTION, _PUSH_RULE),
    ("ollama push --insecure my-model", _PUSH_ACTION, _PUSH_RULE),
    ("ollama push my-model --insecure", _PUSH_ACTION, _PUSH_RULE),
    ("ollama.exe push my-model", _PUSH_ACTION, _PUSH_RULE),
    ("ollama.cmd push alice/my-model", _PUSH_ACTION, _PUSH_RULE),
    ('ollama push "alice/my-model"', _PUSH_ACTION, _PUSH_RULE),
    ("ollama push my-model --unknown-flag", _PUSH_ACTION, _PUSH_RULE),
    ("ollama push", _PUSH_ACTION, _PUSH_RULE),
    ("ollama push --insecure", _PUSH_ACTION, _PUSH_RULE),
    ("ollama rm llama3", _RM_ACTION, _RM_RULE),
    ("ollama rm", _RM_ACTION, _RM_RULE),
    ("ollama rm llama3 mistral", _RM_ACTION, _RM_RULE),
    ("ollama.exe rm llama3", _RM_ACTION, _RM_RULE),
    ("ollama.cmd rm llama3 mistral", _RM_ACTION, _RM_RULE),
    ("ollama rm llama3; ollama list", _RM_ACTION, _RM_RULE),
    ("ollama list; ollama push my-model", _PUSH_ACTION, _PUSH_RULE),
    ("zsh -lc 'ollama push my-model'", _PUSH_ACTION, _PUSH_RULE),
)


def test_ollama_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in OLLAMA_REVIEW_CASES:
        evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.ollama" for item in evaluation.extension_observations)


def test_enabled_ollama_publication_and_removal_reach_review(tmp_path: Path) -> None:
    for command, action_class, rule_id in OLLAMA_REVIEW_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.ollama"),),
        ).evaluation
        if evaluation.command.confidence != "exact":
            assert evaluation.command.uncertainty_reason == "transparent_wrapper_not_yet_supported"
            continue
        matched = {
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.ollama"
        }
        assert rule_id in matched, command
        assert evaluation.controlling_rule_id == rule_id
        assert any(item.match.action_class == action_class for item in evaluation.matches)


def test_registry_observations_attribute_push_and_rm(tmp_path: Path) -> None:
    for command, _action_class, expected_rule in OLLAMA_REVIEW_CASES:
        if command.startswith("zsh -lc"):
            fixture = real_native_review_fixture(
                command,
                controls=(("extension", "command.ollama", "enabled"),),
            )
            assert fixture.payload["command_extensions"]["evaluation_error"] == "native_command_evaluation_failed"
            assert fixture.payload["command_extensions"]["observations"] == []
            assert fixture.payload["command_model"]["uncertainty_reason"] == "transparent_wrapper_not_yet_supported"
            continue
        observations = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            controls=(("extension", "command.ollama", "enabled"),),
        ).evaluation.extension_observations
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ollama"}
        assert expected_rule in matched, command


OLLAMA_SAFE_COMMANDS: tuple[str, ...] = (
    "ollama list",
    "ollama ls",
    "ollama ps",
    "ollama show llama3",
    "ollama run llama3",
    "ollama --help",
    "ollama -h",
    "ollama push --help",
    "ollama push -h",
    "ollama rm --help",
    "ollama rm -h",
    "ollama pull my-model",
    "ollama create my-model",
    "ollama cp llama3 mistral",
    "echo ollama push my-model",
    "grep 'ollama push my-model' docs",
    "notollama push my-model",
    "ollama-cli push my-model",
)


def test_ollama_read_help_and_unrelated_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(OLLAMA_SAFE_COMMANDS, tmp_path)


def test_enabled_ollama_help_and_read_commands_do_not_review(tmp_path: Path) -> None:
    for command in (
        "ollama list",
        "ollama ps",
        "ollama show llama3",
        "ollama run llama3",
        "ollama --help",
        "ollama push --help",
        "ollama rm --help",
    ):
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.ollama"),),
        ).evaluation
        assert evaluation.controlling_rule_id not in {_PUSH_RULE, _RM_RULE}
        assert all(
            not item.effective_evidence
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.ollama"
        )


def test_independent_git_force_push_still_reviews_when_ollama_is_enabled(tmp_path: Path) -> None:
    command = "ollama push my-model && git push --force origin main"
    evaluation = real_native_command_evaluation(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(enable_local_admin_extension_layer("command.ollama"),),
    ).evaluation
    matched = {item.rule.rule_id for item in evaluation.extension_observations}
    assert {_PUSH_RULE, "command.git.force-push"} <= matched


def test_ollama_evidence_omits_model_names_and_raw_arguments(tmp_path: Path) -> None:
    command = "ollama push alice/my-model"
    evaluation = real_native_command_evaluation(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(enable_local_admin_extension_layer("command.ollama"),),
    ).evaluation
    ollama_matches = [item.match for item in evaluation.matches if item.extension.extension_id == "command.ollama"]
    assert ollama_matches
    serialized = json.dumps(
        [
            {
                "rule_id": match.rule.rule_id,
                "reason": match.reason,
                "action_class": match.action_class,
                "evidence": [item.to_dict() for item in match.matcher_evidence],
            }
            for match in ollama_matches
        ]
    )
    for token in _SENSITIVE_TOKENS:
        assert token not in serialized
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.ollama")
    assert extension is not None
    catalog = json.dumps(extension.to_dict())
    for token in ("alice/my-model", "llama3", "mistral"):
        assert token not in catalog
    for permission in extension.permissions:
        assert permission.example_command in {"ollama push", "ollama rm"}


def test_ollama_extension_publishes_references_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.ollama")
    assert extension is not None
    assert extension.reference_urls == (
        "https://github.com/ollama/ollama/blob/main/cmd/cmd.go",
        "https://docs.ollama.com/cli",
    )
    assert all(url.startswith("https://") for url in extension.reference_urls)
    assert risk_classes_for_command_action(_PUSH_ACTION) == ("network_egress",)
    assert risk_classes_for_command_action(_RM_ACTION) == ("destructive_shell",)
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["publisher"]["id"] == "community.kantorcodes"
