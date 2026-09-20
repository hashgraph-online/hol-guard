"""Structured omairc command extension tests."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import (
    assert_safe_command_cases,
    enable_local_admin_extension_layer,
)

_SEND_ACTION = "Omairc message send command"
_RAISE_ACTION = "Omairc window raise command"
_SEND_RULE = "command.omairc.send"
_RAISE_RULE = "command.omairc.raise"
_SENSITIVE_TOKENS = ("#omarchy", "hello there", "abc", "secret-channel")

OMAIRC_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("omairc send '#omarchy' hello", _SEND_ACTION, _SEND_RULE),
    ("omairc send '#omarchy' 'hello there'", _SEND_ACTION, _SEND_RULE),
    ("omairc send --network abc '#omarchy' hello", _SEND_ACTION, _SEND_RULE),
    ("omairc send '#omarchy' --help", _SEND_ACTION, _SEND_RULE),
    ("omairc send -- '#omarchy' --version", _SEND_ACTION, _SEND_RULE),
    ("omairc send", _SEND_ACTION, _SEND_RULE),
    ("omairc send --unknown-flag '#omarchy' hello", _SEND_ACTION, _SEND_RULE),
    ("omairc.exe send '#omarchy' hello", _SEND_ACTION, _SEND_RULE),
    ("omairc.cmd send '#omarchy' hello", _SEND_ACTION, _SEND_RULE),
    ("omairc raise", _RAISE_ACTION, _RAISE_RULE),
    ("omairc.exe raise", _RAISE_ACTION, _RAISE_RULE),
    ("omairc.cmd raise", _RAISE_ACTION, _RAISE_RULE),
    ("omairc send '#omarchy' hello; omairc read --last 1", _SEND_ACTION, _SEND_RULE),
    ("omairc read --last 1; omairc send '#omarchy' hello", _SEND_ACTION, _SEND_RULE),
    ("omairc connections; omairc raise", _RAISE_ACTION, _RAISE_RULE),
    ("zsh -lc \"omairc send '#omarchy' hello\"", _SEND_ACTION, _SEND_RULE),
)

OMAIRC_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("exec omairc send '#omarchy' hello", _SEND_RULE),
    ("exec -a omairc omairc send '#omarchy' hello", _SEND_RULE),
    ("exec -a renamed /usr/local/bin/omairc send '#omarchy' hello", _SEND_RULE),
    ("xargs omairc send '#omarchy' hello", _SEND_RULE),
    ("xargs -n 1 omairc send '#omarchy' hello", _SEND_RULE),
    ("xargs -a input.txt omairc send '#omarchy' hello", _SEND_RULE),
    ("xargs --arg-file input.txt omairc send '#omarchy' hello", _SEND_RULE),
    ("exec /usr/local/bin/omairc send '#omarchy' hello", _SEND_RULE),
    ("exec omairc.exe send '#omarchy' hello", _SEND_RULE),
    ("xargs /usr/bin/omairc send '#omarchy' hello", _SEND_RULE),
    ("xargs omairc.cmd send '#omarchy' hello", _SEND_RULE),
    ("exec omairc raise", _RAISE_RULE),
    ("exec -a omairc omairc raise", _RAISE_RULE),
    ("xargs omairc raise", _RAISE_RULE),
    ("exec /usr/local/bin/omairc raise", _RAISE_RULE),
    ("xargs omairc.exe raise", _RAISE_RULE),
)

OMAIRC_SAFE_COMMANDS: tuple[str, ...] = (
    "omairc connections",
    "omairc list",
    "omairc status",
    "omairc status --network abc",
    "omairc names '#omarchy'",
    "omairc names --network abc '#omarchy'",
    "omairc read --last 20",
    "omairc read '#omarchy' --since 5m",
    "omairc read --unread",
    "omairc conversations",
    "omairc send --help",
    "omairc send --network abc --help",
    "omairc.exe send --help",
    "omairc.cmd send --help",
    "omairc raise --help",
    "omairc --help",
    "omairc --version",
    "echo omairc send '#omarchy' hello",
    "grep 'omairc send' docs",
    "notomairc send '#omarchy' hello",
)


def _enabled_evaluation(command: str, tmp_path: Path):
    return evaluate_command(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(enable_local_admin_extension_layer("command.omairc"),),
    )


def test_omairc_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in OMAIRC_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.omairc" for item in evaluation.extension_observations)


def test_enabled_omairc_send_and_raise_reach_review(tmp_path: Path) -> None:
    for command, action_class, rule_id in OMAIRC_REVIEW_CASES:
        evaluation = _enabled_evaluation(command, tmp_path)
        matched = {
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.omairc"
        }
        assert rule_id in matched, command
        assert evaluation.controlling_rule_id == rule_id
        assert any(item.match.action_class == action_class for item in evaluation.matches)
        assert evaluation.minimum_action in {"review", "block"}


def test_omairc_wrapper_invocations_reach_review(tmp_path: Path) -> None:
    for command, expected_rule in OMAIRC_WRAPPER_REVIEW_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.omairc"}
        assert expected_rule in matched, command


def test_omairc_read_status_names_and_connections_remain_automatic(tmp_path: Path) -> None:
    assert_safe_command_cases(OMAIRC_SAFE_COMMANDS, tmp_path)
    for command in (
        "omairc connections",
        "omairc list",
        "omairc status",
        "omairc names '#omarchy'",
        "omairc read --last 20",
        "omairc send --help",
        "omairc raise --help",
    ):
        evaluation = _enabled_evaluation(command, tmp_path)
        assert evaluation.controlling_rule_id not in {_SEND_RULE, _RAISE_RULE}
        assert all(
            not item.effective_evidence
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.omairc"
        )
        assert evaluation.minimum_action == "allow"


def test_enabled_omairc_send_uncertain_result_still_reviews(tmp_path: Path) -> None:
    """Malformed send quoting stays reviewable and never implies automatic safety."""

    command = "omairc send '#omarchy hello"
    parsed = parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert parsed.confidence != "exact"
    assert parsed.uncertainty_reason == "malformed_shell_quoting"

    evaluation = evaluate_command(
        command,
        canonical_command=parsed,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(enable_local_admin_extension_layer("command.omairc"),),
    )
    matched = {
        item.rule.rule_id
        for item in evaluation.extension_observations
        if item.extension.extension_id == "command.omairc" and item.effective_evidence
    }
    assert _SEND_RULE in matched
    assert evaluation.controlling_rule_id == _SEND_RULE
    assert evaluation.minimum_action in {"review", "block"}
    assert evaluation.minimum_action != "allow"
    assert evaluation.command.confidence != "exact"


def test_omairc_send_help_after_target_is_not_automatic(tmp_path: Path) -> None:
    evaluation = _enabled_evaluation("omairc send '#omarchy' --help", tmp_path)
    assert evaluation.controlling_rule_id == _SEND_RULE
    send_observations = [
        item
        for item in evaluation.extension_observations
        if item.extension.extension_id == "command.omairc" and item.rule.rule_id == _SEND_RULE
    ]
    assert send_observations
    assert send_observations[0].effective_evidence
    assert all(
        variant.variant_id != "help" or not variant.matcher_evidence for variant in send_observations[0].safe_variants
    )


def test_omairc_evidence_omits_targets_and_message_text(tmp_path: Path) -> None:
    command = "omairc send --network abc '#omarchy' 'hello there'"
    evaluation = _enabled_evaluation(command, tmp_path)
    omairc_matches = [item.match for item in evaluation.matches if item.extension.extension_id == "command.omairc"]
    assert omairc_matches
    serialized = json.dumps(
        [
            {
                "rule_id": match.rule.rule_id,
                "reason": match.reason,
                "action_class": match.action_class,
                "evidence": [item.to_dict() for item in match.matcher_evidence],
            }
            for match in omairc_matches
        ]
    )
    for token in _SENSITIVE_TOKENS:
        assert token not in serialized
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.omairc")
    assert extension is not None
    catalog = json.dumps(extension.to_dict())
    for token in ("#omarchy", "hello there"):
        assert token not in catalog
    for permission in extension.permissions:
        assert permission.example_command in {"omairc send", "omairc raise"}


def test_omairc_extension_publishes_reference_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.omairc")
    assert extension is not None
    assert extension.reference_urls == ("https://github.com/fredimachado/omairc",)
    assert all(url.startswith("https://") for url in extension.reference_urls)
    assert risk_classes_for_command_action(_SEND_ACTION) == ("network_egress",)
    assert risk_classes_for_command_action(_RAISE_ACTION) == ("execution",)
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["publisher"]["id"] == "community.fredimachado"
