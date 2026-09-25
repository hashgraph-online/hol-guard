"""Structured claude-tmux cleanup command extension tests."""

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
from tests.native_command_test_support import real_native_command_evaluation

_EXTENSION = "command.claude-tmux"
_TEARDOWN_ACTION = "claude tmux session teardown command"
_PRUNE_ACTION = "claude tmux process prune command"
_TEARDOWN_RULE = "command.claude-tmux.session-teardown"
_PRUNE_RULE = "command.claude-tmux.process-prune"
_SENSITIVE_TOKENS = ("api", "notes", "consent.txt")

# Every kill in the tool is gated by one confirmation prompt, so each case here
# is a run that answers that prompt without a person: --force, or a pipeline
# feeding the prompt its consent.
CLAUDE_TMUX_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("ctc --all --force", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("claude-tmux-cleanup --all --force", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("ctc --all --force --prune", _PRUNE_ACTION, _PRUNE_RULE),
    # No target and no selection flag is the widest form: the interactive sweep
    # with every prompt answered for you.
    ("ctc --force", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("ctc -f", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("ctc -af", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("ctc -afp", _PRUNE_ACTION, _PRUNE_RULE),
    ("ctc --force --all", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("ctc api --all --force", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("ctc --force api --prune", _PRUNE_ACTION, _PRUNE_RULE),
    ("yes | ctc --all", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("yes | ctc --all --prune", _PRUNE_ACTION, _PRUNE_RULE),
    ("echo y | ctc api", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("yes | cat | ctc --all", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("yes | cat - | ctc --all", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("echo yes | ctc --all", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    # The minimal forms: with no selection flag the run is the interactive
    # sweep, and fed consent answers its prompt for every session.
    ("yes | ctc", _TEARDOWN_ACTION, _TEARDOWN_RULE),
    ("yes | ctc --prune", _PRUNE_ACTION, _PRUNE_RULE),
)


def test_claude_tmux_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in CLAUDE_TMUX_REVIEW_CASES:
        evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != _EXTENSION for item in evaluation.extension_observations)


def test_enabled_extension_controls_the_documented_shapes(tmp_path: Path) -> None:
    """Once enabled, each unattended shape is owned by its rule."""
    for command, action_class, rule_id in CLAUDE_TMUX_REVIEW_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer(_EXTENSION),),
        ).evaluation
        matched = {
            item.rule.rule_id for item in evaluation.extension_observations if item.extension.extension_id == _EXTENSION
        }
        assert rule_id in matched, command
        assert evaluation.controlling_rule_id == rule_id
        assert any(item.match.action_class == action_class for item in evaluation.matches)


def test_enabled_prune_outranks_the_teardown_it_contains(tmp_path: Path) -> None:
    """A full sweep is both actions, and the one reaching past tmux controls the decision."""
    evaluation = real_native_command_evaluation(
        "ctc --all --force --prune",
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(enable_local_admin_extension_layer(_EXTENSION),),
    ).evaluation
    observed = {
        item.rule.rule_id for item in evaluation.extension_observations if item.extension.extension_id == _EXTENSION
    }

    assert observed == {_TEARDOWN_RULE, _PRUNE_RULE}
    assert evaluation.controlling_rule_id == _PRUNE_RULE


CLAUDE_TMUX_SAFE_COMMANDS: tuple[str, ...] = (
    # The preview lists sessions and pids and signals nothing.
    "ctc --dry-run",
    "ctc --all --force --dry-run",
    "ctc --all --force --prune --dry-run",
    "ctc -a -f -p -n",
    # Without --force the command stops on its confirmation prompt.
    "ctc",
    "ctc api",
    "ctc --all",
    "ctc --prune",
    "ctc --help",
    "claude-tmux-cleanup --help",
    "ctc --force --help",
    # A refusal is not consent, and neither is arbitrary piped data.
    "yes n | ctc --all",
    "cat notes | ctc --all",
    "echo | ctc --all",
    # An intervening command owns the consumer's stdin; earlier consent is not proof.
    "yes | printf n | ctc --all",
    # `&&` and `;` start their own execution context and share no stdin.
    "yes && ctc --all",
    "yes ; ctc --all",
    # The feed has to come before the cleanup, not after it.
    "ctc --all | yes",
    # The launcher is a different program and starts nothing destructive.
    "claude-tmux",
    "ct api",
    # Neither a mention of the command nor a grep for it is an invocation.
    "grep 'ctc --all --force --prune' docs",
    "echo ctc --all --force",
    # A lookalike name does not own these flags.
    "ctcx --all --force",
)


def test_claude_tmux_previews_and_prompted_runs_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(CLAUDE_TMUX_SAFE_COMMANDS, tmp_path)


def test_enabled_previews_and_prompted_runs_do_not_review(tmp_path: Path) -> None:
    for command in (
        "ctc --dry-run",
        "ctc --all --force --dry-run",
        "ctc --all --force --prune --dry-run",
        "ctc --all",
        "ctc --help",
        "ctc --force --help",
        "yes n | ctc --all",
        "cat notes | ctc --all",
    ):
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer(_EXTENSION),),
        ).evaluation
        assert evaluation.controlling_rule_id not in {_TEARDOWN_RULE, _PRUNE_RULE}, command


def test_redirect_fed_consent_defers_to_the_authoring_path(tmp_path: Path) -> None:
    """The parser refuses redirects, so a here-string never reaches native evaluation.

    The matcher reads an affirmative here-string, but a redirect leaves the model
    uncertain with no segments, so nothing is observed here and the command
    cannot be reported as safe either. This fails loudly if the parser later
    admits redirects and the two paths are left to disagree.
    """
    for command in ("ctc --all <<< y", "ctc --all < consent.txt"):
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer(_EXTENSION),),
        ).evaluation
        assert evaluation.command.confidence != "exact", command
        assert evaluation.command.uncertainty_reason == "command_redirect_not_yet_supported"


def test_claude_tmux_evidence_omits_session_names_and_raw_arguments(tmp_path: Path) -> None:
    evaluation = real_native_command_evaluation(
        "ctc api --all --force",
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(enable_local_admin_extension_layer(_EXTENSION),),
    ).evaluation
    matches = [item.match for item in evaluation.matches if item.extension.extension_id == _EXTENSION]
    assert matches
    serialized = json.dumps(
        [
            {
                "rule_id": match.rule.rule_id,
                "reason": match.reason,
                "action_class": match.action_class,
                "evidence": [item.to_dict() for item in match.matcher_evidence],
            }
            for match in matches
        ]
    )
    for token in _SENSITIVE_TOKENS:
        assert token not in serialized


def test_claude_tmux_extension_publishes_reference_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION)

    assert extension is not None
    assert extension.reference_urls == ("https://github.com/s403o/claude-code-tmux",)
    assert all(url.startswith("https://") for url in extension.reference_urls)
    assert risk_classes_for_command_action(_TEARDOWN_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_PRUNE_ACTION) == ("destructive_shell",)
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["activation"] == "opt-in"
    assert {rule["rule_id"] for rule in payload["rules"]} == {_TEARDOWN_RULE, _PRUNE_RULE}
