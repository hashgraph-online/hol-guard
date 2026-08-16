from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.cli.commands_support_command_activity as command_activity
import codex_plugin_scanner.guard.native_command_model as native_command_model
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION,
    CommandShadowCohort,
    CommandShadowProposal,
)

_OCCURRED_AT = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
_NATIVE_PROPOSAL_VERSION = "guard.command-shadow-proposal.rust-parser.v1"


def _native_payload(command: str) -> dict[str, object]:
    payload = parse_shell_command(command).to_dict()
    payload["parser_profile"] = "posix-simple-v1"
    return payload


def test_exact_native_parse_builds_python_rule_shadow_proposal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = "git push origin main --force"
    expected = evaluate_command(command)
    monkeypatch.setattr(
        native_command_model,
        "review_command_model_native",
        lambda *_args, **_kwargs: _native_payload(command),
    )

    proposal = native_command_model.native_command_shadow_proposal(
        command,
        guard_home=tmp_path,
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert proposal is not None
    assert proposal.version == _NATIVE_PROPOSAL_VERSION
    assert proposal.cohorts == frozenset({CommandShadowCohort.BASELINE})
    assert proposal.decision == expected.decision_plane


def test_unbound_or_inconsistent_native_parse_cannot_create_proposal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = "git push origin main --force"
    payload = _native_payload(command)
    segments = payload["segments"]
    assert isinstance(segments, list)
    segment = segments[0]
    assert isinstance(segment, dict)
    span = segment["span"]
    assert isinstance(span, dict)
    span["end"] = len(command) + 1
    monkeypatch.setattr(
        native_command_model,
        "review_command_model_native",
        lambda *_args, **_kwargs: payload,
    )

    assert (
        native_command_model.native_command_shadow_proposal(
            command,
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )

    mismatched = _native_payload(command)
    mismatched["normalized_text"] = "git status --short"
    monkeypatch.setattr(
        native_command_model,
        "review_command_model_native",
        lambda *_args, **_kwargs: mismatched,
    )
    assert (
        native_command_model.native_command_shadow_proposal(
            command,
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_uncertain_native_parse_does_not_create_shadow_proposal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = "echo $(uname)"
    payload = _native_payload(command)
    payload.update(
        {
            "segments": [],
            "confidence": "uncertain",
            "uncertainty_reason": "command_substitution_unsupported",
            "path_overridden": False,
        }
    )
    monkeypatch.setattr(
        native_command_model,
        "review_command_model_native",
        lambda *_args, **_kwargs: payload,
    )

    assert (
        native_command_model.native_command_shadow_proposal(
            command,
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_activity_shadow_prefers_native_proposal_without_changing_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = "git push origin main --force"
    evaluation = evaluate_command(command)
    native_proposal = CommandShadowProposal(
        decision=evaluation.decision_plane,
        cohorts=frozenset({CommandShadowCohort.BASELINE}),
        version=_NATIVE_PROPOSAL_VERSION,
    )
    monkeypatch.setattr(
        command_activity,
        "native_command_shadow_proposal",
        lambda *_args, **_kwargs: native_proposal,
    )

    observation, failed = command_activity._build_shadow_best_effort(
        evaluation=evaluation,
        command_text=command,
        guard_home=tmp_path,
        cwd=tmp_path,
        home_dir=tmp_path,
        policy_action="review",
        activity_id="activity:native-shadow-test",
        occurred_at=_OCCURRED_AT,
    )

    assert failed is False
    assert observation is not None
    assert observation.authoritative_action == "review"
    assert observation.proposal_version == _NATIVE_PROPOSAL_VERSION
    assert command not in repr(asdict(observation))


def test_native_shadow_exception_falls_back_to_existing_python_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = "git push origin main --force"
    evaluation = evaluate_command(command)

    def fail_native(*_args: object, **_kwargs: object) -> CommandShadowProposal | None:
        raise RuntimeError("synthetic native failure")

    monkeypatch.setattr(command_activity, "native_command_shadow_proposal", fail_native)

    observation, failed = command_activity._build_shadow_best_effort(
        evaluation=evaluation,
        command_text=command,
        guard_home=tmp_path,
        cwd=tmp_path,
        home_dir=tmp_path,
        policy_action="review",
        activity_id="activity:native-shadow-fallback",
        occurred_at=_OCCURRED_AT,
    )

    assert failed is False
    assert observation is not None
    assert observation.authoritative_action == "review"
    assert observation.proposal_version == COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION
