"""The edge answers a review's policy binding, retry binding and token; the pause only reads it."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_exact_action as exact


def _evidence(**overrides: object) -> dict[str, object]:
    return {"policy_binding_valid": True, "binding": "b", "token": "t", "once_only_reason": None, **overrides}


def test_the_edge_evidence_is_read_as_sent() -> None:
    assert exact.review_evidence_parts(_evidence()) == (True, "b", "t", None)
    once = _evidence(token=None, once_only_reason="compound_command")
    assert exact.review_evidence_parts(once) == (True, "b", None, "compound_command")


def test_the_resident_decides_the_policy_binding() -> None:
    rejected = _evidence(policy_binding_valid=False, binding=None, token=None, once_only_reason=exact.UNPROVEN_LAUNCH)
    assert exact.review_evidence_parts(rejected) == (False, None, None, exact.UNPROVEN_LAUNCH)


@pytest.mark.parametrize(
    "overrides",
    [
        {"token": None, "once_only_reason": None},
        {"token": "t", "once_only_reason": "compound_command"},
        {"token": None, "once_only_reason": "compound_command_allow"},
        {"token": "t", "once_only_reason": "allow"},
        {"token": 7, "once_only_reason": None},
    ],
)
def test_an_ambiguous_or_unknown_answer_stays_once_only(overrides: dict[str, object]) -> None:
    assert exact.review_evidence_parts(_evidence(**overrides)) == (True, "b", None, exact.UNPROVEN_LAUNCH)


@pytest.mark.parametrize("evidence", [None, {}, _evidence(policy_binding_valid="yes"), _evidence(binding=1)])
def test_missing_or_malformed_evidence_proves_nothing(evidence: Mapping[str, object] | None) -> None:
    assert exact.review_evidence_parts(evidence) is None


def _pause(
    review: Any,
    tmp_path: Path,
    native_result: Mapping[str, object],
    local_cli_rule: Mapping[str, object] | None = None,
    review_evidence: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return review.pause_native_pre_tool_for_approval(
        object(),
        harness="codex",
        payload={"tool_name": "Bash", "tool_input": {"command": "make build"}, "cwd": str(tmp_path)},
        native_result=native_result,
        native_receipt=None,
        workspace=tmp_path,
        guard_home=tmp_path / "guard-home",
        local_cli_rule=local_cli_rule,
        review_evidence=review_evidence,
    )


_REVIEW = {"decision": "deny", "minimum_action": "review", "policy_action": "review"}


def test_a_custom_block_settles_before_the_policy_binding_is_checked(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval as review

    # The verdict claims extension policy and no evidence proves it; the block
    # denies either way, so the binding is never read first.
    custom = {"blocked": True, "harness_response": {"decision": "deny", "source": "custom"}}
    response = _pause(review, tmp_path, {**_REVIEW, "command_extensions": {"uncertainty_count": 0}}, custom)

    assert response == {"decision": "deny", "source": "custom"}


def test_a_matching_custom_grant_settles_without_evidence(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval as review

    granted = {"decision": "allow"}

    assert _pause(review, tmp_path, _REVIEW, local_cli_rule={"blocked": True, "harness_response": granted}) is granted


@pytest.mark.parametrize("evidence", [None, _evidence(policy_binding_valid=False)])
def test_missing_or_rejected_evidence_is_denied_before_any_saved_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, evidence: Mapping[str, object] | None
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval as review

    monkeypatch.setattr(
        review, "native_saved_decision_response", lambda *_a, **_k: pytest.fail("no saved decision without a binding")
    )
    monkeypatch.setattr(review, "render_pre_tool", lambda _harness, verdict, **_k: dict(verdict))

    response = _pause(review, tmp_path, _REVIEW, review_evidence=evidence)

    assert response["reason_code"] == "native_review_policy_binding_invalid"
    assert response["policy_action"] == "block"
