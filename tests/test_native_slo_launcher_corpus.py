from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from scripts.native_slo_launcher_corpus import _selected, installed_expectation, validate_installed_response
from scripts.native_slo_workloads import ExpectedResponse, QualificationCase


def _case(harness: str = "codex", *, event: str = "PostToolUse", block: bool = False) -> QualificationCase:
    fields: dict[str, object] = {"policy_action": "allow", "hookSpecificOutput.hookEventName": event}
    if block:
        fields.update(
            decision="block",
            policy_action="block",
            model_output_action="block",
            reason_code="output_secret_match",
            **{"continue": True},
        )
    return QualificationCase(
        f"{harness}/{event}/{'block' if block else 'allow'}/1k",
        harness,
        event,
        event,
        "1k",
        {"hook_event_name": event},
        ExpectedResponse(
            "block" if block else "allow",
            "block" if block else "allow_original",
            "completed_block" if block else "benign",
            fields,
        ),
        "native_resident",
        "normal",
        "installed_canonical",
        1024,
        1200,
        "inline",
    )


def test_codex_delivered_projection_still_requires_the_native_route() -> None:
    case = installed_expectation(_case())
    response = {"hookSpecificOutput": {"hookEventName": "PostToolUse"}}
    validate_installed_response(case, response, "native_resident")
    with pytest.raises(AssertionError, match=":route"):
        validate_installed_response(case, response, "native_fail_safe")


def test_codex_filter_cannot_turn_a_block_into_allow() -> None:
    case = installed_expectation(_case(block=True))
    response = {"hookSpecificOutput": {"hookEventName": "PostToolUse"}, "decision": "block", "continue": True}
    validate_installed_response(case, response, "native_resident")
    with pytest.raises(AssertionError, match=":field:decision"):
        validate_installed_response(case, {**response, "decision": "allow"}, "native_resident")


@pytest.mark.parametrize(
    "extra", [{"policy_action": "allow"}, {"arbitrary": "value"}, {"approval_request_id": "fixture"}]
)
def test_codex_stdout_rejects_unrecognized_top_level_fields(extra: dict[str, str]) -> None:
    with pytest.raises(RuntimeError, match="stdout schema mismatch"):
        validate_installed_response(
            installed_expectation(_case()),
            {"hookSpecificOutput": {"hookEventName": "PostToolUse"}, **extra},
            "native_resident",
        )


def test_codex_post_stdout_rejects_pretool_permission_fields() -> None:
    with pytest.raises(RuntimeError, match="stdout schema mismatch"):
        validate_installed_response(
            installed_expectation(_case()),
            {"hookSpecificOutput": {"hookEventName": "PostToolUse", "permissionDecision": "allow"}},
            "native_resident",
        )


def test_claude_retains_its_semantic_metadata_contract() -> None:
    case = installed_expectation(_case("claude-code"))
    response = {"hookSpecificOutput": {"hookEventName": "PostToolUse"}, "policy_action": "allow"}
    validate_installed_response(case, response, "native_resident")
    with pytest.raises(AssertionError, match=":field:policy_action"):
        validate_installed_response(case, {"hookSpecificOutput": response["hookSpecificOutput"]}, "native_resident")


@pytest.mark.parametrize("surface", ["normalizer_only_not_installed", "transport_boundary", "preflight_only"])
def test_http_only_cases_cannot_be_relabelled_as_installed(surface: str) -> None:
    case = replace(_case(), surface=surface)
    assert not _selected(case)
    with pytest.raises(ValueError, match="not an installed registration"):
        installed_expectation(case)


def test_frozen_priority_selection_covers_all_sizes_and_source_refs(tmp_path: Path) -> None:
    from scripts.native_slo_workloads import build_cases

    cases = tuple(case for case in build_cases(tmp_path) if _selected(case))
    assert {case.size_class for case in cases} >= {"1k", "16k", "256k", "1m", "max", "empty"}
    assert any(case.payload_kind == "source_file_ref" for case in cases)
    assert {case.setup for case in cases} >= {"normal", "watch", "unavailable", "expired", "revoked", "integrity"}
    assert {(case.harness, case.event) for case in cases} == {
        (harness, event) for harness in ("codex", "claude-code") for event in ("PreToolUse", "PostToolUse")
    }
