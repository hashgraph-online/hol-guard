"""Frozen oracles must catch changed semantics, omitted fields and false route claims."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from dataclasses import replace
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
    availability_harness_response,
    recording_only_pre_tool_response,
)
from codex_plugin_scanner.guard.daemon.hook_worker_native import _watch_native_post_tool_result
from codex_plugin_scanner.guard.daemon.hook_worker_responses import (
    harness_json_from_native_post_tool,
    harness_json_from_native_pre_tool,
    harness_json_from_native_pre_tool_review,
)
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from codex_plugin_scanner.guard.runtime.source_paths import source_path_is_allowed
from scripts.native_slo_workloads import (
    QualificationCase,
    build_cases,
    configuration_text,
    corpus_manifest,
    installed_response_expectation,
    validate_case,
    validate_installed_response,
    validate_native_result,
    validate_setup,
)


@pytest.fixture(scope="module")
def cases(tmp_path_factory: pytest.TempPathFactory) -> tuple[QualificationCase, ...]:
    return build_cases(tmp_path_factory.mktemp("qualification-workspace"))


def _case(cases: tuple[QualificationCase, ...], case_id: str) -> QualificationCase:
    return next(case for case in cases if case.case_id == case_id)


def _delivered(case: QualificationCase) -> dict[str, object]:
    """Exercise existing renderers against independently frozen native vectors.

    This is a contract test, not evidence that installed native evaluation ran.
    Actual native computation, fault setup and route evidence belong to the
    paired driver and must pass the separate validators there.
    """

    if case.expected_http_status == 413:
        handler = object.__new__(_GuardDaemonHandler)
        handler.headers = Message()
        handler.headers["Content-Length"] = str(case.wire_bytes)
        _, error = handler._load_request_body()
        assert error == "request_body_too_large"
        return {"error": error}
    if case.native_expected is None:
        return availability_harness_response(
            case.payload,
            harness=case.harness,
            event_name=case.canonical_event,
            reason_code=case.expected.reason_code or "native_hook_event_unavailable",
            reason="Synthetic availability fixture",
        )
    native = {**case.native_expected.fields, "reason": "Synthetic completed native fixture"}
    if case.canonical_event == "PostToolUse":
        if case.setup == "watch":
            native = _watch_native_post_tool_result(native, case.payload)
        return harness_json_from_native_post_tool(case.harness, native)
    if case.setup == "watch":
        return recording_only_pre_tool_response(
            case.harness,
            reason_code=str(native["reason_code"]),
            reason="Synthetic observed native fixture",
        )
    if case.setup == "review_queue_failed":
        native.update(
            decision="deny", minimum_action="block", policy_action="block", reason_code="native_review_queue_failed"
        )
    if native.get("minimum_action") == "review":
        response = harness_json_from_native_pre_tool_review(
            case.harness,
            native,
            approval={"approval_url": "http://127.0.0.1:4781/requests/fixture", "request_id": "fixture"},
        )
        response["prompted"] = True
        return response
    return harness_json_from_native_pre_tool(case.harness, native)


def test_every_frozen_delivered_projection_matches_existing_contract(cases: tuple[QualificationCase, ...]) -> None:
    for case in cases:
        validate_case(case, _delivered(case), case.expected_route, http_status=case.expected_http_status)


def test_installed_surface_inventory_is_frozen_against_ownership_contract() -> None:
    root = Path(__file__).resolve().parents[1]
    ownership = json.loads((root / "docs/guard/contracts/hook-data-plane-ownership.v2.json").read_text())
    assert corpus_manifest()["harness_routes"] == ownership["harness_routes"]


def test_actual_cursor_and_copilot_aliases_are_present(cases: tuple[QualificationCase, ...]) -> None:
    actual = {(case.harness, case.event) for case in cases}
    assert {
        ("cursor", event)
        for event in (
            "beforeShellExecution",
            "beforeMCPExecution",
            "beforeReadFile",
            "beforeWriteFile",
            "afterShellExecution",
            "afterMCPExecution",
        )
    }.issubset(actual)
    assert {("copilot", "preToolUse"), ("copilot", "postToolUse")}.issubset(actual)
    for case in cases:
        if case.harness in {"cursor", "cline"} and case.canonical_event == "PostToolUse":
            assert not case.installed_enforcement
        if case.event in {"afterReadFile", "afterWriteFile", "pre-tool-use"}:
            assert case.surface == "normalizer_only_not_installed"
    assert not any(case.harness in {"antigravity", "gemini", "paseo"} for case in cases)


def test_file_and_mcp_aliases_are_real_actions(cases: tuple[QualificationCase, ...]) -> None:
    for event, expected_tool in (
        ("beforeReadFile", "Read"),
        ("beforeWriteFile", "Write"),
        ("beforeMCPExecution", "mcp__qualification__inspect"),
    ):
        selected = _case(cases, f"cursor/{event}/normal/small")
        assert selected.payload["tool_name"] == expected_tool
        assert "command" not in str(selected.payload["tool_input"])
        assert selected.expected.policy_action == "review"


def test_size_classes_measure_content_and_wire_bytes_separately(cases: tuple[QualificationCase, ...]) -> None:
    sizes = {"1k": 1024, "16k": 16384, "256k": 262144, "1m": 1048576, "max": 5242880}
    assert corpus_manifest()["size_bytes"] == sizes
    assert corpus_manifest()["http_body_bytes"] == _GuardDaemonHandler._MAX_BODY_BYTES == 1_000_000
    for case in cases:
        assert case.wire_bytes == len(json.dumps(case.payload, separators=(",", ":"), ensure_ascii=True).encode())
        if case.content_bytes:
            assert case.content_bytes == sizes[case.size_class]
        if case.semantic_sample:
            assert case.wire_bytes <= 1_000_000
            if case.content_bytes >= 1_048_576:
                assert case.payload_kind == "source_file_ref"
        if case.expected_http_status == 413:
            assert case.wire_bytes > 1_000_000
            assert not case.semantic_sample
            assert case.expected.reason_class == "http_body_limit"
            assert case.expected.model_action == "not_delivered"


def test_source_refs_bind_exact_shared_synthetic_content(cases: tuple[QualificationCase, ...]) -> None:
    paths: set[Path] = set()
    for case in cases:
        reference = case.payload.get("guard_source_ref")
        if not isinstance(reference, Mapping):
            continue
        path = Path(str(reference["path"]))
        paths.add(path)
        workspace = path.parent.parent
        assert source_path_is_allowed(str(path), cwd=workspace, home_dir=workspace).allowed
        body = path.read_bytes()
        assert len(body) == case.content_bytes
        assert len(body.decode("ascii")) == reference["output_chars"]
        if "source-digest-mismatch" not in case.case_id:
            assert hashlib.sha256(body).hexdigest() == reference["output_sha256"]
    assert len(paths) == 5  # benign/secret 1MiB and max, plus the 1KiB identity fault


def test_non_source_fixture_suffix_cannot_qualify_content_scanning(tmp_path: Path) -> None:
    directory = tmp_path / "native-qualification"
    directory.mkdir()
    for extension, allowed in (("txt", False), ("rs", True)):
        path = directory / ("benign." + extension)
        path.write_bytes(b"const guard_value = 1;\n")
        decision = source_path_is_allowed(str(path), cwd=tmp_path, home_dir=tmp_path)
        assert decision.allowed is allowed


def test_warm_fixture_reuse_does_not_change_source_identity(tmp_path: Path) -> None:
    first = build_cases(tmp_path)
    root = tmp_path / "native-qualification"
    stamps = {path.name: path.stat().st_mtime_ns for path in root.iterdir()}
    second = build_cases(tmp_path)
    assert first == second
    assert stamps == {path.name: path.stat().st_mtime_ns for path in root.iterdir()}


def test_changed_fixture_and_symlink_are_rejected(tmp_path: Path) -> None:
    build_cases(tmp_path)
    path = tmp_path / "native-qualification/benign-1k.rs"
    path.write_text("changed")
    with pytest.raises(ValueError, match="fixture_changed"):
        build_cases(tmp_path)
    path.unlink()
    target = tmp_path / "unchanged.txt"
    target.write_text("unchanged")
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable on this runner")
    with pytest.raises(ValueError, match="fixture_symlink"):
        build_cases(tmp_path)
    assert target.read_text() == "unchanged"


@pytest.mark.parametrize(
    "mutation", ("reason", "empty", "false_allow", "wrong_event", "numeric_continue", "unexpected_proof")
)
def test_validator_rejects_semantic_changes(cases: tuple[QualificationCase, ...], mutation: str) -> None:
    case = _case(cases, "claude-code/PreToolUse/dangerous/small")
    response = copy.deepcopy(_delivered(case))
    if mutation == "reason":
        response["reason_code"] = "native_pre_tool_unavailable"
    elif mutation == "empty":
        response = {}
    elif mutation == "false_allow":
        response["policy_action"] = "allow"
    elif mutation == "wrong_event":
        response["hookSpecificOutput"] = {"hookEventName": "PostToolUse", "permissionDecision": "deny"}
    elif mutation == "numeric_continue":
        response["continue"] = 1
    else:
        response["reviewed_output_sha256"] = "f" * 64
    with pytest.raises(AssertionError, match="native_qualification_mismatch"):
        validate_case(case, response, case.expected_route)


def test_validator_requires_post_allow_shape_even_without_reason_code(cases: tuple[QualificationCase, ...]) -> None:
    case = _case(cases, "claude-code/PostToolUse/benign/1k")
    assert case.expected.reason_code is None  # existing renderer omits it
    with pytest.raises(AssertionError):
        validate_case(case, {}, case.expected_route)
    with pytest.raises(AssertionError):
        validate_case(case, {**_delivered(case), "reason_code": "output_secret_match"}, case.expected_route)


def test_route_and_http_status_are_not_inferred_from_allow(cases: tuple[QualificationCase, ...]) -> None:
    case = _case(cases, "pi/PostToolUse/benign/1k")
    with pytest.raises(AssertionError, match=":route"):
        validate_case(case, _delivered(case), "python_semantic")
    bounded = next(case for case in cases if case.expected_http_status == 413)
    with pytest.raises(AssertionError, match=":http_status"):
        validate_case(bounded, _delivered(bounded), "engine_bypassed")


def test_watch_native_deny_and_delivered_allow_are_independent(cases: tuple[QualificationCase, ...]) -> None:
    case = _case(cases, "pi/PostToolUse/watch/1k")
    assert case.native_expected is not None
    assert case.native_expected.decision == "deny"
    assert case.expected.decision == "allow"
    assert case.expected.policy_action == "warn"
    # Independent resident-edge result, before Python Watch delivery. The
    # direct HookReviewRequestV1 observe transformation is a different route.
    native = {
        "decision": "deny",
        "model_output_action": "block",
        "policy_action": "block",
        "reason_code": "output_secret_match",
    }
    validate_native_result(case, native)
    assert "observe_mode" not in case.native_expected.fields
    assert "observed_policy_action" not in case.native_expected.fields
    delivered = _delivered(case)
    validate_case(case, delivered, case.expected_route)
    with pytest.raises(AssertionError):
        validate_native_result(case, delivered)
    with pytest.raises(AssertionError):
        validate_case(case, native, case.expected_route)
    with pytest.raises(AssertionError):
        validate_native_result(case, {**native, "reason_code": "observe_output_secret_match"})


def test_unavailable_watch_and_integrity_have_different_results(cases: tuple[QualificationCase, ...]) -> None:
    for label in ("unavailable", "watch_unavailable", "expired", "revoked"):
        case = _case(cases, f"grok/PreToolUse/{label}/small")
        assert case.expected.decision == "allow"
        assert case.expected.policy_action == "warn"
        assert not case.semantic_sample
    for label in ("integrity", "queue_bytes"):
        case = _case(cases, f"grok/PreToolUse/{label}/small")
        assert case.expected.decision == "deny"
        assert case.expected.policy_action == "block"
    permission = _case(cases, "copilot/permissionRequestV2/unavailable/small")
    assert permission.expected.fields["behavior"] == "deny"
    assert permission.expected.fields["interrupt"] is False


def test_setup_requires_observed_state_not_a_label(cases: tuple[QualificationCase, ...]) -> None:
    case = _case(cases, "grok/PreToolUse/expired/small")
    with pytest.raises(AssertionError, match="setup_unproven"):
        validate_setup(case, {"setup": "expired"})
    requirements = corpus_manifest()["setup_requirements"]
    assert isinstance(requirements, dict)
    evidence: dict[str, object] = dict.fromkeys(requirements[case.setup], True)
    validate_setup(case, evidence)
    evidence["expired_resident_authority"] = 1
    with pytest.raises(AssertionError, match="expired_resident_authority"):
        validate_setup(case, evidence)


def test_review_cannot_pass_without_a_resolvable_approval(cases: tuple[QualificationCase, ...]) -> None:
    case = _case(cases, "claude-code/PreToolUse/review/small")
    response = _delivered(case)
    response.pop("approval_url")
    with pytest.raises(AssertionError, match="missing:approval_url"):
        validate_case(case, response, case.expected_route)
    failed = _case(cases, "claude-code/PreToolUse/review-queue-failed/small")
    assert failed.expected.reason_code == "native_review_queue_failed"
    assert failed.native_expected is not None
    assert failed.native_expected.reason_code == "native_command_review_required"


def test_explicit_configuration_and_case_bound(cases: tuple[QualificationCase, ...]) -> None:
    assert 300 < len(cases) < 2_048
    assert len({case.case_id for case in cases}) == len(cases)
    assert 'mode = "observe"' in configuration_text("watch")
    assert 'mode = "enforce"' in configuration_text("normal")
    with pytest.raises(ValueError, match="setup_unknown"):
        configuration_text("invented")
    sample = _case(cases, "grok/PreToolUse/unavailable/small")
    with pytest.raises(AssertionError, match="unexpected_native_result"):
        validate_native_result(sample, {"decision": "allow"})
    with pytest.raises(AssertionError, match="missing_native_result"):
        validate_native_result(replace(sample, native_expected=cases[0].native_expected), None)


def test_cursor_wrapper_observers_do_not_claim_output_enforcement(cases: tuple[QualificationCase, ...]) -> None:
    case = _case(cases, "cursor/afterShellExecution/block/1k")
    assert case.expected.model_action == "block"  # daemon result
    wrapper, code = installed_response_expectation(case)
    assert wrapper.model_action == "unreviewed_original"
    assert code == 0
    validate_installed_response(case, {}, 0)
    with pytest.raises(AssertionError):
        validate_installed_response(case, {"decision": "block"}, 0)
    with pytest.raises(AssertionError, match="installed_exit"):
        validate_installed_response(case, {}, 2)


def test_cursor_read_review_uses_deny_while_shell_review_uses_ask(cases: tuple[QualificationCase, ...]) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hook_payload import cursor_hook_response_from_guard

    for case_id, permission, code in (
        ("cursor/beforeReadFile/normal/small", "deny", 2),
        ("cursor/beforeWriteFile/normal/small", "ask", 0),
        ("cursor/beforeShellExecution/review/small", "ask", 0),
        ("cursor/beforeShellExecution/watch-dangerous/small", "allow", 0),
    ):
        case = _case(cases, case_id)
        response = cursor_hook_response_from_guard(
            policy_action=case.expected.policy_action or "allow",
            guard_payload=_delivered(case),
            hook_event_name=case.event,
        )
        assert response["permission"] == permission
        validate_installed_response(case, response, code)


def test_cline_post_context_is_observation_even_for_completed_block(cases: tuple[QualificationCase, ...]) -> None:
    from codex_plugin_scanner.guard.adapters.cline_bridge import cline_control_from_guard_output

    for label in ("benign", "block", "watch", "unavailable"):
        case = _case(cases, f"cline/PostToolUse/{label}/1k")
        response = cline_control_from_guard_output(json.dumps(_delivered(case)), event_name=case.canonical_event)
        validate_installed_response(case, response, 0)
        assert response["cancel"] is False
    unavailable = _case(cases, "pi/PostToolUse/benign/1k")
    with pytest.raises(ValueError, match="wrapper_oracle_unavailable"):
        installed_response_expectation(unavailable)
