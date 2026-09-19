"""Authenticated defaults keep post-tool output behind the same source fence."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from pathlib import Path
from types import MethodType, SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_worker as worker_module
from codex_plugin_scanner.guard.daemon import hook_worker_native
from codex_plugin_scanner.guard.daemon.hook_worker_responses import prepare_native_hook_policy
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge
from codex_plugin_scanner.guard.native_scoped_result import scoped_invocation_matches
from tests.test_native_scoped_result import _bound_result


def _post_result(*, observe: bool = False, deny: bool = False, source_ref: bool = False):
    edge, binding = _bound_result(observe=observe)
    action = "block" if deny else "allow"
    edge["event_name"] = "PostToolUse"
    edge["payload_kind"] = "source_file_ref" if source_ref else "inline"
    edge["policy_binding"]["selected_decision_id"] = None
    edge["observed_policy_action"] = action if observe else None
    result: dict[str, object] = {
        "decision": "deny" if deny else "allow",
        "model_output_action": "block" if deny else "allow_original",
        "notice": "warning" if deny else "none",
        "reason_code": "synthetic_output_block" if deny else "synthetic_output_allow",
        "policy_action": action,
    }
    if observe:
        result.update(observe_mode=True, observed_policy_action=action)
    edge["result"] = result
    edge["receipt"].update(
        event_name="PostToolUse",
        payload_kind=edge["payload_kind"],
        decision=result["decision"],
        model_output_action=result["model_output_action"],
        reason_code=result["reason_code"],
        policy_action=action,
        observed_policy_action=edge["observed_policy_action"],
    )
    edge["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(edge["receipt"])).hexdigest()
    return edge, binding


@pytest.mark.parametrize("observe", [False, True])
@pytest.mark.parametrize("deny", [False, True])
@pytest.mark.parametrize("source_ref", [False, True])
def test_post_defaults_require_exact_source_and_authenticated_receipt(
    observe: bool, deny: bool, source_ref: bool
) -> None:
    edge, binding = _post_result(observe=observe, deny=deny, source_ref=source_ref)
    assert _decode_edge(edge, snapshot_binding=binding) == edge
    assert _decode_edge(edge) is None
    for field in (
        "generation",
        "resident_generation",
        "source_input_digest",
        "policy_digest",
        "runtime_identity",
        "mode",
    ):
        wrong = dict(binding)
        wrong[field] = 17 if isinstance(wrong[field], int) else "f" * 64
        assert _decode_edge(edge, snapshot_binding=wrong) is None
    wrong = deepcopy(edge)
    wrong["policy_binding"]["selected_decision_id"] = 8
    assert _decode_edge(wrong, snapshot_binding=binding) is None
    for field, value in (
        ("observe_mode", not observe),
        ("decision", "allow" if deny else "deny"),
        ("event_name", "PreToolUse"),
    ):
        wrong = deepcopy(edge)
        wrong["receipt"][field] = value
        wrong["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(wrong["receipt"])).hexdigest()
        assert _decode_edge(wrong, snapshot_binding=binding) is None


@pytest.mark.parametrize(
    "field",
    [
        "decision",
        "model_output_action",
        "notice",
        "reason_code",
        "policy_action",
        "observe_mode",
        "reason",
        "reviewed_output_sha256",
        "reviewed_excerpt",
    ],
)
@pytest.mark.parametrize("value", [[], {}, 1, None])
def test_post_defaults_refuse_malformed_typed_result(field: str, value: object) -> None:
    edge, binding = _post_result()
    edge["result"][field] = value
    assert _decode_edge(edge, snapshot_binding=binding) is None


def test_post_defaults_refuse_unknown_fields_missing_required_fields_and_cross_event_replay() -> None:
    edge, binding = _post_result()
    for section in (None, "result", "receipt", "policy_binding"):
        wrong = deepcopy(edge)
        target = wrong if section is None else wrong[section]
        target["unknown"] = "synthetic"
        assert _decode_edge(wrong, snapshot_binding=binding) is None
    for field in edge["result"]:
        wrong = deepcopy(edge)
        wrong["result"].pop(field)
        assert _decode_edge(wrong, snapshot_binding=binding) is None
    for event in ("PostToolUse", "post_tool_use", "afterReadFile"):
        assert scoped_invocation_matches(
            edge, request_id="request-1", harness="claude-code", rule_digest="e" * 64, event=event
        )
    for event in ("PreToolUse", "UserPromptSubmit", "unknown"):
        assert not scoped_invocation_matches(
            edge, request_id="request-1", harness="claude-code", rule_digest="e" * 64, event=event
        )


@pytest.mark.parametrize(
    "fault", ["deny-original", "allow-block", "excerpt-missing", "unknown-output", "false-observe"]
)
def test_post_result_matrix_cannot_be_repaired_with_only_a_new_receipt_hash(fault: str) -> None:
    edge, binding = _post_result(observe=True)
    result = edge["result"]
    if fault == "deny-original":
        result["decision"] = "deny"
    elif fault == "allow-block":
        result["model_output_action"] = "block"
    elif fault == "excerpt-missing":
        result["model_output_action"] = "replace_with_reviewed_excerpt"
    elif fault == "unknown-output":
        result["model_output_action"] = "unknown"
    else:
        result["observe_mode"] = False
    for key in ("decision", "model_output_action", "observe_mode"):
        edge["receipt"][key] = result[key]
    edge["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(edge["receipt"])).hexdigest()
    assert _decode_edge(edge, snapshot_binding=binding) is None


@pytest.mark.parametrize("failure", [None, "stale", "missing-result", "missing-check", "capture-refused"])
@pytest.mark.parametrize("observe", [False, True])
def test_post_worker_checks_live_binding_before_output_and_never_lowers_intrinsic_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None, observe: bool
) -> None:
    edge, binding = _post_result(observe=observe, deny=True)
    assert _decode_edge(edge, snapshot_binding=binding) == edge
    receipts: list[object] = []
    routes: list[str] = []
    checks: list[object] = []
    publisher = SimpleNamespace(requires_scoped_authority=True, current=True)

    def current(value: object) -> bool:
        checks.append(value)
        return publisher.current

    if failure != "missing-check":
        publisher.result_binding_is_current = current
    publisher.capture_policy_decision_context = lambda *_args: (failure != "capture-refused", None)

    def transport(**kwargs: object):
        assert kwargs["observe_mode"] is False
        publisher.current = failure != "stale"
        return None if failure == "missing-result" else edge

    monkeypatch.setattr(hook_worker_native, "hook_review_is_recording_only", lambda **_kwargs: True)
    host: Any = SimpleNamespace(
        policy_snapshot_publisher=publisher,
        _native_policy_snapshot=lambda *_args, **_kwargs: binding,
        _review_raw_hook_native=transport,
        _record_native_decision_receipt=lambda receipt: receipts.append(receipt) or receipt,
        _record_post_tool_activity=lambda **_kwargs: None,
        metrics=SimpleNamespace(record_route=routes.append),
        activity_writer=None,
    )
    host._review_native_edge_with_snapshot = MethodType(
        worker_module.HookWorker._review_native_edge_with_snapshot, host
    )
    actual = worker_module.HookWorker._review_native_edge(
        host,
        payload={"tool_name": "Read", "tool_response": "synthetic"},
        harness="claude-code",
        event_name="PostToolUse",
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        deadline=None,
    )
    assert actual["policy_action"] == "block" and actual["model_output_action"] == "block"
    output = actual["hookSpecificOutput"]
    assert isinstance(output, dict) and output["hookEventName"] == "PostToolUse"
    if failure is None:
        assert receipts == [edge["receipt"]] and routes == ["native_resident"]
    else:
        assert actual["reason_code"] == "native_scoped_authority_unavailable"
        assert receipts == [] and routes == ["native_fail_safe"]
    assert len(checks) == (0 if failure in {"missing-result", "missing-check"} else 1)


def test_post_admission_refusal_uses_terminal_post_shape(tmp_path: Path) -> None:
    emitted: list[dict[str, Any]] = []
    worker = SimpleNamespace(
        prepare_workspace_policy=lambda *_args, **_kwargs: None,
        policy_snapshot_publisher=SimpleNamespace(requires_scoped_authority=True),
        metrics=SimpleNamespace(record_route=lambda _route: None),
    )
    assert not prepare_native_hook_policy(
        SimpleNamespace(_write_json=emitted.append),
        SimpleNamespace(hook_worker=worker),
        {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": "synthetic"},
        {},
        "claude-code",
        str(tmp_path),
        0.0,
    )
    assert emitted[0]["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert emitted[0]["policy_action"] == "block" and emitted[0]["model_output_action"] == "block"


@pytest.mark.parametrize("action", ["warn", "block"])
def test_observe_policy_warning_does_not_request_approval_or_lower_intrinsic_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    edge, binding = _bound_result(observe=True)
    edge["policy_binding"]["selected_decision_id"] = None
    decision = "allow" if action == "warn" else "deny"
    edge["result"].update(policy_action=action, minimum_action=action, decision=decision, explicitly_benign=False)
    edge["observed_policy_action"] = "block"
    edge["receipt"].update(policy_action=action, decision=decision, observed_policy_action="block")
    edge["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(edge["receipt"])).hexdigest()
    assert _decode_edge(edge, snapshot_binding=binding) == edge

    def no_approval(*_args: object, **_kwargs: object) -> None:
        pytest.fail("a native policy-only Observe warning or terminal Block cannot request approval")

    monkeypatch.setattr(hook_worker_native, "pause_native_pre_tool_for_approval", no_approval)
    monkeypatch.setattr(hook_worker_native, "hook_review_is_recording_only", lambda **_kwargs: True)
    host: Any = SimpleNamespace(
        policy_snapshot_publisher=SimpleNamespace(
            requires_scoped_authority=True,
            result_binding_is_current=lambda _binding: True,
            capture_policy_decision_context=lambda *_args: (True, None),
        ),
        _native_policy_snapshot=lambda *_args, **_kwargs: binding,
        _review_raw_hook_native=lambda **_kwargs: edge,
        _record_native_decision_receipt=lambda receipt: receipt,
        metrics=SimpleNamespace(record_route=lambda _route: None),
        activity_writer=None,
    )
    host._review_native_edge_with_snapshot = MethodType(
        worker_module.HookWorker._review_native_edge_with_snapshot, host
    )
    actual = worker_module.HookWorker._review_native_edge(
        host,
        payload={"tool_name": "Shell", "tool_input": {"command": "printf first && printf second"}},
        harness="claude-code",
        event_name="PreToolUse",
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        deadline=None,
    )
    output = actual["hookSpecificOutput"]
    assert isinstance(output, dict) and output["permissionDecision"] == decision
    assert actual["policy_action"] == action


@pytest.mark.parametrize("observe", [False, True])
@pytest.mark.parametrize("action", ["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"])
@pytest.mark.parametrize("output", ["allow_original", "replace_with_reviewed_excerpt", "block"])
def test_post_action_output_matrix_rejects_self_consistent_but_impossible_results(
    observe: bool, action: str, output: str
) -> None:
    edge, binding = _post_result(observe=observe)
    result = edge["result"]
    result.update(policy_action=action, model_output_action=output, decision="deny" if output == "block" else "allow")
    if output == "replace_with_reviewed_excerpt":
        result["reviewed_excerpt"] = "synthetic reviewed output"
        result["notice"] = "excerpt"
    elif output == "block":
        result["notice"] = "warning"
    observed = action if observe else None
    edge["observed_policy_action"] = observed
    if observe:
        result["observed_policy_action"] = observed
    for key in ("decision", "model_output_action", "policy_action"):
        edge["receipt"][key] = result[key]
    edge["receipt"]["observed_policy_action"] = observed
    edge["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(edge["receipt"])).hexdigest()
    if action in {"allow", "warn"}:
        valid = output == "allow_original"
    elif observe:
        # Observe can report a higher policy floor beside an allowed original
        # or reviewed excerpt, but only an intrinsic Block can deny output.
        valid = output != "block" or action == "block"
    elif action == "review":
        valid = output in {"block", "replace_with_reviewed_excerpt"}
    else:
        valid = output == "block"
    assert (_decode_edge(edge, snapshot_binding=binding) is not None) is valid


@pytest.mark.parametrize("fault", ["missing-observed-action", "wrong-observed-action", "extraneous-excerpt"])
def test_post_projection_and_excerpt_fields_cannot_be_repaired_by_rehashing(fault: str) -> None:
    edge, binding = _post_result(observe=True)
    if fault == "extraneous-excerpt":
        edge["result"]["reviewed_excerpt"] = "unexpected replacement"
    else:
        value = None if fault == "missing-observed-action" else "block"
        edge["observed_policy_action"] = value
        edge["result"]["observed_policy_action"] = value
        edge["receipt"]["observed_policy_action"] = value
    edge["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(edge["receipt"])).hexdigest()
    assert _decode_edge(edge, snapshot_binding=binding) is None
