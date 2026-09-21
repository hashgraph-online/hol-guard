"""Malformed installed-input expectations never count continuation as evaluation."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from scripts import native_slo_launcher_input as corpus
from scripts.native_slo_priority_launchers import RegisteredLauncher

_PORT = 4871
_REQUEST = "b" * 32
_UNKNOWN = "HOL Guard requires review because this PreToolUse action is not yet supported for automatic allow."
_CODEX_REASON = "HOL Guard could not authenticate the local daemon. Run `hol-guard daemon repair`, then retry."
_LIMIT_REASON = "HOL Guard blocked this action because hook input exceeded the safe size limit."
_INVALID_REASON = (
    'HOL Guard could not reach the local daemon (daemon returned HTTP 400: {"error": "invalid_request_body"}; '
    "fallback exited 2) and continued this action without native review."
)


def _launcher(tmp_path, harness="codex", event="PreToolUse"):
    return RegisteredLauncher(
        harness,
        event,
        ("registered-interpreter", "-I", "registered-bridge", harness, event),
        (("REGISTERED_FLAG", "yes"),),
        "a" * 64,
        tmp_path / "configuration",
    )


def _response(case):
    if case.requires_review:
        url = f"http://127.0.0.1:{_PORT}/requests/{_REQUEST}"
        reason = _UNKNOWN + " Open HOL Guard to approve or keep this blocked: " + url + "."
        result = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask" if case.harness == "claude-code" else "deny",
                "permissionDecisionReason": reason,
            }
        }
        if case.harness == "claude-code":
            result.update(
                policy_action="review",
                reason_code="native_pre_tool_unknown_review",
                reason=reason,
                approval_url=url,
                approval_request_id=_REQUEST,
                primary_approval_request_id=_REQUEST,
                primary_approval_url=url,
                guardApprovalRequestId=_REQUEST,
                guardApprovalUrl=url,
                approval_requests=[{"request_id": _REQUEST, "approval_url": url}],
                prompted=True,
                approval_center_url=f"http://127.0.0.1:{_PORT}",
            )
        return result
    if case.kind == "invalid_ascii_json" and case.harness == "claude-code" and case.registration_event == "PostToolUse":
        return {}
    reason = _CODEX_REASON if case.harness == "codex" else _LIMIT_REASON if case.kind == "oversize" else _INVALID_REASON
    if case.kind == "oversize" and case.harness == "claude-code" and case.registration_event == "PostToolUse":
        return {"decision": "block", "reason": reason, "hookSpecificOutput": {"hookEventName": "PostToolUse"}}
    result = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny" if case.kind == "oversize" else "allow",
            "permissionDecisionReason": reason,
        }
    }
    if case.kind == "invalid_ascii_json":
        result["continue"] = True
    elif case.harness == "claude-code":
        result["systemMessage"] = reason
    return result


def _witness(case):
    native = None
    if case.requires_review:
        native = {
            "authority": "rust",
            "decision": "deny",
            "policy_action": "review",
            "minimum_action": "review",
            "reason_code": "native_pre_tool_unknown_review",
            "reason": _UNKNOWN,
            "explicitly_benign": False,
            "action": {"harness": case.harness, "event": "PreToolUse", "action_type": "unknown"},
        }
    return {
        "setup": {
            "isolated_store": True,
            "effective_policy_allow": True,
            "policy_ack_current": True,
            "python_oracle_disabled": True,
            "fault_scope": "none",
        },
        "native_result": native,
    }


@pytest.mark.parametrize("harness", ["codex", "claude-code"])
@pytest.mark.parametrize("event", ["PreToolUse", "PostToolUse"])
def test_exact_four_inputs_and_independent_stdout_contracts(tmp_path, harness, event):
    cases = corpus.input_cases(_launcher(tmp_path, harness, event))
    assert [case.kind for case in cases] == ["invalid_ascii_json", "nonobject_json", "empty", "oversize"]
    assert len(cases[-1].stdin.encode()) == 1_000_001
    assert all(case.stdin.isascii() for case in cases)
    with pytest.raises(json.JSONDecodeError):
        json.loads(cases[0].stdin)
    assert json.loads(cases[1].stdin) == [] and cases[2].stdin == ""
    for case in cases:
        response = _response(case)
        corpus.validate_input_delivery(case, response, approval={"request_id": _REQUEST}, port=_PORT)
        corpus._validate_witness(case, _witness(case), case.expected_route)
        with pytest.raises(RuntimeError, match="stdout_contract"):
            corpus.validate_input_delivery(
                case, {**response, "extra": "unexpected"}, approval={"request_id": _REQUEST}, port=_PORT
            )


@pytest.mark.parametrize("kind", ["nonobject_json", "empty"])
def test_normalized_empty_post_registration_is_native_pretool_review(tmp_path, kind):
    case = next(c for c in corpus.input_cases(_launcher(tmp_path, "codex", "PostToolUse")) if c.kind == kind)
    assert case.expected_route == "native_resident" and case.delivery == "review_deny"
    with pytest.raises(RuntimeError):
        corpus.validate_input_delivery(case, {}, approval={"request_id": _REQUEST}, port=_PORT)
    with pytest.raises(RuntimeError, match="route_mismatch"):
        corpus._validate_witness(case, _witness(case), "native_fail_safe")
    forged = _witness(case)
    forged["native_result"]["decision"] = "allow"
    with pytest.raises(RuntimeError, match="native_review_unproven"):
        corpus._validate_witness(case, forged, "native_resident")


def test_oversize_codex_post_retains_existing_pretool_denial(tmp_path):
    case = corpus.input_cases(_launcher(tmp_path, "codex", "PostToolUse"))[-1]
    response = _response(case)
    assert response["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    response["hookSpecificOutput"]["hookEventName"] = "PostToolUse"
    with pytest.raises(RuntimeError, match="stdout_contract"):
        corpus.validate_input_delivery(case, response)


@pytest.mark.parametrize("mutation", ["allow", "wrong_id", "remote_url", "extra_specific", "numeric_continue"])
def test_false_success_and_review_identity_mutations_fail(tmp_path, mutation):
    case = corpus.input_cases(_launcher(tmp_path))[2]
    response = _response(case)
    if mutation == "allow":
        response["hookSpecificOutput"]["permissionDecision"] = "allow"
    elif mutation == "wrong_id":
        response["hookSpecificOutput"]["permissionDecisionReason"] = response["hookSpecificOutput"][
            "permissionDecisionReason"
        ].replace(_REQUEST, "c" * 32)
    elif mutation == "remote_url":
        response["hookSpecificOutput"]["permissionDecisionReason"] = response["hookSpecificOutput"][
            "permissionDecisionReason"
        ].replace("127.0.0.1", "example.invalid")
    elif mutation == "extra_specific":
        response["hookSpecificOutput"]["unexpected"] = True
    else:
        case = corpus.input_cases(_launcher(tmp_path))[0]
        response = _response(case)
        response["continue"] = 1
    with pytest.raises(RuntimeError):
        corpus.validate_input_delivery(case, response, approval={"request_id": _REQUEST}, port=_PORT)


class _Session:
    def __init__(self, root):
        self.root, self.workspace, self.guard_home = root, root / "workspace", root / "guard-home"
        self.routes = {"native_resident": 0}
        self.case = None
        self.calls = []
        self.daemon = SimpleNamespace(
            port=_PORT,
            _server=SimpleNamespace(
                hook_worker=SimpleNamespace(metrics=SimpleNamespace(snapshot=lambda: {"routes": dict(self.routes)}))
            ),
        )

    def control(self, operation, **arguments):
        self.calls.append((operation, arguments))
        if operation == "case_before":
            return {"reset": True}
        if operation == "launcher_approval_begin":
            assert arguments["payload"] == {} and arguments["resolution"] == "block"
            return {"operation_id": "operation", "state": "waiting"}
        if operation == "launcher_approval_result":
            return {
                "request_id": _REQUEST,
                "state": "resolved",
                "resolution": "block",
                "approval_durable": True,
                "authority": "ordinary_local_review",
                "matching": "exact_identity_and_new_row",
            }
        assert operation == "case_result"
        return _witness(self.case)


def _install_fakes(tmp_path, monkeypatch, *, fail_at=None):
    session = _Session(tmp_path)
    launchers = tuple(
        _launcher(tmp_path, harness, event)
        for harness in ("claude-code", "codex")
        for event in ("PreToolUse", "PostToolUse")
    )
    pending = []
    original_cases = corpus.input_cases

    def cases(launcher):
        result = original_cases(launcher)
        pending.extend(result)
        return result

    def run(argv, *, input_text, cwd, environment, timeout_seconds, output_limit):
        case = pending.pop(0)
        session.case = case
        session.routes["native_resident"] += int(case.requires_review)
        expected_launcher = next(
            item for item in launchers if (item.harness, item.event) == (case.harness, case.registration_event)
        )
        assert argv == expected_launcher.argv and input_text == case.stdin
        assert cwd == session.workspace and timeout_seconds == 10 and output_limit == 2 * 1024 * 1024
        assert environment["REGISTERED_FLAG"] == "yes"
        assert environment["HOME"] == str(session.root) and "HOL_GUARD_NATIVE_BINARY" not in environment
        run.calls += 1
        code = 7 if run.calls == fail_at else 0
        return SimpleNamespace(
            returncode=code,
            timed_out=False,
            containment_failed=False,
            output_limit_exceeded=False,
            stdout=json.dumps(_response(case)),
            stderr="not exported",
        )

    run.calls = 0
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", "/untrusted/override")
    monkeypatch.setattr(corpus, "input_cases", cases)
    monkeypatch.setattr(corpus, "install_priority_launchers", lambda _session: launchers)
    monkeypatch.setattr(
        corpus,
        "registered_launcher",
        lambda path, harness, event: next(x for x in launchers if (x.harness, x.event) == (harness, event)),
    )
    monkeypatch.setattr(corpus, "run_isolated_hook_process", run)
    monkeypatch.setattr(corpus, "wait_for_route_corpus", lambda metrics, expected: metrics.snapshot())
    return session


def test_all_sixteen_cases_execute_exact_registered_processes(tmp_path, monkeypatch):
    session = _install_fakes(tmp_path, monkeypatch)
    evidence = tmp_path / "input.jsonl"
    result = corpus.run_registered_input_corpus(session, evidence_file=evidence)
    assert result["validated_cases"] == 16 and result["native_allow_count"] == 0
    assert result["coverage"]["route"] == {"engine_bypassed": 8, "native_resident": 8}
    assert result["coverage"]["delivery"] == {
        "availability_continuation": 4,
        "review_ask": 4,
        "review_deny": 4,
        "launcher_limit_block": 4,
    }
    assert result["qualification_complete"] is False
    raw = evidence.read_text()
    assert len(raw.splitlines()) == 32
    assert str(tmp_path) not in raw and "not exported" not in raw and "guard-token" not in raw
    assert sum(op == "launcher_approval_begin" for op, _ in session.calls) == 8
    assert sum(op == "case_result" for op, _ in session.calls) == 16


def test_input_route_failure_retains_actual_case_counters_without_observer_retry(tmp_path, monkeypatch):
    import hashlib

    from scripts.native_slo_failure import FixtureFailureError, failure_evidence

    session = _install_fakes(tmp_path, monkeypatch)
    original_run = corpus.run_isolated_hook_process
    original_control = session.control

    def wrong_route(*args, **kwargs):
        result = original_run(*args, **kwargs)
        if session.case.kind == "nonobject_json":
            session.routes["native_resident"] -= 1
            session.routes["native_fail_safe"] = 1
        return result

    def observed_control(operation, **arguments):
        result = original_control(operation, **arguments)
        if operation == "case_result":
            result.update(native_call_count=0, native_completed_call_count=0, policy_refusal_count=1)
        return result

    monkeypatch.setattr(corpus, "run_isolated_hook_process", wrong_route)
    session.control = observed_control
    evidence = tmp_path / "route-failure.jsonl"
    with pytest.raises(FixtureFailureError, match="route_mismatch") as caught:
        corpus.run_registered_input_corpus(session, evidence_file=evidence)
    detail = failure_evidence(caught.value)
    assert detail["case"] == "input.claude-code.PreToolUse.nonobject_json"
    assert detail["category"] == "RuntimeError"
    assert detail["diagnostic_digest"] == hashlib.sha256(b"priority_launcher_input_route_mismatch").hexdigest()
    assert detail["origin"] == "native_slo_launcher_input._validate_witness"
    assert detail["expected_route"] == "native_resident"
    assert detail["observed_route"] == "native_fail_safe"
    assert detail["routes_before"] == {"native_resident": 0}
    assert detail["routes_after"] == {"native_resident": 0, "native_fail_safe": 1}
    assert detail["native_call_count"] == 0 and detail["policy_refusal_count"] == 1
    assert detail["witness_capture"] == "existing_case_result"
    assert sum(op == "case_result" for op, _ in session.calls) == 2
    assert sum(op == "launcher_approval_result" for op, _ in session.calls) == 0
    records = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert [row["status"] for row in records] == ["offered", "completed", "offered", "failed"]
    assert records[-1]["route"] == "native_fail_safe"


def test_failure_preserves_prior_success_and_failed_exit(tmp_path, monkeypatch):
    session = _install_fakes(tmp_path, monkeypatch, fail_at=2)
    evidence = tmp_path / "failed.jsonl"
    with pytest.raises(RuntimeError, match="process_contract"):
        corpus.run_registered_input_corpus(session, evidence_file=evidence)
    records = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert [r["status"] for r in records] == ["offered", "completed", "offered", "failed"]
    assert records[-1]["attempted_exit"] == 7 and records[-1]["stage"] == "process"


def test_live_block_resolution_never_accepts_allow(tmp_path):
    session = _Session(tmp_path)
    original = session.control
    session.control = lambda operation, **kwargs: {**original(operation, **kwargs), "resolution": "allow"}
    with pytest.raises(RuntimeError, match="resolution_unproven"):
        corpus._block_resolution(session, "operation")


def test_rejected_inputs_cannot_hide_native_work(tmp_path):
    case = corpus.input_cases(_launcher(tmp_path))[0]
    evidence = _witness(case)
    evidence["native_result"] = {"decision": "allow"}
    with pytest.raises(RuntimeError, match="unexpected_native_work"):
        corpus._validate_witness(case, evidence, "engine_bypassed")


@pytest.mark.parametrize("flag", ["timed_out", "containment_failed", "output_limit_exceeded"])
def test_zero_exit_cannot_hide_process_failure(tmp_path, monkeypatch, flag):
    session = _install_fakes(tmp_path, monkeypatch)
    original = corpus.run_isolated_hook_process

    def failed_process(*args, **kwargs):
        result = original(*args, **kwargs)
        setattr(result, flag, True)
        return result

    monkeypatch.setattr(corpus, "run_isolated_hook_process", failed_process)
    evidence = tmp_path / "failed-process.jsonl"
    with pytest.raises(RuntimeError, match="process_contract"):
        corpus.run_registered_input_corpus(session, evidence_file=evidence)
    records = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert [row["status"] for row in records] == ["offered", "failed"]
    assert records[-1]["attempted_exit"] == 0 and records[-1]["stage"] == "process"


@pytest.mark.parametrize("read_number", [1, 2])
def test_changed_registration_fails_and_prevents_further_forwarding(tmp_path, monkeypatch, read_number):
    session = _install_fakes(tmp_path, monkeypatch)
    original = corpus.registered_launcher
    reads = []

    def changed_registration(*args):
        reads.append(args)
        return None if len(reads) == read_number else original(*args)

    monkeypatch.setattr(corpus, "registered_launcher", changed_registration)
    process = corpus.run_isolated_hook_process
    evidence = tmp_path / "registration.jsonl"
    with pytest.raises(RuntimeError, match="registration_changed"):
        corpus.run_registered_input_corpus(session, evidence_file=evidence)
    records = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert [row["status"] for row in records] == ["offered", "failed"]
    assert records[-1]["stage"] == ("registration" if read_number == 1 else "readback_after")
    assert process.calls == read_number - 1


def test_failed_resolution_cannot_be_reported_as_valid_review(tmp_path, monkeypatch):
    session = _install_fakes(tmp_path, monkeypatch)
    original = session.control

    def failed_resolution(operation, **kwargs):
        result = original(operation, **kwargs)
        return {**result, "state": "failed"} if operation == "launcher_approval_result" else result

    session.control = failed_resolution
    evidence = tmp_path / "resolution.jsonl"
    with pytest.raises(RuntimeError, match="resolution_unproven"):
        corpus.run_registered_input_corpus(session, evidence_file=evidence)
    records = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert [row["status"] for row in records] == ["offered", "completed", "offered", "failed"]
    assert records[-1]["route"] == "native_resident" and records[-1]["stage"] == "witness"
