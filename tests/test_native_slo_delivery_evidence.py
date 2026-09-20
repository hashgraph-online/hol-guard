"""Retain delivered facts on failed attribution without manufacturing native work."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from scripts import native_slo_launcher_input as inputs
from scripts import native_slo_registered_surfaces as registrations
from scripts import native_slo_registered_surfaces_run as surfaces
from scripts import native_slo_surface_failure as failures
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_delivery_evidence import delivery_evidence
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_workloads import build_cases
from tests.test_native_slo_launcher_input import _install_fakes
from tests.test_native_slo_registered_surfaces import _cline


def _result(response: object) -> BoundedHookProcessResult:
    return BoundedHookProcessResult(0, json.dumps(response), False, False, stderr="private stderr")


@pytest.mark.parametrize("validated", [True, False])
def test_closed_delivery_projection_survives_actual_aggregate_and_json_roundtrip(validated):
    result = _result(
        {
            "continue": True,
            "cancel": False,
            "policy_action": "warn",
            "reason_code": "private arbitrary text",
            "reason": "/private/home/sensitive",
            "hookSpecificOutput": {"permissionDecision": "allow", "permissionDecisionReason": "private reason"},
            "approval_request_id": "private-row-identity",
        }
    )
    original = RuntimeError("priority_launcher_input_route_mismatch")
    enriched = failures.enrich_surface_failure(
        original,
        case_id="input.claude-code.PreToolUse.empty",
        registration_digest="a" * 64,
        stage="witness",
        expected_route="native_resident",
        observed_route="engine_bypassed",
        routes_before={"native_resident": 25},
        routes_after={"native_resident": 25},
        delivery_result=result,
        delivery_validated=validated,
        evidence={"native_result": None, "native_call_count": 0},
    )
    assert isinstance(enriched, FixtureFailureError)
    assert str(enriched) == str(original)
    aggregate = {"additional_scenarios": {"priority_input": {"failure": failure_evidence(enriched)}}}
    encoded = json.dumps(assert_privacy_safe(aggregate))
    detail = json.loads(encoded)["additional_scenarios"]["priority_input"]["failure"]
    assert detail["diagnostic_digest"] == hashlib.sha256(str(original).encode()).hexdigest()
    assert detail["observed_route"] == "engine_bypassed" and detail["native_call_count"] == 0
    assert detail["route_witness_scope"] == "fixture_daemon_only" and detail["child_route"] == "unknown"
    assert detail["delivery_capture"] == {
        "available": True,
        "exit_code": 0,
        "timed_out": False,
        "containment_failed": False,
        "limit_exceeded": False,
        "stderr_present": True,
        "shape_validation": "passed" if validated else "not_run",
        "json_shape": "object",
    }
    delivered = detail["observed_semantics"]["delivered"]
    assert delivered["available"] and delivered["continue"] and delivered["cancel"] is False
    assert delivered["hook_permission"] == "allow" and delivered["policy_action"] == "warn"
    assert detail["observed_semantics"]["native"] == {"available": False}
    for private in ("private", "sensitive", "truncated", "approval_request_id"):
        assert private not in encoded


@pytest.mark.parametrize("stdout,shape", [("", "empty"), ("{broken", "invalid_json"), ("[]", "nonobject")])
def test_bad_or_nonobject_stream_is_not_called_a_valid_delivery(stdout, shape):
    process, observed = delivery_evidence(replace(_result({}), stdout=stdout), validated=False)
    assert process["json_shape"] == shape and process["shape_validation"] == "not_run"
    assert observed == {"available": False}


@pytest.mark.parametrize("field", ["timed_out", "containment_failed", "output_limit_exceeded"])
def test_closed_process_failure_flags_are_retained(field):
    process, _ = delivery_evidence(replace(_result({}), **{field: True}), validated=False)
    assert process["limit_exceeded" if field == "output_limit_exceeded" else field] is True
    assert process["shape_validation"] == "not_run"


def test_projection_refuses_to_coerce_permission_and_boolean_fields():
    _, observed = delivery_evidence(
        _result({"continue": 1, "cancel": "false", "permission": "/private/path"}), validated=False
    )
    assert observed["continue"] == observed["cancel"] == "invalid_type"
    assert observed["permission"] == "unrecognized"


@pytest.mark.parametrize("kind", ["nonobject_json", "empty"])
def test_original_priority_call_once_retains_continuation_before_failed_daemon_attribution(tmp_path, monkeypatch, kind):
    session = cast(SimpleNamespace, cast(object, _install_fakes(tmp_path, monkeypatch)))
    original_run, original_control = inputs.run_isolated_hook_process, session.control
    invocations = []

    def run(*args, **kwargs):
        invocations.append((args, kwargs))
        result = original_run(*args, **kwargs)
        if session.case.kind == kind:
            session.routes["native_resident"] -= 1
            return BoundedHookProcessResult(
                result.returncode,
                json.dumps({"continue": True, "hookSpecificOutput": {"permissionDecision": "allow"}}),
                result.output_limit_exceeded,
                result.timed_out,
                result.containment_failed,
                result.stderr,
            )
        return result

    def control(operation, **kwargs):
        evidence = original_control(operation, **kwargs)
        if operation == "case_result" and session.case.kind == kind:
            evidence.update(native_result=None, native_call_count=0, native_completed_call_count=0)
        return evidence

    monkeypatch.setattr(inputs, "run_isolated_hook_process", run)
    session.control = control
    ledger = tmp_path / "attempts.jsonl"
    with pytest.raises(FixtureFailureError, match="priority_launcher_input_route_mismatch") as caught:
        inputs.run_registered_input_corpus(cast(inputs.DaemonFixture, cast(object, session)), evidence_file=ledger)
    expected_calls = 2 if kind == "nonobject_json" else 3
    assert len(invocations) == cast(SimpleNamespace, cast(object, original_run)).calls == expected_calls
    assert invocations[-1][1]["input_text"] == ("[]" if kind == "nonobject_json" else "")
    assert sum(op == "launcher_approval_begin" for op, _ in session.calls) == expected_calls - 1
    assert sum(op == "launcher_approval_result" for op, _ in session.calls) == expected_calls - 2
    assert sum(op == "case_result" for op, _ in session.calls) == expected_calls
    detail = json.loads(json.dumps(failure_evidence(caught.value)))
    assert detail["delivery_capture"]["shape_validation"] == "not_run"
    assert detail["observed_semantics"]["delivered"]["continue"] is True
    assert detail["observed_semantics"]["native"] == {"available": False}
    assert detail["child_route"] == "unknown" and detail["observed_route"] == "engine_bypassed"
    records = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert records[-1]["status"] == "failed" and records[-1]["stage"] == "witness"


@pytest.mark.skipif(os.name == "nt", reason="This actual registered executable control uses a POSIX shebang")
def test_actual_cline_child_delivery_is_retained_after_unchanged_route_failure(tmp_path, monkeypatch):
    home, workspace, guard_home = tmp_path / "home", tmp_path / "workspace", tmp_path / "guard"
    for path in (home, workspace, guard_home):
        path.mkdir()
    context = HarnessContext(home, workspace, guard_home)
    _cline(context)
    case = next(case for case in build_cases(workspace) if case.case_id == "cline/PreToolUse/benign/small")
    state_path = guard_home / "managed/cline/native-hooks-state.json"
    state = json.loads(state_path.read_text())
    executable = Path(state["paths"]["PreToolUse"])
    marker = tmp_path / "child-call-count"
    stdin = json.dumps(case.payload, separators=(",", ":"), ensure_ascii=True)
    executable.write_text(
        f"#!{sys.executable}\nimport os,sys\nfrom pathlib import Path\n"
        f"assert sys.argv == {[str(executable)]!r}\nassert sys.stdin.read() == {stdin!r}\n"
        f"assert os.environ['HOME'] == {str(home)!r}\nassert os.getcwd() == {str(workspace)!r}\n"
        "assert 'HOL_GUARD_NATIVE_BINARY' not in os.environ\n"
        f"with Path({str(marker)!r}).open('a') as receipt: receipt.write('called\\n')\n"
        'print(\'{"cancel": false, "contextModification": "", "errorMessage": ""}\')\n'
    )
    state["sha256"]["PreToolUse"] = hashlib.sha256(executable.read_bytes()).hexdigest()
    state_path.write_text(json.dumps(state))
    surface = next(
        item for item in registrations.read_registered_surfaces(context, "cline") if item.event == "PreToolUse"
    )
    calls = []

    def control(operation):
        calls.append(operation)
        return {} if operation == "case_before" else {"native_result": None, "native_call_count": 0}

    metrics = SimpleNamespace(snapshot=lambda: {"routes": {"native_resident": 25}})
    session = SimpleNamespace(
        root=home,
        workspace=workspace,
        guard_home=guard_home,
        control=control,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics))),
    )
    monkeypatch.setattr(surfaces, "install_registered_surface", lambda *_: (surface,))
    monkeypatch.setattr(surfaces, "surface_cases", lambda *_: (case,))
    monkeypatch.setattr(surfaces, "wait_for_route_corpus", lambda *_args, **_kwargs: metrics.snapshot())
    ledger = tmp_path / "cline.jsonl"
    with pytest.raises(FixtureFailureError, match="registered_surface_native_route_mismatch") as caught:
        surfaces.run_registered_surface_corpus(
            cast(surfaces.SurfaceSession, cast(object, session)), harnesses=("cline",), evidence_file=ledger
        )
    assert marker.read_text() == "called\n" and calls == ["case_before", "case_result"]
    detail = json.loads(json.dumps(failure_evidence(caught.value)))
    assert detail["delivery_capture"]["shape_validation"] == "passed"
    assert detail["delivery_capture"]["exit_code"] == 0
    assert detail["observed_semantics"]["delivered"] == {"available": True, "cancel": False}
    assert detail["observed_semantics"]["native"] == {"available": False}
    assert detail["child_route"] == "unknown" and detail["routes_before"] == detail["routes_after"]
    records = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert records[-1]["status"] == "failed" and records[-1]["stage"] == "route"
    assert "cancel" not in ledger.read_text() and str(executable) not in json.dumps(detail)


def test_delivery_capture_failure_keeps_original_failure_and_native_witness(monkeypatch):
    def fail(*_args, **_kwargs):
        raise RuntimeError("private diagnostic failure")

    monkeypatch.setattr(failures, "delivery_evidence", fail)
    original = AssertionError("registered_surface_native_route_mismatch")
    enriched = failures.enrich_surface_failure(
        original,
        case_id="cline.PreToolUse.benign.small",
        registration_digest="a" * 64,
        stage="route",
        expected_route="native_resident",
        observed_route="engine_bypassed",
        routes_before={},
        routes_after={},
        delivery_result=_result({"cancel": False}),
        delivery_validated=True,
        evidence={"native_result": None, "native_call_count": 0},
    )
    assert isinstance(enriched, FixtureFailureError) and str(enriched) == str(original)
    detail = json.loads(json.dumps(failure_evidence(enriched)))
    assert detail["delivery_capture"] == {"available": False, "capture_failed": True}
    assert detail["native_call_count"] == 0 and detail["observed_semantics"]["native"] == {"available": False}
    assert "private diagnostic" not in json.dumps(detail)
