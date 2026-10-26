"""Bash sink transport binding, lifetime ownership and replay semantics."""

from __future__ import annotations

import copy
import io
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard import native_bash_protocol as bridge
from codex_plugin_scanner.guard.native_bash_reply import validate_executed, validate_prepared
from codex_plugin_scanner.guard.runtime import bound_bash_sink as sink


def _request():
    return {
        "request_id": "transport-1",
        "operation_id": "stable-operation-1",
        "authorization": {"kind": "current_policy", "store_path": "/isolated/guard.db"},
        "timeout_ms": 30_000,
    }


def _result(request):
    completion = {
        "exit_code": 7,
        "stdout": "result\n",
        "stderr": "warning\n",
        "output_limited": False,
        "timed_out": False,
        "cancelled": False,
    }
    return {
        "schema": "guard-native-bash-execute-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + bridge._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "grant_claimed": False,
        "dispatch_acknowledged": True,
        "replayed": False,
        "payload": completion,
        "review_lineage": None,
        "operation": {
            "operation_id": request["operation_id"],
            "artifact_hash": "guard-approval-context:v1:fixture",
            "authorization": "current_policy",
            "state": "completed",
            "dispatch_acknowledged": True,
            "completion": {key: value for key, value in completion.items() if key not in {"stdout", "stderr"}}
            | {"stdout_sha256": "a" * 64, "stderr_sha256": "b" * 64},
        },
    }


@pytest.fixture
def transport(monkeypatch, tmp_path):
    status = SimpleNamespace(identity=SimpleNamespace(path=tmp_path / "native"))
    monkeypatch.setattr(bridge, "runtime_status", lambda: status)
    monkeypatch.setattr(bridge, "_isolated_environment", lambda: {"PATH": "/usr/bin"})
    request = _request()
    runner = Mock(
        return_value=SimpleNamespace(
            returncode=0,
            timed_out=False,
            output_limit_exceeded=False,
            containment_failed=False,
            stdout=json.dumps(_result(request)),
        )
    )
    monkeypatch.setattr(bridge, "run_isolated_hook_process", runner)
    return runner, request


def test_execute_uses_one_owned_client_and_preserves_program_failure(transport, tmp_path):
    runner, request = transport
    result = bridge.execute(request, guard_home=tmp_path, cwd=tmp_path)
    runner.assert_called_once()
    args, options = runner.call_args
    assert args[0][1:] == ["native-bash-execute-client", "--stdin", str(tmp_path / "native-runtime")]
    assert options["parent_liveness"] is True
    assert options["timeout_seconds"] == 32
    assert json.loads(options["input_text"])["request"]["operation_id"] == "stable-operation-1"
    output, errors = io.StringIO(), io.StringIO()
    assert sink.render_result(result, output=output, errors=errors) == 7
    assert output.getvalue() == "result\n" and errors.getvalue() == "warning\n"


def test_host_supervision_is_a_transport_option_outside_the_permission_request(transport, tmp_path):
    runner, request = transport
    before = copy.deepcopy(request)
    bridge.execute(request, guard_home=tmp_path, cwd=tmp_path, host_owner_pid=1234)
    args, options = runner.call_args
    assert args[0][-2:] == ["--host-owner-pid", "1234"]
    assert json.loads(options["input_text"])["request"] == before == request


@pytest.mark.parametrize("pid", [0, 1, -1, True, 2_147_483_648, "1234"])
def test_invalid_host_locator_never_starts_a_client(transport, tmp_path, pid):
    runner, request = transport
    with pytest.raises(bridge.NativeBashError, match="native_bash_host_owner_invalid"):
        bridge.execute(request, guard_home=tmp_path, cwd=tmp_path, host_owner_pid=pid)
    runner.assert_not_called()


def test_runtime_without_pending_lineage_capability_is_not_used(monkeypatch):
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(features={bridge.FEATURE, "resident-protocol-v2"}),
    )
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: status)
    with pytest.raises(bridge.NativeBashError, match="native_bash_owner_unavailable"):
        bridge.runtime_status()
    status.capabilities.features.add("native-bash-review-lineage-v1")
    with pytest.raises(bridge.NativeBashError, match="native_bash_owner_unavailable"):
        bridge.runtime_status()
    status.capabilities.features.add(bridge.DESCRIPTOR_FEATURE)
    with pytest.raises(bridge.NativeBashError, match="native_bash_owner_unavailable"):
        bridge.runtime_status()
    status.capabilities.features.add(bridge.HOST_LIVENESS_FEATURE)
    with pytest.raises(bridge.NativeBashError, match="native_bash_owner_unavailable"):
        bridge.runtime_status()
    status.capabilities.features.add("native-bash-invocation-lifetime-v1")
    with pytest.raises(bridge.NativeBashError, match="native_bash_owner_unavailable"):
        bridge.runtime_status()
    status.capabilities.features.add("native-bash-reply-validation-v1")
    assert bridge.runtime_status() is status


@pytest.mark.parametrize("mutation", ["missing", "operation", "id", "expiry", "unknown", "grant"])
def test_pending_review_cannot_masquerade_as_authorization(mutation):
    request = _request()
    result = _result(request)
    result.update(
        status="error",
        code="native_bash_consent_required",
        payload=None,
        operation=None,
        dispatch_acknowledged=False,
        review_lineage={
            "schema": "guard-native-bash-review-lineage.v1",
            "lineage_id": "c" * 64,
            "operation_id": request["operation_id"],
            "artifact_hash": "guard-approval-context:v1:fixture",
            "created_at_ms": 1000,
            "expires_at_ms": 86_401_000,
        },
    )
    validate_executed(result, request)
    if mutation == "missing":
        result["review_lineage"] = None
    elif mutation == "grant":
        result["grant_claimed"] = True
    else:
        key, value = {
            "operation": ("operation_id", "another-operation-0001"),
            "id": ("lineage_id", "invalid"),
            "expiry": ("expires_at_ms", 1001),
            "unknown": ("allow", True),
        }[mutation]
        result["review_lineage"][key] = value
    with pytest.raises(bridge.NativeBashError):
        validate_executed(result, request)


@pytest.mark.parametrize("failure", ["timeout", "output", "containment", "exit", "binding"])
def test_uncertain_transport_never_reissues_or_changes_operation(transport, tmp_path, failure):
    runner, request = transport
    original = copy.deepcopy(request)
    reply = runner.return_value
    if failure == "binding":
        response = _result(request)
        response["request_sha256"] = "sha256:" + "0" * 64
        reply.stdout = json.dumps(response)
    else:
        setattr(
            reply,
            {
                "timeout": "timed_out",
                "output": "output_limit_exceeded",
                "containment": "containment_failed",
                "exit": "returncode",
            }[failure],
            1,
        )
    with pytest.raises(bridge.NativeBashError):
        bridge.execute(request, guard_home=tmp_path, cwd=tmp_path)
    runner.assert_called_once()
    assert request == original


@pytest.mark.parametrize("raw", ['{"status":"ok","status":"error"}', '{"value":NaN}', "[]", "{"])
def test_non_strict_responses_are_rejected(raw):
    with pytest.raises(bridge.NativeBashError):
        bridge.decode(raw)


@pytest.mark.parametrize("mutation", ["bool", "operation", "dispatch", "completion", "state", "authority"])
def test_native_execution_results_cannot_forge_success_shape(mutation):
    request = _request()
    result = _result(request)
    if mutation == "bool":
        result["grant_claimed"] = 1
    elif mutation == "operation":
        result["operation"]["operation_id"] = "different-operation"
    elif mutation == "dispatch":
        result["dispatch_acknowledged"] = False
    elif mutation == "completion":
        result["operation"]["completion"] = None
    elif mutation == "state":
        result["operation"]["state"] = {}
    else:
        result["operation"]["authorization"] = "saved_grant"
    with pytest.raises(bridge.NativeBashError):
        validate_executed(result, request)


def test_replay_reports_completion_without_emitting_old_output():
    request = _request()
    result = _result(request)
    result.update(
        status="recorded", code="native_bash_already_completed_output_not_retained", replayed=True, payload=None
    )
    validate_executed(result, request)
    output, errors = io.StringIO(), io.StringIO()
    assert sink.render_result(result, output=output, errors=errors) == 7
    assert output.getvalue() == ""
    assert "output_not_retained" in errors.getvalue()
    result["operation"].update(state="uncertain", completion=None)
    result["code"] = "native_bash_operation_in_progress_or_uncertain"
    validate_executed(result, request)
    assert sink.render_result(result, output=output, errors=errors) == 125


@pytest.mark.parametrize(
    "assurance",
    [
        "macos-readonly-root-framed-outputs-v1",
        "macos-readonly-root-http-read-v1",
        "macos-hardened-broker-v1",
    ],
)
def test_prepare_requires_native_consent_flag_and_assurance(assurance):
    payload = {
        "artifact_id": bridge.ARTIFACT_ID,
        "artifact_hash": "guard-approval-context:v1:fixture",
        "assessment": [],
        "consent_required": False,
        "review": {"decision": {}, "receipt": {}},
        "subject": {"schema": "guard.bash-subject.v1", "execution_assurance": assurance},
    }
    assert validate_prepared(payload) is payload
    payload["subject"]["execution_assurance"] = "macos-readonly-root-unbounded-v1"
    with pytest.raises(bridge.NativeBashError):
        validate_prepared(payload)
    payload["subject"]["execution_assurance"] = assurance
    payload["consent_required"] = 0
    with pytest.raises(bridge.NativeBashError):
        validate_prepared(payload)


@pytest.fixture
def store(tmp_path):
    lookup = {"decision": None, "ignored_local_integrity": None, "trust_status": {}}
    return SimpleNamespace(
        path=tmp_path / "guard.db",
        guard_home=tmp_path,
        resolve_policy_decision_lookup=Mock(return_value=lookup),
        _claim_integrity_evidence=Mock(return_value={"evidence_binding": {}}),
    )


def _prepared(consent=False):
    return {
        "artifact_id": bridge.ARTIFACT_ID,
        "artifact_hash": "guard-approval-context:v1:fixture",
        "consent_required": consent,
    }


def test_quiet_policy_does_not_mint_or_claim_consent(store, tmp_path):
    assert sink._authorization(store, _prepared(), harness="omp", workspace=tmp_path) == {
        "kind": "current_policy",
        "store_path": str(store.path),
    }
    assert store.resolve_policy_decision_lookup.call_args.kwargs["consume_one_shot"] is False
    store._claim_integrity_evidence.assert_not_called()


@pytest.mark.parametrize("failure", ["block", "integrity", "degraded"])
def test_sink_never_launders_missing_consent_or_saved_blocks(store, tmp_path, failure):
    lookup = store.resolve_policy_decision_lookup.return_value
    if failure == "block":
        lookup["decision"] = {"action": "block"}
    elif failure == "integrity":
        lookup["ignored_local_integrity"] = {}
    elif failure == "degraded":
        lookup["trust_status"] = {"remembered_rules": "disabled_degraded"}
    with pytest.raises(bridge.NativeBashError):
        sink._authorization(store, _prepared(True), harness="omp", workspace=tmp_path)
    store._claim_integrity_evidence.assert_not_called()


def test_missing_consent_reaches_native_journal_without_fabricating_a_grant(store, tmp_path):
    result = sink._authorization(store, _prepared(True), harness="omp", workspace=tmp_path)
    assert result == {"kind": "current_policy", "store_path": str(store.path)}
    store._claim_integrity_evidence.assert_not_called()


def test_replay_can_report_previously_spent_once_authority_to_an_unprivileged_query():
    request = _request()
    result = _result(request)
    result.update(
        status="recorded",
        code="native_bash_already_completed_output_not_retained",
        replayed=True,
        grant_claimed=True,
        payload=None,
    )
    result["operation"]["authorization"] = "saved_grant"
    validate_executed(result, request)
    result["grant_claimed"] = False
    with pytest.raises(bridge.NativeBashError):
        validate_executed(result, request)


def test_once_evidence_is_handed_to_native_without_spending_it(store, tmp_path):
    decision = {
        "action": "allow",
        "approval_id": "once-id",
        "harness": "omp",
        "workspace": str(tmp_path),
        "artifact_id": bridge.ARTIFACT_ID,
        "artifact_hash": "guard-approval-context:v1:fixture",
    }
    store.resolve_policy_decision_lookup.return_value["decision"] = decision
    result = sink._authorization(store, _prepared(True), harness="omp", workspace=tmp_path)
    assert result["kind"] == "saved_grant"
    assert result["claim"]["decisions"] == [decision]
    assert result["claim"]["consume_local_once"] is True
    store._claim_integrity_evidence.assert_called_once()
