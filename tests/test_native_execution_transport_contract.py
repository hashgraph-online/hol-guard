"""Native execution transport contracts, without Python execution fallbacks."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard import native_execution as bridge


@pytest.fixture
def transport(monkeypatch, tmp_path):
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "native-runtime", sha256="a" * 64),
        capabilities=SimpleNamespace(features=("resident-protocol-v2", "contained-execution-v1", "prompt-analyze-v1")),
    )
    client = Mock(return_value=b'{"status":"ok","result":{"decision":"block"}}')
    failed = Mock()
    succeeded = Mock()
    environment = {"PATH": str(tmp_path / "runtime-bin")}
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: status)
    monkeypatch.setattr(bridge, "native_resident_client_request", client)
    monkeypatch.setattr(bridge, "native_record_resident_failure", failed)
    monkeypatch.setattr(bridge, "native_record_resident_success", succeeded)
    monkeypatch.setattr(bridge, "_isolated_environment", lambda: environment)
    return SimpleNamespace(status=status, client=client, failed=failed, succeeded=succeeded, environment=environment)


def _request(home, request=None, operation="contained_execute", feature="contained-execution-v1"):
    return bridge._resident_request(
        operation=operation,
        request={} if request is None else request,
        guard_home=home,
        timeout_seconds=4.5,
        required_feature=feature,
    )


@pytest.mark.parametrize(
    "field,value", [("available", False), ("compatible", False), ("identity", None), ("capabilities", None)]
)
def test_unavailable_native_runtime_never_sends_a_request(transport, tmp_path, field, value):
    setattr(transport.status, field, value)
    assert _request(tmp_path) is None
    transport.client.assert_not_called()
    transport.succeeded.assert_not_called()


@pytest.mark.parametrize("features", [(), ("resident-protocol-v2",), ("contained-execution-v1",)])
def test_both_protocol_and_operation_capabilities_are_required(transport, tmp_path, features):
    transport.status.capabilities.features = features
    assert _request(tmp_path) is None
    transport.client.assert_not_called()
    transport.succeeded.assert_not_called()


@pytest.mark.parametrize("failure", ["non-json", "circular", "oversized"])
def test_unserializable_or_oversized_requests_never_reach_native_transport(transport, tmp_path, failure):
    request = {}
    if failure == "non-json":
        request["value"] = object()
    elif failure == "circular":
        request["value"] = request
    else:
        request["value"] = "x" * bridge._MAX_REQUEST_BYTES
    assert _request(tmp_path, request) is None
    transport.client.assert_not_called()
    transport.succeeded.assert_not_called()


@pytest.mark.parametrize("response,reason", [(None, "transport"), (b"\xff", "malformed"), (b"{", "malformed")])
def test_missing_or_malformed_native_reply_records_failure_not_success(transport, tmp_path, response, reason):
    transport.client.return_value = response
    assert _request(tmp_path) is None
    transport.failed.assert_called_once_with("a" * 64, tmp_path, reason=f"native_contained_execute_{reason}")
    transport.succeeded.assert_not_called()


@pytest.mark.parametrize("response", [b"[]", b"null", b"false", b'{"status":"error"}', b'{"result":{}}'])
def test_invalid_reply_envelopes_cannot_become_success(transport, tmp_path, response):
    transport.client.return_value = response
    assert _request(tmp_path) is None
    transport.succeeded.assert_not_called()


def test_native_transport_keeps_executable_home_environment_and_payload_bound(transport, tmp_path):
    request = {"workspace": str(tmp_path / "workspace"), "argv": ["node", "--version"]}
    assert _request(tmp_path, request) == {"status": "ok", "result": {"decision": "block"}}
    arguments = transport.client.call_args.kwargs
    assert arguments["executable"] == transport.status.identity.path
    assert arguments["guard_home"] == tmp_path
    assert arguments["environment"] is transport.environment
    assert arguments["timeout_seconds"] == 4.5
    assert json.loads(arguments["payload"]) == {
        "operation": "contained_execute",
        "request": request,
        "deadline_budget_ms": 4500,
    }
    transport.failed.assert_not_called()
    transport.succeeded.assert_called_once_with("a" * 64, tmp_path)


@pytest.mark.parametrize("result", [False, [], "review"])
def test_prompt_versioned_reply_preserves_native_false_and_empty_results(transport, tmp_path, result):
    reply = {"schema": "guard-prompt-analyze-result.v1", "result": result}
    transport.client.return_value = json.dumps(reply).encode()
    assert _request(tmp_path, operation="prompt_analyze", feature="prompt-analyze-v1") == reply
    transport.succeeded.assert_called_once_with("a" * 64, tmp_path)


@pytest.mark.parametrize(
    "reply",
    [
        {"schema": "guard-prompt-analyze-result.v2", "result": False},
        {"schema": "guard-prompt-analyze-result.v1"},
        {"schema": "guard-prompt-analyze-result.v1", "result": False, "status": "ok"},
    ],
)
def test_prompt_reply_requires_the_exact_versioned_envelope(transport, tmp_path, reply):
    transport.client.return_value = json.dumps(reply).encode()
    assert _request(tmp_path, operation="prompt_analyze", feature="prompt-analyze-v1") is None
    transport.succeeded.assert_not_called()


@pytest.mark.parametrize("result", [{"decision": "block"}, {}, [], False, None])
def test_generic_contained_execution_delegates_request_and_policy_to_rust(transport, tmp_path, result):
    transport.client.return_value = json.dumps({"status": "ok", "result": result}).encode()
    request = {"argv": ["node", "--version"]}
    policy = {"network": "denied"}
    actual = bridge.contained_execute_native(
        request, policy, guard_home=tmp_path, run_id="test-run", timeout_seconds=9.5
    )
    assert actual == (result if isinstance(result, dict) else None)
    envelope = json.loads(transport.client.call_args.kwargs["payload"])
    native_request = envelope["request"]
    assert envelope["operation"] == "contained_execute"
    assert native_request["schema"] == "guard-contained-execute-request.v1"
    assert native_request["request_id"].startswith("contained_execute-")
    assert native_request["request"] == request
    assert native_request["policy"] == policy
    assert native_request["guard_home"] == str(tmp_path)
    assert native_request["run_id"] == "test-run"
    assert transport.client.call_args.kwargs["timeout_seconds"] == 9.5


@pytest.mark.parametrize("result", [{"decision": "block"}, {}, [], False, None])
def test_contained_test_hook_delegates_workspace_and_command_to_rust(transport, tmp_path, result):
    transport.client.return_value = json.dumps({"status": "ok", "result": result}).encode()
    workspace = tmp_path / "workspace"
    actual = bridge.contained_test_hook_native(workspace, "node --version", guard_home=tmp_path, timeout_seconds=8.5)
    assert actual == (result if isinstance(result, dict) else None)
    envelope = json.loads(transport.client.call_args.kwargs["payload"])
    native_request = envelope["request"]
    assert envelope["operation"] == "contained_test_hook"
    assert native_request["schema"] == "guard-contained-test-hook-request.v1"
    assert native_request["request_id"].startswith("contained_test_hook-")
    assert native_request["workspace"] == str(workspace)
    assert native_request["command_text"] == "node --version"
    assert native_request["guard_home"] == str(tmp_path)
    assert transport.client.call_args.kwargs["timeout_seconds"] == 8.5


@pytest.mark.parametrize("operation", ["execute", "test-hook"])
def test_contained_adapters_report_missing_authority_without_fabricating_results(transport, tmp_path, operation):
    transport.client.return_value = None
    if operation == "execute":
        result = bridge.contained_execute_native({}, {}, guard_home=tmp_path, run_id="test-run")
    else:
        result = bridge.contained_test_hook_native(tmp_path, "node --version", guard_home=tmp_path)
    assert result is None
    transport.client.assert_called_once()
    transport.failed.assert_called_once()
    transport.succeeded.assert_not_called()


@pytest.mark.parametrize(
    "operation,feature,schema,status",
    [
        ("mcp_stdio_session_open", "mcp-stdio-session-v1", "guard-mcp-stdio-session-result.v1", "opened"),
        ("mcp_stdio_session_recv", "mcp-stdio-session-v1", "guard-mcp-stdio-session-result.v1", "timeout"),
        ("policy_decision_lookup", "policy-decision-lookup-v1", "guard-policy-decision-lookup-result.v1", "error"),
    ],
)
@pytest.mark.parametrize("schema_kind", ["matching", "wrong", "missing"])
def test_versioned_operation_replies_validate_schema_before_status(
    transport,
    tmp_path,
    operation,
    feature,
    schema,
    status,
    schema_kind,
):
    transport.status.capabilities.features = ("resident-protocol-v2", feature)
    reply = {"status": status, "code": "native_policy_decision_lookup_write_failed"}
    if schema_kind != "missing":
        reply["schema"] = schema if schema_kind == "matching" else "unrelated-result.v1"
    transport.client.return_value = json.dumps(reply).encode()
    actual = bridge._resident_request(
        operation=operation,
        request={},
        guard_home=tmp_path,
        timeout_seconds=1.0,
        required_feature=feature,
        response_schema=schema,
    )
    if schema_kind == "matching":
        assert actual == reply
        transport.succeeded.assert_called_once()
    else:
        assert actual is None
        transport.succeeded.assert_not_called()
        transport.failed.assert_called_once()


@pytest.mark.parametrize("result", [{"status": "ok", "tools": []}, {"status": "failed", "reason": "timeout"}])
def test_mcp_probe_accepts_native_result_without_outer_status(transport, tmp_path, result):
    transport.status.capabilities.features = ("resident-protocol-v2", "mcp-stdio-probe-v1")
    reply = {"schema": "guard-mcp-stdio-probe-result.v1", "result": result}
    transport.client.return_value = json.dumps(reply).encode()
    assert (
        bridge._resident_request(
            operation="mcp_stdio_probe",
            request={},
            guard_home=tmp_path,
            timeout_seconds=1.0,
            required_feature="mcp-stdio-probe-v1",
            response_schema="guard-mcp-stdio-probe-result.v1",
        )
        == reply
    )
