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
        capabilities=SimpleNamespace(
            features=(
                "resident-protocol-v2",
                "contained-execution-v1",
                "prompt-analyze-v2",
                "shim-admin-v4",
            )
        ),
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


def _request(home, request=None, operation="shim_admin", feature="shim-admin-v4"):
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


@pytest.mark.parametrize("features", [(), ("resident-protocol-v2",), ("shim-admin-v4",)])
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
    transport.failed.assert_called_once_with("a" * 64, tmp_path, reason=f"native_shim_admin_{reason}")
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
        "operation": "shim_admin",
        "request": request,
        "deadline_budget_ms": 4500,
    }
    transport.failed.assert_not_called()
    transport.succeeded.assert_called_once_with("a" * 64, tmp_path)


@pytest.mark.parametrize("result", [False, [], "review"])
def test_prompt_versioned_reply_preserves_native_false_and_empty_results(transport, tmp_path, result):
    reply = {"schema": "guard-prompt-analyze-result.v1", "result": result}
    transport.client.return_value = json.dumps(reply).encode()
    assert _request(tmp_path, operation="prompt_analyze", feature="prompt-analyze-v2") == reply
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
    assert _request(tmp_path, operation="prompt_analyze", feature="prompt-analyze-v2") is None
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


def test_hook_render_bound_error_is_not_a_resident_outage(transport, tmp_path):
    transport.status.capabilities.features = ("resident-protocol-v2", "hook-render-v2")
    reply = {
        "schema": "guard-hook-render-result.v1",
        "status": "error",
        "code": "native_hook_render_invalid",
        "request_id": "hook-render-1",
        "request_sha256": "sha256:" + "ab" * 32,
    }
    transport.client.return_value = json.dumps(reply).encode()
    actual = bridge._resident_request(
        operation="hook_render",
        request={"schema": "guard-hook-render-request.v1"},
        guard_home=tmp_path,
        timeout_seconds=1.0,
        required_feature="hook-render-v2",
        response_schema="guard-hook-render-result.v1",
        record_success=False,
    )
    assert actual == reply
    transport.failed.assert_not_called()
    transport.succeeded.assert_not_called()


def test_hook_render_unknown_status_still_records_a_failure(transport, tmp_path):
    transport.status.capabilities.features = ("resident-protocol-v2", "hook-render-v2")
    reply = {"schema": "guard-hook-render-result.v1", "status": "boom", "code": "native_hook_render_invalid"}
    transport.client.return_value = json.dumps(reply).encode()
    assert (
        bridge._resident_request(
            operation="hook_render",
            request={},
            guard_home=tmp_path,
            timeout_seconds=1.0,
            required_feature="hook-render-v2",
            response_schema="guard-hook-render-result.v1",
            record_success=False,
        )
        is None
    )
    transport.failed.assert_called_once_with("a" * 64, tmp_path, reason="native_hook_render_status")
    transport.succeeded.assert_not_called()


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


def test_hook_authority_state_bound_error_is_not_a_resident_failure(transport, tmp_path):
    transport.status.capabilities.features = (
        "resident-protocol-v2",
        "hook-authority-state-v1",
    )
    reply = {
        "schema": "guard-hook-authority-state-result.v1",
        "status": "error",
        "code": "native_hook_authority_state_store_unavailable",
    }
    transport.client.return_value = json.dumps(reply).encode()
    actual = bridge._resident_request(
        operation="hook_authority_state",
        request={"request_id": "hook-authority-state-error"},
        guard_home=tmp_path,
        timeout_seconds=5.0,
        required_feature="hook-authority-state-v1",
        response_schema="guard-hook-authority-state-result.v1",
        record_success=False,
    )
    assert actual == reply
    transport.failed.assert_not_called()
    transport.succeeded.assert_not_called()


@pytest.mark.parametrize("runner", ["node", "typescript", "package_script", "workspace_write"])
def test_contained_runner_replies_are_accepted_without_outer_status(transport, tmp_path, runner):
    reply = {"schema": f"guard-contained-{runner.replace('_', '-')}-execute-result.v1", "result": {"stdout": ""}}
    transport.client.return_value = json.dumps(reply).encode()
    assert (
        bridge._resident_request(
            operation=f"contained_{runner}_execute",
            request={},
            guard_home=tmp_path,
            timeout_seconds=1.0,
            required_feature="contained-execution-v1",
        )
        == reply
    )
    transport.succeeded.assert_called_once_with("a" * 64, tmp_path)


def test_containment_health_probe_reply_reaches_the_caller(transport, tmp_path):
    """The resident answers with a status-free versioned reply, as the contained runners do."""
    result = {"enforced": True}
    reply = {"schema": "guard-containment-health-probe-result.v1", "result": result}
    transport.client.return_value = json.dumps(reply).encode()
    assert bridge.containment_health_probe_native(daemon_fingerprint="f" * 64, guard_home=tmp_path) == result
    envelope = json.loads(transport.client.call_args.kwargs["payload"])
    # The resident clamps this operation to 15 seconds; asking for less leaves
    # the worst-case probe and reap with almost no room for start-up.
    assert envelope["deadline_budget_ms"] == 15_000
    transport.client.return_value = json.dumps({**reply, "status": "ok"}).encode()
    assert bridge.containment_health_probe_native(daemon_fingerprint="f" * 64, guard_home=tmp_path) is None


def test_contained_runner_transport_budget_covers_resident_overhead(transport, tmp_path):
    transport.client.return_value = b'{"schema":"guard-contained-node-execute-result.v1","result":null}'
    bridge._contained_runner_request(
        op_prefix="contained_node_execute",
        request_schema="guard-contained-node-execute-request.v1",
        workspace=tmp_path,
        manager="npx",
        argv=("--no-install", "vitest", "run"),
        guard_home=tmp_path,
        shim_directory=tmp_path,
        environment={},
        timeout_seconds=100.0,
        evidence=None,
    )
    envelope = json.loads(transport.client.call_args.kwargs["payload"])
    assert envelope["deadline_budget_ms"] >= 100_000 + 60_000
    assert transport.client.call_args.kwargs["timeout_seconds"] >= 160.0


@pytest.mark.parametrize(
    "frame,expected",
    [
        ({"error": "native_client_auth_timeout_failed", "retryable": False}, "native_client_auth_timeout_failed"),
        ({"error": "not-a-finite-code", "retryable": False}, None),
        ({"error": 7}, None),
    ],
)
def test_framed_resident_refusal_keeps_its_finite_code(transport, tmp_path, frame, expected):
    from codex_plugin_scanner.guard.native_resident_client import (
        native_resident_client_failure_code,
        record_native_resident_client_failure_code,
    )

    record_native_resident_client_failure_code(None)
    transport.client.return_value = json.dumps(frame).encode()
    response = bridge._resident_request(
        operation="daemon_lifecycle_decide",
        request={},
        guard_home=tmp_path,
        timeout_seconds=4.5,
        required_feature="contained-execution-v1",
        response_schema="guard-daemon-lifecycle-decision-result.v1",
        record_success=False,
    )
    assert response is None
    assert native_resident_client_failure_code() == expected
    transport.failed.assert_called_once_with("a" * 64, tmp_path, reason="native_daemon_lifecycle_decide_schema")


def test_contained_execute_reply_reaches_the_caller(transport, tmp_path):
    """The contained execute op answers with a status-free versioned reply."""
    result = {"exit_code": 0, "enforcement": "bubblewrap"}
    transport.client.return_value = json.dumps(
        {"schema": "guard-contained-execute-result.v1", "result": result}
    ).encode()
    request = {
        "schema_version": "containment-contract-v1",
        "kind": "probe",
        "argv": ["/bin/true"],
        "cwd": str(tmp_path),
        "env_allowlist": [],
        "timeout_seconds": 60,
        "max_output_bytes": 1024,
        "additional_read_paths": [],
        "allow_outbound_network": False,
    }
    policy = {"schema_version": "containment-contract-v1", "action": "run"}
    assert bridge.contained_execute_native(request, policy, guard_home=tmp_path, run_id="probe-1") == result
    envelope = json.loads(transport.client.call_args.kwargs["payload"])
    # The resident clamps this operation at the contract's one-hour request
    # timeout plus the client's transport slack, so a minute-long contained run
    # keeps the budget its own timeout earns.
    assert envelope["deadline_budget_ms"] == 90_000
    assert transport.client.call_args.kwargs["timeout_seconds"] == 90.0
    # A reply carrying an outer status is not this operation's shape.
    transport.client.return_value = json.dumps(
        {"schema": "guard-contained-execute-result.v1", "result": result, "status": "ok"}
    ).encode()
    assert bridge.contained_execute_native(request, policy, guard_home=tmp_path, run_id="probe-1") is None
