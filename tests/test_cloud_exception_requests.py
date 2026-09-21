"""Cloud exception request proxy helpers."""

from __future__ import annotations

import email.message
import io
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cloud_exception_requests import (
    CloudExceptionRequestError,
    fetch_cloud_exception_requests,
    normalized_cloud_exception_requests_url,
    submit_cloud_exception_request,
    submit_command_policy_exception_request,
    validate_cloud_exception_request_payload,
    validate_command_policy_exception_payload,
)
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore


def test_normalized_cloud_exception_requests_url_from_sync_url() -> None:
    assert (
        normalized_cloud_exception_requests_url("https://hol.org/api/guard/receipts/sync")
        == "https://hol.org/api/guard/exceptions/requests"
    )


def test_validate_cloud_exception_request_payload_requires_source_receipt() -> None:
    with pytest.raises(ValueError, match="source receipt"):
        validate_cloud_exception_request_payload(
            {
                "scope": "artifact",
                "requestedBy": "requester@example.com",
                "owner": "owner@example.com",
                "reason": "Temporary acceptance for a blocked package.",
                "requestedExpiresAt": "2026-12-31T00:00:00.000Z",
                "artifactId": "pkg:npm/example",
                "harness": "codex",
            }
        )


def test_validate_cloud_exception_request_payload_normalizes_artifact_scope() -> None:
    payload = validate_cloud_exception_request_payload(
        {
            "scope": "artifact",
            "requestedBy": "requester@example.com",
            "owner": "owner@example.com",
            "reason": "Temporary acceptance for a blocked package.",
            "requestedExpiresAt": "2026-12-31T00:00:00.000Z",
            "sourceReceiptId": "receipt_demo_001",
            "artifactId": "pkg:npm/example",
            "harness": "codex",
        }
    )
    assert payload["scope"] == "artifact"
    assert payload["sourceReceiptId"] == "receipt_demo_001"


def test_validate_cloud_exception_request_payload_accepts_source_review_item() -> None:
    payload = validate_cloud_exception_request_payload(
        {
            "scope": "workspace",
            "requestedBy": "requester@example.com",
            "owner": "owner@example.com",
            "reason": "Temporary acceptance for this project.",
            "requestedExpiresAt": "2026-12-31T00:00:00.000Z",
            "sourceReviewItemId": "request-local-42",
            "workingDirectory": "/tmp/project",
        }
    )
    assert payload["sourceReviewItemId"] == "request-local-42"
    assert "sourceReceiptId" not in payload


def test_validate_cloud_exception_request_payload_requires_workspace_selector() -> None:
    with pytest.raises(ValueError, match="selector"):
        validate_cloud_exception_request_payload(
            {
                "scope": "workspace",
                "requestedBy": "requester@example.com",
                "owner": "owner@example.com",
                "reason": "Temporary acceptance for this project.",
                "requestedExpiresAt": "2026-12-31T00:00:00.000Z",
                "sourceReceiptId": "receipt_demo_001",
            }
        )


def test_cloud_exception_request_error_carries_http_status() -> None:
    error = CloudExceptionRequestError("Guard is not logged in.", status=401)
    assert error.status == 401


# ---------------------------------------------------------------------------
# Command-policy exception request validator tests
# ---------------------------------------------------------------------------


def test_validate_command_policy_payload_rejects_missing_kind() -> None:
    with pytest.raises(ValueError, match="kind='command-policy'"):
        validate_command_policy_exception_payload(
            {
                "sourceLocalRequestId": "req-001",
                "sourceMachineInstallationId": "machine-001",
                "workspaceId": "ws-001",
                "requestedDuration": "once",
                "reason": "Needs temporary access.",
            }
        )


def test_validate_command_policy_payload_rejects_raw_command() -> None:
    with pytest.raises(ValueError, match="must not include 'rawCommand'"):
        validate_command_policy_exception_payload(
            {
                "kind": "command-policy",
                "sourceLocalRequestId": "req-001",
                "sourceMachineInstallationId": "machine-001",
                "workspaceId": "ws-001",
                "requestedDuration": "once",
                "reason": "Needs temporary access.",
                "rawCommand": "rm -rf /",
            }
        )


def test_validate_command_policy_payload_rejects_graph_injection() -> None:
    with pytest.raises(ValueError, match="must not include 'graph'"):
        validate_command_policy_exception_payload(
            {
                "kind": "command-policy",
                "sourceLocalRequestId": "req-001",
                "sourceMachineInstallationId": "machine-001",
                "workspaceId": "ws-001",
                "requestedDuration": "once",
                "reason": "Needs temporary access.",
                "graph": {"nodes": []},
            }
        )


def test_validate_command_policy_payload_rejects_short_reason() -> None:
    with pytest.raises(ValueError, match="at least 8 characters"):
        validate_command_policy_exception_payload(
            {
                "kind": "command-policy",
                "sourceLocalRequestId": "req-001",
                "sourceMachineInstallationId": "machine-001",
                "workspaceId": "ws-001",
                "requestedDuration": "once",
                "reason": "short",
            }
        )


def test_validate_command_policy_payload_rejects_invalid_duration() -> None:
    with pytest.raises(ValueError, match="invalid requestedDuration"):
        validate_command_policy_exception_payload(
            {
                "kind": "command-policy",
                "sourceLocalRequestId": "req-001",
                "sourceMachineInstallationId": "machine-001",
                "workspaceId": "ws-001",
                "requestedDuration": "persistent",
                "reason": "Needs temporary access.",
            }
        )


def test_validate_command_policy_payload_rejects_missing_local_request_id() -> None:
    with pytest.raises(ValueError, match="sourceLocalRequestId"):
        validate_command_policy_exception_payload(
            {
                "kind": "command-policy",
                "sourceMachineInstallationId": "machine-001",
                "workspaceId": "ws-001",
                "requestedDuration": "once",
                "reason": "Needs temporary access.",
            }
        )


def test_validate_command_policy_payload_normalizes_valid_input() -> None:
    normalized = validate_command_policy_exception_payload(
        {
            "kind": "command-policy",
            "sourceLocalRequestId": "req-001",
            "sourceMachineInstallationId": "machine-001",
            "workspaceId": "ws-001",
            "requestedDuration": "workspace",
            "reason": "Needs temporary workspace access for CI.",
            "note": "CI runner exception",
        }
    )
    assert normalized["kind"] == "command-policy"
    assert normalized["sourceLocalRequestId"] == "req-001"
    assert normalized["sourceMachineInstallationId"] == "machine-001"
    assert normalized["workspaceId"] == "ws-001"
    assert normalized["requestedDuration"] == "workspace"
    assert "rawCommand" not in normalized
    assert "graph" not in normalized
    assert "command" not in normalized
    assert normalized["note"] == "CI runner exception"


def test_validate_command_policy_payload_proves_no_command_crosses_boundary() -> None:
    """The single most important test: prove no raw command, regex,
    pattern, graph, or expression key survives validation."""
    forbidden = [
        "rawCommand",
        "command",
        "commandExpression",
        "expression",
        "regex",
        "pattern",
        "graph",
        "proposedGraph",
    ]
    normalized = validate_command_policy_exception_payload(
        {
            "kind": "command-policy",
            "sourceLocalRequestId": "req-001",
            "sourceMachineInstallationId": "machine-001",
            "workspaceId": "ws-001",
            "requestedDuration": "session",
            "reason": "Needs temporary session access for CI.",
        }
    )
    for key in forbidden:
        assert key not in normalized, f"Forbidden key '{key}' leaked into normalized payload"


_VALID_RESOURCE_EXCEPTION_PAYLOAD: dict[str, object] = {
    "scope": "workspace",
    "requestedBy": "analyst",
    "reason": "Legitimate pipeline step needs a temporary exception.",
    "owner": "owner@hol.org",
    "requestedExpiresAt": "2026-10-01T00:00:00Z",
    "sourceReceiptId": "receipt-001",
    "workspaceId": "workspace-alpha",
}

_VALID_COMMAND_POLICY_PAYLOAD: dict[str, object] = {
    "kind": "command-policy",
    "sourceLocalRequestId": "req-001",
    "sourceMachineInstallationId": "machine-001",
    "workspaceId": "ws-001",
    "requestedDuration": "session",
    "reason": "Needs temporary session access for CI.",
}


def _hermetic_sync_context(monkeypatch: pytest.MonkeyPatch, response: object) -> list[urllib.request.Request]:
    """Patch the Cloud sync request path hermetically; return the captured requests."""
    monkeypatch.setattr(
        guard_runner_module,
        "prepare_guard_cloud_connect_authorization",
        lambda _store: {"repaired_storage": False, "cleared_stale_sign_in": False, "existing_sign_in_valid": True},
    )
    monkeypatch.setattr(
        guard_runner_module,
        "_test_sync_auth_context_override",
        {
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "demo-token",
            "dpop_key_material": None,
        },
    )
    captured: list[urllib.request.Request] = []

    def _fake_urlopen_json(*, request: urllib.request.Request, **_kwargs: object) -> object:
        captured.append(request)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(guard_runner_module, "_urlopen_json_with_timeout_retry", _fake_urlopen_json)
    return captured


def test_submit_cloud_exception_request_posts_normalized_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    captured = _hermetic_sync_context(monkeypatch, {"requestId": "exc-1", "status": "pending"})

    result = submit_cloud_exception_request(store, dict(_VALID_RESOURCE_EXCEPTION_PAYLOAD))

    assert result == {"requestId": "exc-1", "status": "pending"}
    request = captured[0]
    assert request.full_url == "https://hol.org/api/guard/exceptions/requests"
    assert request.get_method() == "POST"
    assert isinstance(request.data, bytes)
    assert json.loads(request.data.decode("utf-8")) == validate_cloud_exception_request_payload(
        dict(_VALID_RESOURCE_EXCEPTION_PAYLOAD)
    )
    assert request.headers.get("Authorization") == "Bearer demo-token"


def test_submit_command_policy_exception_request_uses_same_sync_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    captured = _hermetic_sync_context(monkeypatch, {"requestId": "policy-1"})

    result = submit_command_policy_exception_request(store, dict(_VALID_COMMAND_POLICY_PAYLOAD))

    assert result == {"requestId": "policy-1"}
    request = captured[0]
    assert request.full_url == "https://hol.org/api/guard/exceptions/requests"
    assert isinstance(request.data, bytes)
    body = json.loads(request.data.decode("utf-8"))
    assert body["kind"] == "command-policy"
    assert "rawCommand" not in body and "command" not in body


def test_fetch_cloud_exception_requests_uses_explicit_auth_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    captured = _hermetic_sync_context(monkeypatch, {"requests": []})

    result = fetch_cloud_exception_requests(
        store,
        auth_context={
            "sync_url": "https://cloud.example/registry/api/v1/guard/receipts/sync",
            "access_token": "explicit-token",
            "dpop_key_material": None,
        },
    )

    assert result == {"requests": []}
    request = captured[0]
    assert request.full_url == "https://cloud.example/registry/api/v1/guard/exceptions/requests"
    assert request.get_method() == "GET"
    assert request.data is None
    assert request.headers.get("Authorization") == "Bearer explicit-token"


def test_sync_request_maps_http_error_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _hermetic_sync_context(
        monkeypatch,
        urllib.error.HTTPError(
            url="https://hol.org/api/guard/exceptions/requests",
            code=409,
            msg="Conflict",
            hdrs=email.message.Message(),
            fp=io.BytesIO(b'{"error": "request already exists"}'),
        ),
    )

    with pytest.raises(CloudExceptionRequestError) as excinfo:
        submit_cloud_exception_request(store, dict(_VALID_RESOURCE_EXCEPTION_PAYLOAD))

    assert excinfo.value.status == 409
    assert "request already exists" in str(excinfo.value)


def test_sync_request_maps_server_http_error_to_502(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _hermetic_sync_context(
        monkeypatch,
        urllib.error.HTTPError(
            url="https://hol.org/api/guard/exceptions/requests",
            code=500,
            msg="Internal Server Error",
            hdrs=email.message.Message(),
            fp=io.BytesIO(b""),
        ),
    )

    with pytest.raises(CloudExceptionRequestError) as excinfo:
        fetch_cloud_exception_requests(store)

    assert excinfo.value.status == 502


def test_sync_request_maps_transport_error_to_502(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _hermetic_sync_context(monkeypatch, urllib.error.URLError("connection refused"))

    with pytest.raises(CloudExceptionRequestError) as excinfo:
        submit_cloud_exception_request(store, dict(_VALID_RESOURCE_EXCEPTION_PAYLOAD))

    assert excinfo.value.status == 502
    assert "connection refused" in str(excinfo.value)


def test_sync_request_rejects_non_dict_response(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _hermetic_sync_context(monkeypatch, ["not", "a", "dict"])

    with pytest.raises(CloudExceptionRequestError) as excinfo:
        submit_cloud_exception_request(store, dict(_VALID_RESOURCE_EXCEPTION_PAYLOAD))

    assert excinfo.value.status == 502
    assert "invalid response" in str(excinfo.value)


def test_sync_request_maps_not_configured_to_401(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(guard_runner_module, "_test_sync_auth_context_override", None)
    monkeypatch.setattr(
        guard_runner_module,
        "prepare_guard_cloud_connect_authorization",
        lambda _store: {"repaired_storage": False, "cleared_stale_sign_in": False, "existing_sign_in_valid": False},
    )

    def _raise_not_configured(_store: object) -> dict[str, object]:
        raise guard_runner_module.GuardSyncNotConfiguredError("Guard is not logged in.")

    _ = monkeypatch.setattr(guard_runner_module, "_resolve_guard_sync_auth_context", _raise_not_configured)

    with pytest.raises(CloudExceptionRequestError) as excinfo:
        submit_cloud_exception_request(store, dict(_VALID_RESOURCE_EXCEPTION_PAYLOAD))

    assert excinfo.value.status == 401
    assert "not logged in" in str(excinfo.value)


def test_sync_request_maps_expired_authorization_to_401(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")

    def _raise_expired(_store: object) -> dict[str, object]:
        raise guard_runner_module.GuardSyncAuthorizationExpiredError("Run `hol-guard connect` to sign in again.")

    _ = monkeypatch.setattr(guard_runner_module, "prepare_guard_cloud_connect_authorization", _raise_expired)

    with pytest.raises(CloudExceptionRequestError) as excinfo:
        fetch_cloud_exception_requests(store)

    assert excinfo.value.status == 401
    assert "connect" in str(excinfo.value)
