"""Proxy Cloud exception request creation to Guard Cloud."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse

from .store import GuardStore

_VALID_SCOPES = frozenset({"artifact", "publisher", "harness", "workspace"})

_VALID_COMMAND_POLICY_DURATIONS = frozenset({"once", "session", "machine", "workspace", "30d", "90d"})


class CloudExceptionRequestError(RuntimeError):
    status: int

    def __init__(self, message: str, *, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


def normalized_cloud_exception_requests_url(sync_url: str) -> str:
    parsed = urllib.parse.urlsplit(sync_url)
    if parsed.path.rstrip("/") == "/registry/api/v1/guard/receipts/sync":
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, "/registry/api/v1/guard/exceptions/requests", parsed.query, "")
        )
    if parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, "/api/guard/exceptions/requests", parsed.query, "")
        )
    if parsed.path.rstrip("/") == "/guard/receipts/sync":
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/guard/exceptions/requests", parsed.query, ""))
    base = sync_url.rstrip("/")
    if base.endswith("/receipts/sync"):
        return base[: -len("/receipts/sync")] + "/exceptions/requests"
    return urllib.parse.urljoin(base + "/", "exceptions/requests")


def _as_trimmed_string(value: object | None) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed if trimmed else None


def _scope_selector_present(payload: dict[str, object]) -> bool:
    scope = payload.get("scope")
    if scope == "artifact":
        return isinstance(payload.get("artifactId"), str) and bool(str(payload.get("artifactId")).strip())
    if scope == "publisher":
        return isinstance(payload.get("publisher"), str) and bool(str(payload.get("publisher")).strip())
    if scope == "harness":
        return isinstance(payload.get("harness"), str) and bool(str(payload.get("harness")).strip())
    if scope == "workspace":
        workspace_id = _as_trimmed_string(payload.get("workspaceId"))
        working_directory = _as_trimmed_string(payload.get("workingDirectory"))
        return workspace_id is not None or working_directory is not None
    return False


def validate_cloud_exception_request_payload(payload: dict[str, object]) -> dict[str, object]:
    scope = _as_trimmed_string(payload.get("scope"))
    if scope not in _VALID_SCOPES:
        raise ValueError("Guard exception request scope is invalid.")
    requested_by = _as_trimmed_string(payload.get("requestedBy"))
    reason = _as_trimmed_string(payload.get("reason"))
    owner = _as_trimmed_string(payload.get("owner"))
    requested_expires_at = _as_trimmed_string(payload.get("requestedExpiresAt"))
    if not requested_by or not reason or not owner or not requested_expires_at:
        raise ValueError("Guard exception request requires requester, owner, reason, and expiry.")
    source_receipt_id = _as_trimmed_string(payload.get("sourceReceiptId"))
    source_review_item_id = _as_trimmed_string(payload.get("sourceReviewItemId"))
    if not source_receipt_id and not source_review_item_id:
        raise ValueError("Guard exception request requires a source receipt or source review item.")
    normalized: dict[str, object] = {
        "scope": scope,
        "requestedBy": requested_by,
        "reason": reason,
        "owner": owner,
        "requestedExpiresAt": requested_expires_at,
    }
    for key in (
        "harness",
        "artifactId",
        "publisher",
        "sourceReceiptId",
        "sourceReviewItemId",
        "projectId",
        "workspaceId",
        "workingDirectory",
        "teamId",
        "stepUpChallengeId",
    ):
        value = _as_trimmed_string(payload.get(key))
        if value is not None:
            normalized[key] = value
    if not _scope_selector_present(normalized):
        raise ValueError("Guard exception request must include a selector for its scope.")
    return normalized


def validate_command_policy_exception_payload(payload: dict[str, object]) -> dict[str, object]:
    """Validate a command-policy exception request payload.

    The payload carries only correlation identifiers — never raw command,
    regex, graph, or policy action. The Cloud re-fetches the bound
    pending command server-side.

    Required fields:
      - kind: must be "command-policy"
      - sourceLocalRequestId: stable local request id from the queue
      - sourceMachineInstallationId: machine that observed the command
      - workspaceId: workspace binding
      - requestedDuration: once | session | machine | workspace | 30d | 90d
      - reason: at least 8 characters

    Forbidden keys (rejected if present):
      - rawCommand, command, commandExpression, graph, proposedGraph
      - owner, requestedBy (the Cloud resolves these from auth)
    """
    kind = _as_trimmed_string(payload.get("kind"))
    if kind != "command-policy":
        raise ValueError("Command-policy exception request requires kind='command-policy'.")

    # Reject forbidden keys — no command/graph/policy material crosses
    # the dashboard-to-Cloud boundary.
    forbidden_keys = frozenset(
        {
            "rawCommand",
            "command",
            "commandExpression",
            "graph",
            "proposedGraph",
            "expression",
            "regex",
            "pattern",
        }
    )
    for key in forbidden_keys:
        if key in payload:
            raise ValueError(f"Command-policy request must not include '{key}'.")

    source_local_request_id = _as_trimmed_string(payload.get("sourceLocalRequestId"))
    source_machine_installation_id = _as_trimmed_string(payload.get("sourceMachineInstallationId"))
    workspace_id = _as_trimmed_string(payload.get("workspaceId"))
    requested_duration = _as_trimmed_string(payload.get("requestedDuration"))
    reason = _as_trimmed_string(payload.get("reason"))

    if not source_local_request_id:
        raise ValueError("Command-policy request requires sourceLocalRequestId.")
    if not source_machine_installation_id:
        raise ValueError("Command-policy request requires sourceMachineInstallationId.")
    if not workspace_id:
        raise ValueError("Command-policy request requires workspaceId.")
    if not requested_duration or requested_duration not in _VALID_COMMAND_POLICY_DURATIONS:
        raise ValueError("Command-policy request has an invalid requestedDuration.")
    if not reason or len(reason) < 8:
        raise ValueError("Command-policy request requires a reason of at least 8 characters.")

    normalized: dict[str, object] = {
        "kind": "command-policy",
        "sourceLocalRequestId": source_local_request_id,
        "sourceMachineInstallationId": source_machine_installation_id,
        "workspaceId": workspace_id,
        "requestedDuration": requested_duration,
        "reason": reason,
    }
    # Optional note (max 500 chars).
    note = _as_trimmed_string(payload.get("note"))
    if note:
        if len(note) > 500:
            raise ValueError("Command-policy request note must be at most 500 characters.")
        normalized["note"] = note
    # Optional signed claim.
    signed_claim = _as_trimmed_string(payload.get("signedClaim"))
    if signed_claim:
        normalized["signedClaim"] = signed_claim
    return normalized


def _guard_cloud_exception_sync_request(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None,
    method: str,
    data: bytes | None,
    invalid_response_message: str,
) -> dict[str, object]:
    from codex_plugin_scanner.guard.runtime.runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotConfiguredError,
        _guard_sync_request,
        _resolve_guard_sync_auth_context,
        _sync_http_error_message,
        _sync_url_error_message,
        _urlopen_json_with_timeout_retry,
        prepare_guard_cloud_connect_authorization,
    )

    try:
        prepare_guard_cloud_connect_authorization(store)
        resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    except GuardSyncAuthorizationExpiredError as error:
        raise CloudExceptionRequestError(str(error), status=401) from error
    except GuardSyncNotConfiguredError as error:
        raise CloudExceptionRequestError(str(error), status=401) from error
    request_url = normalized_cloud_exception_requests_url(str(resolved_auth_context["sync_url"]))
    request = _guard_sync_request(
        resolved_auth_context,
        request_url=request_url,
        method=method,
        data=data,
        extra_headers=None,
    )
    try:
        response = _urlopen_json_with_timeout_retry(request=request, timeout_seconds=30, retry_timeout_seconds=45)
    except urllib.error.HTTPError as error:
        status = error.code if error.code in {400, 401, 403, 409, 422} else 502
        raise CloudExceptionRequestError(_sync_http_error_message(error), status=status) from error
    except OSError as error:
        raise CloudExceptionRequestError(_sync_url_error_message(error), status=502) from error
    if not isinstance(response, dict):
        raise CloudExceptionRequestError(invalid_response_message, status=502)
    return response


def submit_command_policy_exception_request(
    store: GuardStore,
    payload: dict[str, object],
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Submit a command-policy exception request to Guard Cloud.

    Uses the same Cloud sync auth as the resource-exception path.
    The Cloud re-fetches the bound pending command server-side using
    the correlation identifiers — no raw command is transmitted.
    """
    normalized = validate_command_policy_exception_payload(payload)
    return _guard_cloud_exception_sync_request(
        store,
        auth_context=auth_context,
        method="POST",
        data=json.dumps(normalized).encode("utf-8"),
        invalid_response_message="Guard Cloud command-policy request returned an invalid response.",
    )


def submit_cloud_exception_request(
    store: GuardStore,
    payload: dict[str, object],
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    normalized = validate_cloud_exception_request_payload(payload)
    return _guard_cloud_exception_sync_request(
        store,
        auth_context=auth_context,
        method="POST",
        data=json.dumps(normalized).encode("utf-8"),
        invalid_response_message="Guard Cloud exception request returned an invalid response.",
    )


def fetch_cloud_exception_requests(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    return _guard_cloud_exception_sync_request(
        store,
        auth_context=auth_context,
        method="GET",
        data=None,
        invalid_response_message="Guard Cloud exception request list returned an invalid response.",
    )
