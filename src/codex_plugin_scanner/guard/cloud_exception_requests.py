"""Proxy Cloud exception request creation to Guard Cloud."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
from typing import Any

from .store import GuardStore

_VALID_SCOPES = frozenset({"artifact", "publisher", "harness", "workspace"})
_STEP_UP_SCOPES = frozenset({"harness", "workspace"})


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
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, "/guard/exceptions/requests", parsed.query, "")
        )
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


def submit_cloud_exception_request(
    store: GuardStore,
    payload: dict[str, object],
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    from codex_plugin_scanner.guard.runtime.runner import (
        _guard_sync_request,
        _resolve_guard_sync_auth_context,
        _sync_http_error_message,
        _sync_url_error_message,
        _urlopen_json_with_timeout_retry,
        prepare_guard_cloud_connect_authorization,
    )

    normalized = validate_cloud_exception_request_payload(payload)
    prepare_guard_cloud_connect_authorization(store)
    resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    request_url = normalized_cloud_exception_requests_url(str(resolved_auth_context["sync_url"]))
    body = json.dumps(normalized).encode("utf-8")
    request = _guard_sync_request(
        resolved_auth_context,
        request_url=request_url,
        method="POST",
        data=body,
        extra_headers=None,
    )
    try:
        response = _urlopen_json_with_timeout_retry(request=request, timeout_seconds=30, retry_timeout_seconds=45)
    except urllib.error.HTTPError as error:
        raise RuntimeError(_sync_http_error_message(error)) from error
    except OSError as error:
        raise RuntimeError(_sync_url_error_message(error)) from error
    if not isinstance(response, dict):
        raise RuntimeError("Guard Cloud exception request returned an invalid response.")
    return response


def cloud_exception_request_error_status(message: str) -> int:
    lowered = message.lower()
    if "not logged in" in lowered or "reauthoriz" in lowered:
        return 401
    if "invalid" in lowered or "requires" in lowered or "must include" in lowered:
        return 400
    return 502
