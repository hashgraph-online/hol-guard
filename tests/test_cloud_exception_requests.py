"""Cloud exception request proxy helpers."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.cloud_exception_requests import (
    CloudExceptionRequestError,
    normalized_cloud_exception_requests_url,
    validate_cloud_exception_request_payload,
)


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
