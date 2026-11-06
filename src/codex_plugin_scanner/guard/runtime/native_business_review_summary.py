"""Local presentation adapter; policy and snapshot authority remain native."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..native_resident_client import native_resident_client_request
from ..native_runtime import _isolated_environment, native_runtime_status

_FEATURE = "native-local-business-review-summary-v1"
_FIELDS = frozenset(
    {
        "schema",
        "version",
        "request_id",
        "request_snapshot_digest",
        "prepared_input_binding",
        "service",
        "operation",
        "audience_kind",
        "audience_expansion_state",
        "recipient_count",
        "record_count",
        "byte_count",
        "attachment_count",
        "inspection_state",
        "sensitivity_labels",
        "snapshot_fact_completeness",
        "account_currentness",
        "execution_state",
    }
)
_COUNTS = ("recipient_count", "record_count", "byte_count", "attachment_count")
_STATES = frozenset({"known", "unknown", "unsupported"})
_LABELS = frozenset({"public", "personal", "confidential", "secret", "unknown"})
_SERVICES = {
    "google_gmail": frozenset(
        {"mail_read", "mail_draft", "mail_send", "mail_label", "mail_permanent_delete", "mail_settings"}
    ),
    "google_drive": frozenset({"drive_read", "drive_edit", "drive_share", "drive_export"}),
    "google_calendar": frozenset({"calendar_read", "calendar_invite"}),
}


def valid_business_review_summary(value: object, request_id: str) -> dict[str, object] | None:
    """Check the finite presentation wire shape, never infer a policy decision."""
    if not isinstance(value, dict) or set(value) != _FIELDS:
        return None
    if (
        value["schema"] != "guard-native-local-business-review-summary.v1"
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["request_id"] != request_id
        or value["account_currentness"] != "not_asserted"
        or value["execution_state"] != "not_checked"
    ):
        return None
    for name in ("request_snapshot_digest", "prepared_input_binding"):
        if not isinstance(value[name], str) or re.fullmatch(r"[0-9a-f]{64}", value[name]) is None:
            return None
    service, operation = value["service"], value["operation"]
    if not isinstance(service, str) or not isinstance(operation, str) or operation not in _SERVICES.get(service, ()):
        return None
    if not isinstance(value["audience_kind"], str) or value["audience_kind"] not in {
        "private",
        "named",
        "public",
        "unknown",
    }:
        return None
    for name in ("audience_expansion_state", "inspection_state", "snapshot_fact_completeness"):
        if not isinstance(value[name], str) or value[name] not in _STATES:
            return None
    if any(type(value[name]) is not int or not 0 <= value[name] <= (1 << 53) - 1 for name in _COUNTS):
        return None
    labels = value["sensitivity_labels"]
    if not isinstance(labels, list) or len(labels) > len(_LABELS):
        return None
    if any(not isinstance(label, str) or label not in _LABELS for label in labels) or len(set(labels)) != len(labels):
        return None
    return dict(value)


class NativeBusinessReviewSummaryReadError(RuntimeError):
    """Finite presentation failure; private native details are never echoed."""

    def __init__(self) -> None:
        super().__init__("native_local_business_summary_read_failed")


def read_native_business_review_summary(guard_home: Path, request_id: str) -> dict[str, object] | None:
    """Read an existing frozen snapshot. Never stage, approve, or dispatch work."""
    if not isinstance(request_id, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", request_id) is None:
        return None
    try:
        status = native_runtime_status()
        if not status.available:
            return None
        if not status.compatible or status.identity is None or status.capabilities is None:
            raise NativeBusinessReviewSummaryReadError()
        if not {"resident-protocol-v2", _FEATURE}.issubset(status.capabilities.features):
            return None
        payload = json.dumps(
            {"operation": "workspace_review_local_summary", "request": {"request_id": request_id}},
            separators=(",", ":"),
        ).encode("utf-8")
        encoded = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=payload,
            timeout_seconds=2.0,
        )
        if encoded is None:
            raise NativeBusinessReviewSummaryReadError()
        response = json.loads(encoded.decode("utf-8"))
        if (
            isinstance(response, dict)
            and set(response) in ({"error"}, {"error", "retryable"})
            and ("retryable" not in response or type(response["retryable"]) is bool)
            and response["error"]
            in (
                "native_local_business_summary_unavailable",
                "native_workspace_review_request_missing",
                "native_policy_snapshot_missing",
                "native_policy_snapshot_unavailable",
            )
        ):
            return None
        summary = valid_business_review_summary(response, request_id)
        if summary is None:
            raise NativeBusinessReviewSummaryReadError()
        return summary
    except (UnicodeDecodeError, ValueError, TypeError, OSError) as error:
        raise NativeBusinessReviewSummaryReadError() from error
