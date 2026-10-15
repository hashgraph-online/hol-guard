"""Read-only native discovery for the local business review interface."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..native_resident_client import native_resident_client_request
from ..native_runtime import _isolated_environment, native_runtime_status
from .native_business_review_summary import valid_business_review_summary

_FEATURE = "native-local-business-review-queue-v1"
_MAX_ITEMS = 128


class NativeBusinessReviewQueueReadError(RuntimeError):
    """Finite public failure without private transport or snapshot details."""

    def __init__(self) -> None:
        super().__init__("native_local_business_queue_read_failed")


def read_native_business_review_queue(guard_home: Path) -> list[dict[str, object]]:
    """Discover existing snapshots through native verification, never filesystem reads."""
    try:
        status = native_runtime_status()
        if not status.available:
            return []
        if not status.compatible or status.identity is None or status.capabilities is None:
            raise NativeBusinessReviewQueueReadError()
        if not {"resident-protocol-v2", _FEATURE}.issubset(status.capabilities.features):
            return []
        encoded = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=b'{"operation":"workspace_review_local_queue","request":{}}',
            timeout_seconds=2.0,
        )
        if encoded is None:
            raise NativeBusinessReviewQueueReadError()
        response = json.loads(encoded.decode("utf-8"))
        # No installed policy is an optional feature absence. Corrupt or stale
        # policy/request state and transport failures are never an empty queue.
        if (
            isinstance(response, dict)
            and set(response) in ({"error"}, {"error", "retryable"})
            and response.get("error") in ("native_policy_snapshot_missing", "native_policy_snapshot_unavailable")
            and ("retryable" not in response or type(response["retryable"]) is bool)
        ):
            return []
        if not isinstance(response, dict) or set(response) != {"schema", "version", "items"}:
            raise NativeBusinessReviewQueueReadError()
        if (
            response["schema"] != "guard-native-local-business-review-queue.v1"
            or type(response["version"]) is not int
            or response["version"] != 1
            or not isinstance(response["items"], list)
            or len(response["items"]) > _MAX_ITEMS
        ):
            raise NativeBusinessReviewQueueReadError()
        items: list[dict[str, object]] = []
        previous_id = ""
        for item in response["items"]:
            request_id = item.get("request_id") if isinstance(item, dict) else None
            if (
                not isinstance(request_id, str)
                or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", request_id) is None
                or request_id <= previous_id
            ):
                raise NativeBusinessReviewQueueReadError()
            summary = valid_business_review_summary(item, request_id)
            if summary is None:
                raise NativeBusinessReviewQueueReadError()
            items.append(summary)
            previous_id = request_id
        return items
    except (UnicodeDecodeError, ValueError, TypeError, OSError) as error:
        raise NativeBusinessReviewQueueReadError() from error
