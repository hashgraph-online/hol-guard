"""Local Cloud Review setup HTTP boundary."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from ..approval_gate import ApprovalGateError
from ..store import GuardStore
from .cloud_review_settings import CloudReviewSettingsError, ExactCloudReviewError, change_cloud_review_settings


class JsonResponseWriter(Protocol):
    def __call__(
        self, payload: dict[str, object], *, status: int = 200, extra_headers: dict[str, str] | None = None
    ) -> None: ...


def handle_cloud_review_settings(
    store: GuardStore,
    payload: dict[str, object],
    *,
    refresh_workers: Callable[[], dict[str, object]] | None,
    write_json: JsonResponseWriter,
    write_approval_gate_error: Callable[[ApprovalGateError], None],
) -> None:
    if refresh_workers is None:
        write_json({"error": "command_queue_lifecycle_unavailable"}, status=503)
        return
    try:
        result = change_cloud_review_settings(store, payload, refresh_workers=refresh_workers)
    except ApprovalGateError as error:
        write_approval_gate_error(error)
        return
    except CloudReviewSettingsError as error:
        write_json({"error": error.code, "message": str(error)}, status=400)
        return
    except ExactCloudReviewError as error:
        write_json(
            {
                "error": error.code,
                "message": "Guard could not verify this device's Cloud connection. Your local protection is unchanged.",
            },
            status=409,
        )
        return
    write_json(result, extra_headers={"Cache-Control": "no-store"})
