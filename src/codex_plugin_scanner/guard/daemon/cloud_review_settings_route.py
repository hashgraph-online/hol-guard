"""Local Cloud Review setup HTTP boundary."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

from ..approval_gate import ApprovalGateError
from ..store import GuardStore
from .cloud_review_settings import (
    CloudReviewSettingsError,
    ExactCloudReviewError,
    change_cloud_review_settings,
    cloud_review_settings_status,
)
from .cloud_review_worker_status import observe_cloud_review_workers

if TYPE_CHECKING:
    from .server import GuardDaemonServer


class JsonResponseWriter(Protocol):
    def __call__(
        self, payload: dict[str, object], *, status: int = 200, extra_headers: dict[str, str] | None = None
    ) -> None: ...


class ReviewStatusServer(Protocol):
    store: GuardStore
    command_queue_lifecycle: GuardDaemonServer | None


def handle_cloud_review_status(server: ReviewStatusServer, write_json: JsonResponseWriter) -> None:
    observation = observe_cloud_review_workers(server.store, server.command_queue_lifecycle)
    write_json(
        cloud_review_settings_status(server.store, worker_observation=observation),
        extra_headers={"Cache-Control": "no-store"},
    )


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
