"""Shared headless application path for one signed Cloud review decision."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timezone
from typing import Protocol, cast

from ..adapters import get_adapter
from ..harness_resume import resume_harness_operation
from ..runtime.exact_cloud_review import ExactCloudReviewError, apply_exact_cloud_review
from ..store import GuardStore


class _QueueLifecycle(Protocol):
    def refresh_command_queue_worker(self) -> dict[str, object]: ...


class _HandlerServer(Protocol):
    store: GuardStore
    command_queue_lifecycle: _QueueLifecycle | None


class _CloudReviewHandler(Protocol):
    server: _HandlerServer

    def _handle_headless_remote_once(self, payload: dict[str, object]) -> None: ...
    def _policy_memory_payload(self, value: object) -> dict[str, object]: ...
    def _optional_string(self, value: object) -> str | None: ...
    def _record_headless_receipt(self, **kwargs: object) -> dict[str, object]: ...
    def _codex_resume_after_remote_once(self, **kwargs: object) -> dict[str, object] | None: ...
    def _write_json(self, payload: object, **kwargs: object) -> None: ...


def dispatch_cloud_review_post(handler: object, path: str, payload: dict[str, object]) -> bool:
    typed_handler = cast(_CloudReviewHandler, handler)
    if path == "/v1/requests/remote-once":
        typed_handler._handle_headless_remote_once(payload)
        return True
    if path == "/v1/requests/remote-exact":
        _handle_remote_exact(typed_handler, payload)
        return True
    if path == "/v1/cloud-review/worker/refresh":
        _handle_worker_refresh(typed_handler)
        return True
    return False


_PayloadDecoder = Callable[[object], dict[str, object]]
_OptionalString = Callable[[object], str | None]
_ReceiptRecorder = Callable[..., dict[str, object]]
_CodexResumer = Callable[..., dict[str, object] | None]
_Now = Callable[[], str]


def _handle_remote_exact(handler: _CloudReviewHandler, payload: dict[str, object]) -> None:
    status, response = build_headless_exact_cloud_review_response(
        store=handler.server.store,
        payload=payload,
        decode_mapping=handler._policy_memory_payload,
        optional_string=handler._optional_string,
        record_receipt=handler._record_headless_receipt,
        resume_codex=handler._codex_resume_after_remote_once,
        now=lambda: datetime.now(timezone.utc).isoformat(),
    )
    handler._write_json(response, status=status)


def _handle_worker_refresh(handler: _CloudReviewHandler) -> None:
    lifecycle = handler.server.command_queue_lifecycle
    if lifecycle is None:
        handler._write_json({"error": "command_queue_lifecycle_unavailable"}, status=503)
        return
    handler._write_json(lifecycle.refresh_command_queue_worker(), extra_headers={"Cache-Control": "no-store"})


def build_headless_exact_cloud_review_response(
    *,
    store: GuardStore,
    payload: dict[str, object],
    decode_mapping: _PayloadDecoder,
    optional_string: _OptionalString,
    record_receipt: _ReceiptRecorder,
    resume_codex: _CodexResumer,
    now: _Now,
) -> tuple[int, dict[str, object]]:
    """Return the authenticated exact-review response for the daemon route."""

    harness = optional_string(payload.get("harness"))
    if harness is None:
        return 400, {"error": "missing_harness"}
    try:
        adapter = get_adapter(harness)
    except ValueError:
        return 404, {"error": "unknown_harness"}
    remote_approval = decode_mapping(
        payload.get("remoteApproval") or payload.get("remote_approval") or payload.get("remote_exact")
    )
    if not remote_approval:
        return 400, {"error": "missing_remote_approval"}
    try:
        resolution = apply_exact_cloud_review(
            store,
            remote_approval=remote_approval,
            expected_harness=adapter.harness,
        )
    except ExactCloudReviewError as error:
        return _exact_error_response(error.code)
    resolved_request = resolution.resolved_request
    response: dict[str, object] = {
        "harness": adapter.harness,
        "operation": "remote_exact",
        "request_id": resolution.request_id,
        "resolved_request": resolved_request,
        "status": "completed",
    }
    post_commit_errors: list[str] = []
    try:
        response["receipt"] = record_receipt(
            harness=adapter.harness,
            operation="remote_exact",
            payload=payload,
            result={"request_id": resolution.request_id, "receipt_id": resolution.receipt_id},
            workspace_id=optional_string(resolved_request.get("workspace")),
            artifact_name=f"Exact Cloud review for {resolution.request_id}",
            scanner_evidence_extra={"receipt_id": resolution.receipt_id, "request_id": resolution.request_id},
        )
    except Exception:
        post_commit_errors.append("receipt_record_failed")
        response["receipt"] = {"reason": "receipt_record_failed", "status": "failed"}
        _audit_post_commit_failure(store, "receipt_record_failed", request_id=resolution.request_id)
    if adapter.harness == "codex":
        try:
            codex_resume = resume_codex(request_id=resolution.request_id, action=resolution.action)
        except Exception:
            post_commit_errors.append("harness_resume_failed")
            codex_resume = {"reason": "harness_resume_failed", "status": "failed"}
            _audit_post_commit_failure(store, "harness_resume_failed", request_id=resolution.request_id)
        if codex_resume is not None:
            response["codex_resume"] = codex_resume
    else:
        try:
            harness_resume = resume_harness_operation(
                store,
                request_id=resolution.request_id,
                action=resolution.action,
                now=now(),
            )
        except Exception:
            post_commit_errors.append("harness_resume_failed")
            harness_resume = {"reason": "harness_resume_failed", "status": "failed"}
            _audit_post_commit_failure(store, "harness_resume_failed", request_id=resolution.request_id)
        if harness_resume is not None:
            response["harness_resume"] = harness_resume
            response["harnessResume"] = harness_resume
    response["delivery_status"] = "incomplete" if post_commit_errors else "completed"
    if post_commit_errors:
        response["post_commit_errors"] = post_commit_errors
    return 200, response


def _audit_post_commit_failure(store: GuardStore, code: str, *, request_id: str) -> None:
    with suppress(Exception):
        store.add_event(
            "cloud_review.exact_delivery_failed",
            {"code": code, "request_id": request_id},
            datetime.now(timezone.utc).isoformat(),
        )


def _exact_error_response(code: str) -> tuple[int, dict[str, object]]:
    if code == "remote_exact_reviewer_not_authorized":
        return 403, {"error": code}
    if code in {
        "cloud_review_capability_missing",
        "cloud_review_capability_expired",
        "cloud_review_capability_binding_mismatch",
    }:
        return 403, {"error": code}
    if code.endswith(("_invalid", "_missing", "_unsupported")):
        return 400, {"error": code}
    return 409, {"error": code}


__all__ = ["build_headless_exact_cloud_review_response", "dispatch_cloud_review_post"]
