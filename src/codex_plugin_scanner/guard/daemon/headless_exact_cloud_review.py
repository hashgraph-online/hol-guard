"""Shared headless application path for one signed Cloud review decision."""

from __future__ import annotations

from collections.abc import Callable

from ..adapters import get_adapter
from ..harness_resume import resume_harness_operation
from ..runtime.exact_cloud_review import ExactCloudReviewError, apply_exact_cloud_review
from ..store import GuardStore

_PayloadDecoder = Callable[[object], dict[str, object]]
_OptionalString = Callable[[object], str | None]
_ReceiptRecorder = Callable[..., dict[str, object]]
_CodexResumer = Callable[..., dict[str, object] | None]
_Now = Callable[[], str]


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
    receipt = record_receipt(
        harness=adapter.harness,
        operation="remote_exact",
        payload=payload,
        result={"request_id": resolution.request_id, "receipt_id": resolution.receipt_id},
        workspace_id=optional_string(resolved_request.get("workspace")),
        artifact_name=f"Exact Cloud review for {resolution.request_id}",
        scanner_evidence_extra={"receipt_id": resolution.receipt_id, "request_id": resolution.request_id},
    )
    response: dict[str, object] = {
        "harness": adapter.harness,
        "operation": "remote_exact",
        "receipt": receipt,
        "request_id": resolution.request_id,
        "resolved_request": resolved_request,
        "status": "completed",
    }
    if adapter.harness == "codex":
        codex_resume = resume_codex(request_id=resolution.request_id, action=resolution.action)
        if codex_resume is not None:
            response["codex_resume"] = codex_resume
        return 200, response
    harness_resume = resume_harness_operation(
        store,
        request_id=resolution.request_id,
        action=resolution.action,
        now=now(),
    )
    if harness_resume is not None:
        response["harness_resume"] = harness_resume
        response["harnessResume"] = harness_resume
    return 200, response


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
