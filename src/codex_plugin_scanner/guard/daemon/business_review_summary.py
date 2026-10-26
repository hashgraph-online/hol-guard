"""Authenticated local review-detail route, separate from Cloud projection."""

from urllib.parse import unquote

from ..runtime.native_business_review_summary import (
    NativeBusinessReviewSummaryReadError,
    read_native_business_review_summary,
)


def handle_business_review_summary(handler, request_id: str) -> None:
    request_id = unquote(request_id)
    # SQL owns its detail route. Never attach another native snapshot's metadata
    # to that review, even when an opaque selector happens to collide.
    if handler.server.store.get_approval_request(request_id) is not None:
        handler._write_json(
            {"error": "native_local_business_summary_unavailable"},
            status=404,
            extra_headers={"Cache-Control": "no-store"},
        )
        return
    try:
        summary = read_native_business_review_summary(handler.server.store.guard_home, request_id)
    except NativeBusinessReviewSummaryReadError:
        handler._write_json(
            {"error": "native_local_business_summary_read_failed"},
            status=503,
            extra_headers={"Cache-Control": "no-store"},
        )
        return
    handler._write_json(
        summary if summary is not None else {"error": "native_local_business_summary_unavailable"},
        status=200 if summary is not None else 404,
        extra_headers={"Cache-Control": "no-store"},
    )
