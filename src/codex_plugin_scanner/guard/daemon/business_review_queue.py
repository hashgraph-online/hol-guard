"""Local, read-only native projection; never persist these rows for Cloud sync."""

from __future__ import annotations

from typing import Any

from ..runtime.native_business_review_queue import (
    NativeBusinessReviewQueueReadError,
    read_native_business_review_queue,
)
from ..runtime.native_business_review_summary import (
    NativeBusinessReviewSummaryReadError,
    read_native_business_review_summary,
)
from ..store_approvals import InvalidApprovalCursorError

_CURSOR_PREFIX = "native-business-v1:"


def _native_page(store, summaries: list[dict[str, object]], **request: object) -> dict[str, Any]:
    """The runtime projects, filters and pages the rows (``business_review_page.rs``)."""
    if not summaries:
        # An empty queue needs no runtime; no native cursor can name it.
        if "cursor" in request:
            raise InvalidApprovalCursorError("invalid native cursor")
        return {"count": 0, "items": [], "next_cursor": None}
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        page = native_runner_authority(
            "business_review_page", {"summaries": summaries, **request}, guard_home=store.guard_home
        )
    except NativeRunnerAuthorityError:
        raise NativeBusinessReviewQueueReadError() from None
    error = page.get("error")
    if error in {"invalid_cursor", "expired_cursor"}:
        raise InvalidApprovalCursorError(f"{str(error).split('_')[0]} native cursor")
    if (
        type(page.get("count")) is not int
        or not isinstance(page.get("items"), list)
        or not isinstance(page.get("next_cursor"), str | None)
    ):
        raise NativeBusinessReviewQueueReadError()
    return page


def _native_summaries(store) -> list[dict[str, object]]:
    summaries = read_native_business_review_queue(store.guard_home)
    for summary in summaries:
        # A SQL row must not impersonate or hide a native saved request.
        if store.get_approval_request(str(summary["request_id"])) is not None:
            raise NativeBusinessReviewQueueReadError()
    return summaries


def local_request_page(store, *, status, limit, cursor, harness, search, include_totals):
    """Keep SQL cursors intact, then paginate native rows in a separate phase."""
    native_cursor = isinstance(cursor, str) and cursor.startswith(_CURSOR_PREFIX)
    page: dict[str, Any] = {}
    if not native_cursor:
        page = store.list_approval_request_page(
            status=status,
            limit=limit,
            cursor=cursor,
            harness=harness,
            search=search,
            include_totals=include_totals,
        )
        # Other harnesses cannot contain native rows. Without totals, resolved
        # history and unfinished SQL pagination need no native membership read.
        if (harness and harness != "native-business") or (
            not include_totals and (status == "resolved" or page.get("next_cursor"))
        ):
            return page
    filters = {"status": status, "harness": harness, "search": search}
    native: dict[str, Any]
    try:
        summaries = _native_summaries(store)
        if native_cursor:
            native = _native_page(store, summaries, cursor=cursor, limit=limit, **filters)
        elif status != "resolved" and not page.get("next_cursor"):
            # Append only after SQL pagination ends, keeping each page bounded.
            native = _native_page(store, summaries, room=max(0, limit - len(page["items"])), **filters)
        else:
            native = {**_native_page(store, summaries, room=0, **filters), "items": [], "next_cursor": None}
    except NativeBusinessReviewQueueReadError:
        if native_cursor:
            raise InvalidApprovalCursorError("native queue unavailable; refresh") from None
        page["native_business_queue_error"] = "native_local_business_queue_read_failed"
        page["native_business_queue_checked"] = True
        return page
    if native_cursor:
        page = store.list_approval_request_page(
            status=status,
            limit=1,
            cursor=None,
            harness=harness,
            search=search,
            include_totals=include_totals,
        )
        page["items"] = native["items"]
        page["next_cursor"] = native["next_cursor"]
    elif native["items"] or native["next_cursor"]:
        page["items"] = [*page["items"], *native["items"]]
        page["next_cursor"] = native["next_cursor"]
    count = native["count"]
    if include_totals:
        page["total_pending_count"] += count
        if status != "resolved":
            page["total_count"] += count
    page["native_business_queue_checked"] = True
    return page


def native_request_detail(store, request_id: str):
    if store.get_approval_request(request_id) is not None:
        raise NativeBusinessReviewQueueReadError()
    try:
        summary = read_native_business_review_summary(store.guard_home, request_id)
    except NativeBusinessReviewSummaryReadError:
        raise NativeBusinessReviewQueueReadError() from None
    if summary is None:
        return None
    items = _native_page(store, [summary])["items"]
    return items[0] if items else None
