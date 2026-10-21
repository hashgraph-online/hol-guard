"""Local, read-only native projection; never persist these rows for Cloud sync."""

from __future__ import annotations

import hashlib
import json

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
_OPERATIONS = {
    "mail_read": "Read mail",
    "mail_draft": "Save a mail draft",
    "mail_send": "Send mail",
    "mail_label": "Update mail labels",
    "mail_permanent_delete": "Permanently delete mail",
    "mail_settings": "Change mail settings",
    "drive_read": "Read a Drive file",
    "drive_edit": "Edit a Drive file",
    "drive_share": "Share a Drive file",
    "drive_export": "Export a Drive file",
    "calendar_read": "Read a calendar",
    "calendar_invite": "Send a calendar invitation",
}


def project_request(summary: dict[str, object]) -> dict[str, object]:
    """DTO compatibility only: the explicit display-only flag forbids UI decisions."""
    request_id = str(summary["request_id"])
    title = _OPERATIONS[str(summary["operation"])]
    return {
        "request_id": request_id,
        "harness": "native-business",
        "artifact_id": request_id,
        "artifact_name": title,
        "artifact_type": "business-request",
        "artifact_hash": "",
        "publisher": None,
        "policy_action": "require-reapproval",
        "recommended_scope": None,
        "allowed_scopes": [],
        "changed_fields": [],
        "source_scope": "local",
        "config_path": "",
        "transport": "native-resident",
        "review_command": "",
        "approval_url": "",
        "status": "pending",
        "resolution_action": None,
        "resolution_scope": None,
        "reason": None,
        "created_at": "",
        "resolved_at": None,
        "native_business_review_display_only": True,
        "risk_headline": title,
        "risk_summary": "Saved native request. Review decisions and execution are not connected.",
        "queue_preview": title,
    }


def _native_items(store, *, harness: str | None, search: str | None) -> list[dict[str, object]]:
    summaries = read_native_business_review_queue(store.guard_home)
    items = []
    for summary in summaries:
        # A SQL row must not impersonate or hide a native saved request.
        if store.get_approval_request(str(summary["request_id"])) is not None:
            raise NativeBusinessReviewQueueReadError()
        item = project_request(summary)
        if harness and harness != item["harness"]:
            continue
        if (
            search
            and search.casefold()
            not in " ".join(
                str(item[name]) for name in ("request_id", "artifact_name", "harness", "risk_summary")
            ).casefold()
        ):
            continue
        items.append(item)
    return items


def local_request_page(store, *, status, limit, cursor, harness, search, include_totals):
    """Keep SQL cursors intact, then paginate native rows in a separate phase."""
    native_cursor = isinstance(cursor, str) and cursor.startswith(_CURSOR_PREFIX)
    page = None
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
    try:
        items = _native_items(store, harness=harness, search=search)
    except NativeBusinessReviewQueueReadError:
        if isinstance(cursor, str) and cursor.startswith(_CURSOR_PREFIX):
            raise InvalidApprovalCursorError("native queue unavailable; refresh") from None
        assert page is not None
        page["native_business_queue_error"] = "native_local_business_queue_read_failed"
        page["native_business_queue_checked"] = True
        return page
    digest = hashlib.sha256(
        json.dumps(
            {"items": items, "status": status, "harness": harness, "search": search},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if native_cursor:
        pieces = cursor[len(_CURSOR_PREFIX) :].split(":")
        if (
            len(pieces) != 2
            or pieces[0] != digest
            or not pieces[1].isascii()
            or not pieces[1].isdigit()
            or len(pieces[1]) > 3
            or status == "resolved"
        ):
            raise InvalidApprovalCursorError("invalid native cursor")
        offset = int(pieces[1])
        if offset >= len(items):
            raise InvalidApprovalCursorError("expired native cursor")
        page = store.list_approval_request_page(
            status=status,
            limit=1,
            cursor=None,
            harness=harness,
            search=search,
            include_totals=include_totals,
        )
        page["items"] = items[offset : offset + limit]
        following = offset + limit
        page["next_cursor"] = f"{_CURSOR_PREFIX}{digest}:{following}" if following < len(items) else None
    else:
        assert page is not None
        if status != "resolved" and items and not page.get("next_cursor"):
            # Append only after SQL pagination ends, keeping each page bounded.
            available = limit - len(page["items"])
            page["items"] = [*page["items"], *items[:available]]
            if available < len(items):
                page["next_cursor"] = f"{_CURSOR_PREFIX}{digest}:{available}"
    if include_totals:
        page["total_pending_count"] += len(items)
        if status != "resolved":
            page["total_count"] += len(items)
    page["native_business_queue_checked"] = True
    return page


def native_request_detail(store, request_id: str):
    if store.get_approval_request(request_id) is not None:
        raise NativeBusinessReviewQueueReadError()
    try:
        summary = read_native_business_review_summary(store.guard_home, request_id)
    except NativeBusinessReviewSummaryReadError:
        raise NativeBusinessReviewQueueReadError() from None
    return project_request(summary) if summary is not None else None
