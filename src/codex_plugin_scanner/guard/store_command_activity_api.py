"""Bounded queries and feedback for the local command-activity API.

The native resident (``guard_store`` op) runs every query and the feedback
upsert. Python validates the query objects, translates dates to the UTC
timestamps the store compares against, and returns the resident's payload.
"""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnnecessaryIsInstance=false

from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Final, Protocol, cast

from .runtime.command_activity_api_contract import (
    COMMAND_ACTIVITY_API_SCHEMA_VERSION,
    CommandActivityAnalyticsQuery,
    CommandActivityFeedbackLabel,
    CommandActivityListQuery,
)

_MAX_TIMESTAMP: Final = "9999-12-31T23:59:59.999999+00:00"


class CommandActivityNotFoundError(ValueError):
    pass


class _NativeOwner(Protocol):
    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...


def _midnight(day: date) -> str:
    return datetime.combine(day, time.min, tzinfo=timezone.utc).isoformat()


def _until(through: date | None) -> tuple[str | None, bool]:
    if through is None:
        return None, False
    if through == date.max:
        return _MAX_TIMESTAMP, True
    return _midnight(through + timedelta(days=1)), False


class StoreCommandActivityApiMixin:
    def list_command_activity_page(
        self: _NativeOwner,
        query: CommandActivityListQuery,
        *,
        cursor: tuple[str, str] | None = None,
    ) -> dict[str, object]:
        if not isinstance(cast(object, query), CommandActivityListQuery):
            raise ValueError("invalid_query")
        until, until_inclusive = _until(query.occurred_through)
        payload = self._native_store_call(
            "list_command_activity_page",
            {
                "filters": {
                    "harness": query.harness,
                    "execution_status": query.execution_status,
                    "proof_level": query.proof_level,
                    "approval_reuse_status": query.approval_reuse_status,
                    "prompted": query.prompted,
                    "extension_id": query.extension_id,
                    "rule_id": query.rule_id,
                    "occurred_from": _midnight(query.occurred_from) if query.occurred_from is not None else None,
                    "occurred_until": until,
                    "until_inclusive": until_inclusive,
                },
                "cursor": list(cursor) if cursor is not None else None,
                "limit": query.limit,
            },
        )
        marker = payload["next_marker"]
        return {
            "schema_version": COMMAND_ACTIVITY_API_SCHEMA_VERSION,
            "items": payload["items"],
            "next_marker": (marker[0], marker[1]) if marker is not None else None,
        }

    def command_activity_analytics(
        self: _NativeOwner,
        query: CommandActivityAnalyticsQuery,
        *,
        as_of: date,
    ) -> dict[str, object]:
        if not isinstance(cast(object, query), CommandActivityAnalyticsQuery):
            raise ValueError("invalid_query")
        if type(cast(object, as_of)) is not date:
            raise ValueError("invalid_as_of")
        start = as_of - timedelta(days=query.days - 1)
        payload = self._native_store_call(
            "command_activity_analytics",
            {
                "start": start.isoformat(),
                "end": as_of.isoformat(),
                "days": query.days,
                "top_limit": query.top_limit,
                "dimension": query.dimension,
                "dimension_value": query.dimension_value,
                "feedback_from": _midnight(start),
                "feedback_before": _midnight(as_of + timedelta(days=1)),
            },
        )
        return {"schema_version": COMMAND_ACTIVITY_API_SCHEMA_VERSION, **payload}

    def record_command_activity_feedback(
        self: _NativeOwner,
        *,
        activity_id: str,
        label: CommandActivityFeedbackLabel,
        recorded_at: datetime,
    ) -> dict[str, object]:
        if not isinstance(activity_id, str) or not activity_id:
            raise ValueError("invalid_activity_id")
        if not isinstance(cast(object, label), CommandActivityFeedbackLabel):
            raise ValueError("invalid_feedback_label")
        if recorded_at.tzinfo is None or recorded_at.utcoffset() != timedelta(0):
            raise ValueError("recorded_at_must_be_utc")
        payload = self._native_store_call(
            "record_command_activity_feedback",
            {
                "activity_id": activity_id,
                "label": label.value,
                "recorded_at": recorded_at.isoformat(),
                "schema_version": COMMAND_ACTIVITY_API_SCHEMA_VERSION,
            },
        )
        if payload.get("not_found") is True:
            raise CommandActivityNotFoundError(activity_id)
        return {"schema_version": COMMAND_ACTIVITY_API_SCHEMA_VERSION, **payload}

    def list_command_activity_invalidations(
        self: _NativeOwner,
        cursor: int,
        *,
        limit: int = 100,
    ) -> dict[str, object]:
        if type(cursor) is not int or cursor < 0:
            raise ValueError("invalid_invalidation_cursor")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid_invalidation_limit")
        payload = self._native_store_call("list_command_activity_invalidations", {"cursor": cursor, "limit": limit})
        return cast(dict[str, object], payload)


__all__ = (
    "CommandActivityNotFoundError",
    "StoreCommandActivityApiMixin",
)
