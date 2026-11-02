"""Build and publish Guard insights share payloads for Guard Cloud."""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from .runtime.runner_native_sync import sync_url as derived_sync_url

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.store import GuardStore

_TOP_ARTIFACT_ROWS = 3
_ARTIFACT_LABEL_CHARS = 120
_UNAVAILABLE_MESSAGE = "Guard could not prepare the insights share. Check that the Guard daemon is running."


def build_insights_share_payload(
    analytics: dict[str, object],
    *,
    include_top_artifacts: bool = False,
    show_display_name: bool = False,
    display_name: str | None = None,
    overview_stats: dict[str, int] | None = None,
) -> dict[str, object]:
    """The insights card the resident builds from the receipt analytics."""

    try:
        answer = native_runner_authority(
            "insights_share_payload",
            {
                "analytics": _bounded_analytics(analytics, include_top_artifacts=include_top_artifacts),
                "include_top_artifacts": include_top_artifacts,
                "show_display_name": show_display_name,
                "display_name": display_name,
                "overview_stats": overview_stats,
                "generated_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            },
        )
    except NativeRunnerAuthorityError as error:
        raise RuntimeError(_UNAVAILABLE_MESSAGE) from error
    payload = answer.get("payload")
    if not isinstance(payload, dict):
        raise RuntimeError(_UNAVAILABLE_MESSAGE)
    return payload


def _bounded_analytics(analytics: dict[str, object], *, include_top_artifacts: bool) -> dict[str, object]:
    """The analytics with only the top artifacts the card can show.

    The card shows at most three artifact labels of 120 characters, so longer
    stored names never travel to the resident.
    """

    rows = analytics.get("top_artifacts") if include_top_artifacts else None
    top_artifacts = [
        {**row, "name": row["name"][:_ARTIFACT_LABEL_CHARS]} if isinstance(row.get("name"), str) else row
        for row in (rows if isinstance(rows, list) else [])[:_TOP_ARTIFACT_ROWS]
        if isinstance(row, dict)
    ]
    return {**analytics, "top_artifacts": top_artifacts}


def normalized_insights_share_url(sync_url: str) -> str:
    try:
        return derived_sync_url("insights_share", sync_url)
    except NativeRunnerAuthorityError as error:
        raise RuntimeError(_UNAVAILABLE_MESSAGE) from error


def publish_insights_share(
    store: GuardStore,
    *,
    include_top_artifacts: bool = False,
    show_display_name: bool = False,
    display_name: str | None = None,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    from codex_plugin_scanner.guard.runtime.runner import (
        _guard_sync_request,
        _resolve_guard_sync_auth_context,
        _sync_http_error_message,
        _sync_url_error_message,
        _urlopen_json_with_timeout_retry,
        prepare_guard_cloud_connect_authorization,
    )

    prepare_guard_cloud_connect_authorization(store)
    analytics = store.receipt_analytics(activity_days=90, trend_days=7, top_limit=8)
    overview_stats = {
        "pending": store.count_approval_requests(),
        "apps": len(store.list_managed_installs()),
        "recorded": store.count_receipts(),
    }
    payload = build_insights_share_payload(
        analytics,
        include_top_artifacts=include_top_artifacts,
        show_display_name=show_display_name,
        display_name=display_name,
        overview_stats=overview_stats,
    )
    resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    request_url = normalized_insights_share_url(str(resolved_auth_context["sync_url"]))
    body = json.dumps({"payload": payload}).encode("utf-8")
    request = _guard_sync_request(
        resolved_auth_context,
        request_url=request_url,
        method="POST",
        data=body,
        extra_headers=None,
    )
    try:
        response = _urlopen_json_with_timeout_retry(request=request, timeout_seconds=30, retry_timeout_seconds=45)
    except urllib.error.HTTPError as error:
        raise RuntimeError(_sync_http_error_message(error)) from error
    except OSError as error:
        raise RuntimeError(_sync_url_error_message(error)) from error
    if not isinstance(response, dict):
        raise RuntimeError("Guard insights share returned an invalid response.")
    return response
