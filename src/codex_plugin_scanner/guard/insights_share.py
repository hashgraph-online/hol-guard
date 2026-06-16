"""Build and publish Guard insights share payloads for Guard Cloud."""

from __future__ import annotations

import json
import math
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.store import GuardStore

_HARNESS_LABELS: dict[str, str] = {
    "codex": "Codex",
    "claude-code": "Claude Code",
    "cursor": "Cursor",
    "copilot": "Copilot",
    "gemini-cli": "Gemini CLI",
    "hermes": "Hermes",
    "opencode": "OpenCode",
    "windsurf": "Windsurf",
}


def _coerce_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return 0
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return 0
        try:
            return int(stripped)
        except ValueError:
            return 0
    return 0


def _harness_label(harness: str) -> str:
    normalized = harness.strip().lower()
    if not normalized:
        return "Unknown app"
    return _HARNESS_LABELS.get(normalized, normalized.replace("-", " ").title())


def _heatmap_level(total: int, *, peak: int) -> int:
    if total <= 0 or peak <= 0:
        return 0
    ratio = total / peak
    if ratio >= 0.85:
        return 4
    if ratio >= 0.6:
        return 3
    if ratio >= 0.35:
        return 2
    return 1


def build_insights_share_payload(
    analytics: dict[str, object],
    *,
    include_top_artifacts: bool = False,
    show_display_name: bool = False,
    display_name: str | None = None,
    overview_stats: dict[str, int] | None = None,
) -> dict[str, object]:
    total = _coerce_int(analytics.get("total"))
    blocked = _coerce_int(analytics.get("blocked"))
    stop_rate_pct = round((blocked / total) * 100) if total > 0 else 0
    by_harness = analytics.get("by_harness")
    harness_rows = [row for row in by_harness if isinstance(row, dict)] if isinstance(by_harness, list) else []
    top_harness_row = harness_rows[0] if harness_rows else {}
    top_harness = _harness_label(str(top_harness_row.get("harness") or "Unknown app"))

    harness_breakdown: list[dict[str, object]] = []
    for row in harness_rows[:4]:
        count = _coerce_int(row.get("total"))
        harness_breakdown.append(
            {
                "harness": _harness_label(str(row.get("harness") or "Unknown app")),
                "count": count,
                "sharePct": round((count / total) * 100) if total > 0 else 0,
            }
        )

    daily_activity = analytics.get("daily_activity")
    daily_rows = [row for row in daily_activity if isinstance(row, dict)] if isinstance(daily_activity, list) else []
    peak_day_total = _coerce_int(analytics.get("peak_day_total"))
    heatmap_peak = max((_coerce_int(row.get("total")) for row in daily_rows), default=peak_day_total)
    heatmap_cells: list[dict[str, object]] = []
    for row in daily_rows[-90:]:
        date_key = str(row.get("date_key") or "")
        if not date_key:
            continue
        day_total = _coerce_int(row.get("total"))
        heatmap_cells.append(
            {
                "date": date_key,
                "level": _heatmap_level(day_total, peak=heatmap_peak),
            }
        )

    # Build mini heatmap for last 5 days
    mini_heatmap_cells: list[dict[str, object]] = []
    for row in daily_rows[-5:]:
        date_key = str(row.get("date_key") or "")
        if not date_key:
            continue
        day_total = _coerce_int(row.get("total"))
        mini_heatmap_cells.append(
            {
                "date": date_key,
                "level": _heatmap_level(day_total, peak=heatmap_peak),
            }
        )

    payload: dict[str, object] = {
        "version": 1,
        "generatedAt": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "local_daemon",
        "period": {"label": "all_time", "activityDays": len(daily_rows) or 90},
        "headline": {
            "totalActions": total,
            "activeDayStreak": _coerce_int(analytics.get("active_day_streak")),
            "peakDayTotal": peak_day_total,
            "blockedCount": blocked,
            "stopRatePct": stop_rate_pct,
            "topHarness": top_harness,
        },
        "harnessBreakdown": harness_breakdown,
        "heatmap": {"days": len(heatmap_cells) or 90, "cells": heatmap_cells},
        "showDisplayName": bool(show_display_name and display_name),
    }

    payload["overviewStats"] = {
        "pending": _coerce_int(overview_stats.get("pending")) if overview_stats else 0,
        "apps": _coerce_int(overview_stats.get("apps")) if overview_stats else 0,
        "recorded": _coerce_int(overview_stats.get("recorded")) if overview_stats else 0,
    }

    if mini_heatmap_cells:
        payload["miniHeatmap"] = {"days": len(mini_heatmap_cells), "cells": mini_heatmap_cells}

    if show_display_name and display_name:
        payload["displayName"] = display_name.strip()[:120]

    if include_top_artifacts:
        top_artifacts = analytics.get("top_artifacts")
        artifact_rows = (
            [row for row in top_artifacts if isinstance(row, dict)] if isinstance(top_artifacts, list) else []
        )
        payload["topArtifacts"] = [
            {
                "label": str(row.get("name") or "Protected action")[:120],
                "count": _coerce_int(row.get("total")),
            }
            for row in artifact_rows[:3]
        ]

    return payload


def normalized_insights_share_url(sync_url: str) -> str:
    parsed = urllib.parse.urlsplit(sync_url)
    if parsed.path.rstrip("/") == "/registry/api/v1/guard/receipts/sync":
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, "/registry/api/v1/guard/insights/shares", parsed.query, "")
        )
    if parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/api/guard/insights/shares", parsed.query, ""))
    if parsed.path.rstrip("/") == "/guard/receipts/sync":
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/guard/insights/shares", parsed.query, ""))
    base = sync_url.rstrip("/")
    if base.endswith("/receipts/sync"):
        return base[: -len("/receipts/sync")] + "/insights/shares"
    return urllib.parse.urljoin(base + "/", "insights/shares")


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
