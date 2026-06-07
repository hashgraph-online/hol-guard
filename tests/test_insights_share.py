from codex_plugin_scanner.guard.insights_share import (
    build_insights_share_payload,
    normalized_insights_share_url,
)


def test_build_insights_share_payload_defaults():
    analytics = {
        "total": 100,
        "blocked": 10,
        "active_day_streak": 5,
        "peak_day_total": 20,
        "by_harness": [{"harness": "cursor", "total": 60}],
        "top_artifacts": [{"name": "npm run build", "total": 12}],
        "daily_activity": [
            {"date_key": "2026-06-01", "total": 4},
            {"date_key": "2026-06-02", "total": 20},
        ],
    }
    payload = build_insights_share_payload(analytics)
    assert payload["version"] == 1
    assert payload["headline"]["totalActions"] == 100
    assert payload["headline"]["topHarness"] == "Cursor"
    assert payload["headline"]["stopRatePct"] == 10
    assert "topArtifacts" not in payload


def test_build_insights_share_payload_with_top_artifacts():
    analytics = {
        "total": 50,
        "blocked": 5,
        "active_day_streak": 2,
        "peak_day_total": 8,
        "by_harness": [{"harness": "codex", "total": 50}],
        "top_artifacts": [{"name": "bash", "total": 3}],
        "daily_activity": [{"date_key": "2026-06-02", "total": 8}],
    }
    payload = build_insights_share_payload(
        analytics,
        include_top_artifacts=True,
        show_display_name=True,
        display_name="Alex",
    )
    assert payload["topArtifacts"] == [{"label": "bash", "count": 3}]
    assert payload["displayName"] == "Alex"
    assert payload["showDisplayName"] is True


def test_normalized_insights_share_url_from_receipts_sync():
    url = normalized_insights_share_url("https://hol.org/api/guard/receipts/sync")
    assert url == "https://hol.org/api/guard/insights/shares"
