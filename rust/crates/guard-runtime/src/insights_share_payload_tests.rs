use serde_json::{json, Value};

use super::*;

const GENERATED_AT: &str = "2026-11-01T00:00:00Z";

fn share(analytics: Value, extra: Value) -> Value {
    let mut args = json!({
        "analytics": analytics,
        "include_top_artifacts": false,
        "show_display_name": false,
        "display_name": null,
        "overview_stats": null,
        "generated_at": GENERATED_AT,
    });
    for (key, value) in extra.as_object().unwrap() {
        args[key] = value.clone();
    }
    dispatch(&args).unwrap()["payload"].clone()
}

#[test]
fn defaults_carry_the_headline_and_leave_choices_out() {
    let payload = share(
        json!({
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
        }),
        json!({}),
    );
    assert_eq!(payload["version"], 1);
    assert_eq!(payload["generatedAt"], GENERATED_AT);
    assert_eq!(payload["source"], "local_daemon");
    assert_eq!(
        payload["period"],
        json!({"label": "all_time", "activityDays": 2})
    );
    assert_eq!(
        payload["headline"],
        json!({
            "totalActions": 100,
            "activeDayStreak": 5,
            "peakDayTotal": 20,
            "blockedCount": 10,
            "stopRatePct": 10,
            "topHarness": "Cursor",
        })
    );
    assert_eq!(
        payload["harnessBreakdown"],
        json!([{"harness": "Cursor", "count": 60, "sharePct": 60}])
    );
    let cells = json!([
        {"date": "2026-06-01", "level": 1},
        {"date": "2026-06-02", "level": 4},
    ]);
    assert_eq!(payload["heatmap"], json!({"days": 2, "cells": cells}));
    assert_eq!(payload["miniHeatmap"], json!({"days": 2, "cells": cells}));
    assert_eq!(payload["showDisplayName"], false);
    assert_eq!(
        payload["overviewStats"],
        json!({"pending": 0, "apps": 0, "recorded": 0})
    );
    assert!(payload.get("displayName").is_none());
    assert!(payload.get("topArtifacts").is_none());
}

#[test]
fn share_choices_add_the_name_and_top_artifacts() {
    let long_name = "n".repeat(130);
    let payload = share(
        json!({
            "total": 50,
            "by_harness": [{"harness": "codex", "total": 50}],
            "top_artifacts": [
                {"name": "bash", "total": 3},
                {"name": "", "total": "2"},
                {"name": long_name, "total": 1.9},
                {"name": "dropped", "total": 1},
            ],
        }),
        json!({
            "include_top_artifacts": true,
            "show_display_name": true,
            "display_name": "  Alex  ",
            "overview_stats": {"pending": 2, "apps": 3, "recorded": 50},
        }),
    );
    assert_eq!(payload["displayName"], "Alex");
    assert_eq!(payload["showDisplayName"], true);
    assert_eq!(
        payload["overviewStats"],
        json!({"pending": 2, "apps": 3, "recorded": 50})
    );
    assert_eq!(
        payload["topArtifacts"],
        json!([
            {"label": "bash", "count": 3},
            {"label": "Protected action", "count": 2},
            {"label": "n".repeat(120), "count": 1},
        ])
    );
}

#[test]
fn a_name_is_shown_only_when_chosen_and_present() {
    let hidden = share(json!({}), json!({"display_name": "Alex"}));
    assert_eq!(hidden["showDisplayName"], false);
    assert!(hidden.get("displayName").is_none());
    let empty = share(
        json!({}),
        json!({"show_display_name": true, "display_name": ""}),
    );
    assert_eq!(empty["showDisplayName"], false);
    assert!(empty.get("displayName").is_none());
}

#[test]
fn an_empty_history_keeps_the_ninety_day_window() {
    let payload = share(json!({"peak_day_total": 3}), json!({}));
    assert_eq!(payload["period"]["activityDays"], 90);
    assert_eq!(payload["heatmap"], json!({"days": 90, "cells": []}));
    assert!(payload.get("miniHeatmap").is_none());
    assert_eq!(payload["headline"]["topHarness"], "Unknown App");
    assert_eq!(payload["harnessBreakdown"], json!([]));
}

#[test]
fn heatmaps_read_the_last_rows_against_the_whole_history_peak() {
    let mut rows: Vec<Value> = (0..95)
        .map(|day| json!({"date_key": format!("d{day:02}"), "total": 1}))
        .collect();
    rows[0]["total"] = json!(100);
    rows[94]["date_key"] = json!("");
    let payload = share(json!({"daily_activity": rows}), json!({}));
    let cells = payload["heatmap"]["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 89);
    assert_eq!(cells[0], json!({"date": "d05", "level": 1}));
    assert_eq!(payload["heatmap"]["days"], 89);
    assert_eq!(payload["period"]["activityDays"], 95);
    assert_eq!(payload["miniHeatmap"]["days"], 4);
}

#[test]
fn heatmap_levels_follow_the_ratio_bands() {
    for (total, peak, level) in [
        (0, 10, 0),
        (5, 0, 0),
        (-1, 10, 0),
        (1, 10, 1),
        (35, 100, 2),
        (60, 100, 3),
        (85, 100, 4),
        (10, 10, 4),
    ] {
        assert_eq!(heatmap_level(total, peak), level, "{total}/{peak}");
    }
}

#[test]
fn percentages_round_half_to_even() {
    assert_eq!(percent(1, 8), 12);
    assert_eq!(percent(3, 8), 38);
    assert_eq!(percent(1, 200), 0);
    assert_eq!(percent(3, 200), 2);
    assert_eq!(percent(5, 0), 0);
}

#[test]
fn harness_labels_name_known_apps_and_title_others() {
    for (slug, label) in [
        ("codex", "Codex"),
        (" Claude-Code ", "Claude Code"),
        ("omp", "Oh My Pi"),
        ("gemini-cli", "Gemini CLI"),
        ("my-new-app", "My New App"),
        ("x2y-tool", "X2Y Tool"),
        ("   ", "Unknown app"),
        ("Unknown app", "Unknown App"),
    ] {
        assert_eq!(harness_label(slug), label, "{slug}");
    }
}

#[test]
fn counters_coerce_like_python() {
    for (value, expected) in [
        (json!(true), 1),
        (json!(7), 7),
        (json!(-2.9), -2),
        (json!(" 1_000 "), 1000),
        (json!("1__0"), 0),
        (json!("x"), 0),
        (json!(null), 0),
        (json!([1]), 0),
    ] {
        assert_eq!(coerce_int(Some(&value)), expected, "{value}");
    }
}

#[test]
fn malformed_arguments_are_refused() {
    let base = json!({
        "analytics": {},
        "include_top_artifacts": false,
        "show_display_name": false,
        "display_name": null,
        "overview_stats": null,
        "generated_at": GENERATED_AT,
    });
    let mut cases = vec![json!([]), json!({})];
    for key in base.as_object().unwrap().keys() {
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove(key);
        cases.push(missing);
    }
    for (key, bad) in [
        ("analytics", json!([])),
        ("include_top_artifacts", json!(1)),
        ("show_display_name", json!("yes")),
        ("display_name", json!(5)),
        ("overview_stats", json!([])),
        ("generated_at", json!(null)),
    ] {
        let mut case = base.clone();
        case[key] = bad;
        cases.push(case);
    }
    for case in cases {
        assert_eq!(dispatch(&case), Err(ERR_INVALID), "{case}");
    }
}
