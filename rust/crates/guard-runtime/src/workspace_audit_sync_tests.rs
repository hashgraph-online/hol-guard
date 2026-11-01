use serde_json::{json, Value};

use super::*;

fn job(final_response: Value, enqueue_status: Value) -> Value {
    json!({
        "outcome": "job",
        "workspace": "app",
        "workspace_fingerprint": "fp",
        "job_id": "j1",
        "package_count": 3,
        "enqueue_status": enqueue_status,
        "final": final_response,
        "manifest_paths": ["package.json"],
        "lockfile_paths": [],
    })
}

fn job_row_of(visible: Value, processed: Value, status: &str, message: Value) -> Value {
    json!({
        "workspace": "app",
        "workspace_fingerprint": "fp",
        "job_id": "j1",
        "status": status,
        "package_count": 3,
        "cloud_processed_count": processed,
        "cloud_visible_count": visible,
        "manifest_paths": ["package.json"],
        "lockfile_paths": [],
        "message": message,
    })
}

fn summarize(outcomes: Value) -> Value {
    dispatch(&json!({"synced_at": "T", "workspaces": outcomes})).unwrap()
}

fn counts(summary: &Value) -> [&Value; 6] {
    [
        &summary["status"],
        &summary["completed_jobs"],
        &summary["queued_jobs"],
        &summary["failed_jobs"],
        &summary["incomplete_jobs"],
        &summary["skipped_workspaces"],
    ]
}

#[test]
fn completed_job_is_synced() {
    let summary = summarize(json!([job(
        json!({"status": " Completed ", "totalPackages": 3, "processedCount": 3}),
        json!("queued"),
    )]));
    assert_eq!(
        counts(&summary),
        [
            &json!("synced"),
            &json!(1),
            &json!(0),
            &json!(0),
            &json!(0),
            &json!(0)
        ]
    );
    assert_eq!(summary["synced_at"], "T");
    assert_eq!(summary["workspace_count"], 1);
    assert_eq!(
        summary["workspaces"],
        json!([job_row_of(json!(3), json!(3), "completed", Value::Null)])
    );
}

#[test]
fn a_falsy_job_status_falls_back_like_python_or() {
    // An empty final status takes the enqueue status; the cloud error rides along.
    let summary = summarize(json!([job(
        json!({"status": "", "error": "later"}),
        json!("Failed"),
    )]));
    assert_eq!(summary["status"], "failed");
    assert_eq!(
        summary["workspaces"],
        json!([job_row_of(
            Value::Null,
            Value::Null,
            "failed",
            json!("later")
        )])
    );
    // A zero status and a null enqueue status leave the job queued.
    let summary = summarize(json!([job(json!({"status": 0}), Value::Null)]));
    assert_eq!(summary["status"], "synced");
    assert_eq!(summary["queued_jobs"], 1);
    assert_eq!(summary["workspaces"][0]["status"], "queued");
    // `str(True).lower()`.
    let summary = summarize(json!([job(json!({"status": true}), json!("queued"))]));
    assert_eq!(summary["workspaces"][0]["status"], "true");
    assert_eq!(summary["queued_jobs"], 1);
}

#[test]
fn fewer_visible_rows_than_discovered_is_partial() {
    let summary = summarize(json!([job(
        json!({"status": "completed", "totalPackages": 2, "processedCount": 2.5}),
        json!("queued"),
    )]));
    assert_eq!(
        counts(&summary),
        [
            &json!("partial"),
            &json!(0),
            &json!(0),
            &json!(0),
            &json!(1),
            &json!(0)
        ]
    );
    assert_eq!(
        summary["workspaces"],
        json!([job_row_of(
            json!(2),
            Value::Null,
            "partial",
            json!("Guard Cloud accepted fewer package rows than hol-guard discovered (2 of 3 visible)."),
        )])
    );
}

#[test]
fn counts_follow_python_int_checks() {
    // `isinstance(True, int)` holds, and `True < 3`.
    let summary = summarize(json!([job(
        json!({"status": "completed", "totalPackages": true}),
        json!("queued"),
    )]));
    assert_eq!(summary["status"], "partial");
    let row = &summary["workspaces"][0];
    assert_eq!(row["cloud_visible_count"], true);
    assert_eq!(
        row["message"],
        "Guard Cloud accepted fewer package rows than hol-guard discovered (True of 3 visible)."
    );
    // A float is not an int, so it neither counts nor marks the job partial.
    let summary = summarize(json!([job(
        json!({"status": "completed", "totalPackages": 1.0}),
        json!("queued"),
    )]));
    assert_eq!(summary["status"], "synced");
    assert_eq!(summary["workspaces"][0]["cloud_visible_count"], Value::Null);
}

#[test]
fn skipped_and_failed_workspaces_have_fixed_rows() {
    let summary = summarize(json!([
        {"outcome": "skipped", "workspace": "a"},
        {"outcome": "failed", "workspace": "b", "message": "boom"},
    ]));
    assert_eq!(
        counts(&summary),
        [
            &json!("failed"),
            &json!(0),
            &json!(0),
            &json!(1),
            &json!(0),
            &json!(1)
        ]
    );
    assert_eq!(
        summary["workspaces"],
        json!([
            {
                "workspace": "a",
                "status": "skipped",
                "message": SKIPPED_MESSAGE,
                "package_count": 0,
            },
            {"workspace": "b", "status": "failed", "message": "boom", "package_count": 0},
        ])
    );
    let summary = summarize(json!([
        {"outcome": "failed", "workspace": "b", "message": "boom"},
        job(json!({"status": "queued"}), Value::Null),
    ]));
    assert_eq!(summary["status"], "partial");
}

#[test]
fn no_workspaces_is_idle() {
    let summary = summarize(json!([]));
    assert_eq!(
        counts(&summary),
        [
            &json!("idle"),
            &json!(0),
            &json!(0),
            &json!(0),
            &json!(0),
            &json!(0)
        ]
    );
    assert_eq!(summary["workspaces"], json!([]));
}

#[test]
fn malformed_outcomes_are_refused() {
    let mut no_final = job(json!({}), Value::Null);
    no_final["final"] = json!("done");
    let mut bad_paths = job(json!({}), Value::Null);
    bad_paths["lockfile_paths"] = json!([1]);
    for outcome in [
        json!({"outcome": "skipped"}),
        json!({"outcome": "failed", "workspace": "b"}),
        json!({"outcome": "unknown", "workspace": "b"}),
        no_final,
        bad_paths,
    ] {
        assert_eq!(
            dispatch(&json!({"synced_at": "T", "workspaces": [outcome]})),
            Err(ERR_INVALID)
        );
    }
    assert_eq!(dispatch(&json!({"workspaces": []})), Err(ERR_INVALID));
    assert_eq!(dispatch(&json!({"synced_at": "T"})), Err(ERR_INVALID));
}
