use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn row(artifact: &str, action: &str) -> Value {
    json!({
        "harness": "codex",
        "scope": "artifact",
        "artifact_id": artifact,
        "artifact_hash": null,
        "workspace": null,
        "publisher": null,
        "action": action,
        "expires_at": null,
    })
}

fn ask(legacy: Value, canonical: Value, evaluating: bool, enforcing: bool) -> Value {
    dispatch(&json!({
        "legacy": legacy,
        "canonical": canonical,
        "evaluating": evaluating,
        "canonical_enforcement": enforcing,
    }))
    .expect("verdict")
}

#[test]
fn agreeing_rows_are_applied() {
    let rows = json!([row("command:npm-test", "allow")]);
    assert_eq!(
        ask(rows.clone(), rows, false, true),
        json!({"reason_codes": [], "rejection": null})
    );
}

#[test]
fn a_rollout_device_refuses_rows_that_disagree() {
    let legacy = json!([row("command:npm-test", "block")]);
    let canonical = json!([row("command:npm-test", "allow")]);
    assert_eq!(
        ask(legacy.clone(), canonical.clone(), false, true),
        json!({"reason_codes": ["action"], "rejection": "canonical_shadow_mismatch"})
    );
    assert_eq!(
        ask(legacy, canonical, false, false),
        json!({"reason_codes": ["action"], "rejection": null})
    );
}

#[test]
fn a_missing_shadow_is_recorded_but_never_refuses() {
    let canonical = json!([row("command:npm-test", "allow")]);
    assert_eq!(
        ask(json!([]), canonical, false, true),
        json!({"reason_codes": ["legacy_unavailable"], "rejection": null})
    );
}

#[test]
fn an_evaluating_candidate_reports_no_drift() {
    let legacy = json!([row("command:npm-test", "block")]);
    assert_eq!(
        ask(legacy, json!([]), true, true),
        json!({"reason_codes": [], "rejection": null})
    );
}

#[test]
fn malformed_requests_are_refused() {
    let rows = json!([row("command:npm-test", "allow")]);
    for request in [
        json!("not-an-object"),
        json!({"legacy": rows.clone(), "canonical": rows.clone(), "evaluating": false}),
        json!({"legacy": rows.clone(), "canonical": rows.clone(), "evaluating": "no", "canonical_enforcement": true}),
        json!({"legacy": rows.clone(), "canonical": rows.clone(), "evaluating": false, "canonical_enforcement": true, "extra": 1}),
        json!({"legacy": rows, "canonical": "rows", "evaluating": false, "canonical_enforcement": true}),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
