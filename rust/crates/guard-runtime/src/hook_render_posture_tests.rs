use serde_json::{json, Value};

use super::{cursor_probe_reviews, recording_only_for_binding};

fn only(binding: &Value, harness: &str) -> bool {
    recording_only_for_binding(Some(binding), &json!(harness))
}

#[test]
fn no_binding_never_records() {
    assert!(!recording_only_for_binding(None, &json!("codex")));
    assert!(!recording_only_for_binding(
        Some(&Value::Null),
        &json!("codex")
    ));
}

#[test]
fn the_snapshot_mode_decides_without_an_override() {
    assert!(only(&json!({"mode": "observe"}), "codex"));
    assert!(!only(&json!({"mode": "enforce"}), "codex"));
}

#[test]
fn a_watch_override_records_under_an_enforcing_snapshot() {
    let binding = json!({"mode": "enforce", "harness_postures": {"codex": "watch"}});
    assert!(only(&binding, "codex"));
    assert!(!only(&binding, "claude-code"));
}

#[test]
fn a_protected_override_keeps_stopping_under_a_watch_snapshot() {
    let binding = json!({"mode": "observe", "harness_postures": {"codex": "protected"}});
    assert!(!only(&binding, "codex"));
    assert!(only(&binding, "claude-code"));
}

#[test]
fn a_malformed_override_is_ignored() {
    let binding = json!({"mode": "enforce", "harness_postures": {"codex": "bogus"}});
    assert!(!only(&binding, "codex"));
    let binding = json!({"mode": "observe", "harness_postures": {"codex": 3, "": "protected"}});
    assert!(only(&binding, "codex"));
    let binding = json!({"mode": "observe", "harness_postures": "watch"});
    assert!(only(&binding, "codex"));
}

#[test]
fn a_harness_alias_reads_the_canonical_override() {
    let binding = json!({"mode": "enforce", "harness_postures": {"claude-code": "watch"}});
    assert!(only(&binding, "claude"));
    assert!(only(&binding, " Claude_Code "));
}

#[test]
fn a_blank_or_non_text_harness_reads_the_mode() {
    let binding = json!({"mode": "observe", "harness_postures": {"codex": "protected"}});
    assert!(recording_only_for_binding(Some(&binding), &json!("")));
    assert!(recording_only_for_binding(Some(&binding), &json!(7)));
}

#[test]
fn the_cursor_probe_reviews_only_an_enforcing_binding_with_a_workspace() {
    let enforce = json!({"mode": "enforce"});
    assert!(cursor_probe_reviews(Some(&enforce), true));
    assert!(!cursor_probe_reviews(Some(&enforce), false));
    assert!(!cursor_probe_reviews(None, true));
    assert!(!cursor_probe_reviews(
        Some(&json!({"mode": "observe"})),
        true
    ));
    let watch = json!({"mode": "enforce", "harness_postures": {"cursor": "watch"}});
    assert!(!cursor_probe_reviews(Some(&watch), true));
}
