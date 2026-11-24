use super::{capacity_harness, resident_counts, slot, Counts};
use serde_json::json;

#[test]
fn an_unknown_harness_counts_as_other() {
    assert_eq!(slot("claude-code"), "claude-code");
    assert_eq!(slot("Claude-Code"), "other");
    assert_eq!(slot("gemini"), "other");
}

#[test]
fn miss_reasons_count_per_harness_and_unknown_reasons_collapse() {
    let mut counts = Counts::default();
    counts.note("codex", Some("no_resident"));
    counts.note("codex", Some("no_resident"));
    counts.note("codex", Some("/etc/passwd"));
    counts.note("muse", None);
    assert_eq!(
        counts.detail(),
        r#"{"missed":{"codex":{"no_resident":2,"unknown":1}},"received":{"codex":3,"muse":1}}"#
    );
}

#[test]
fn capacity_counts_under_the_adapter_an_alias_names() {
    assert_eq!(capacity_harness("claude"), "claude-code");
    assert_eq!(capacity_harness("oh-my-pi"), "omp");
    assert_eq!(capacity_harness("zai-zcode"), "zcode");
    assert_eq!(capacity_harness("paseo"), "paseo");
    assert_eq!(capacity_harness("claude_code"), "other");
    assert_eq!(capacity_harness(""), "other");
}

#[test]
fn resident_counter_pages_are_bounded_and_normalized() {
    let normalized = resident_counts(&json!({
        "by_harness": {
            "codex": {"answer": 3},
            "gemini": {"answer": 1}
        }
    }))
    .expect("valid counters");
    assert_eq!(
        normalized,
        json!({"codex": {"answer": 3}, "other": {"answer": 1}})
    );
}

#[test]
fn malformed_resident_counter_pages_are_ignored() {
    assert!(resident_counts(&json!({"by_harness": []})).is_none());
    assert!(resident_counts(&json!({
        "by_harness": {"codex": {"Bad-Code": 1}}
    }))
    .is_none());
    assert!(resident_counts(&json!({
        "by_harness": {"codex": {"answer": -1}}
    }))
    .is_none());
}
