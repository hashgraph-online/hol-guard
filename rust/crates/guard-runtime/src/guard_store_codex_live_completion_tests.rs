//! The pieces of a Codex live completion that need no store: which resume
//! replays a decision, which correlation the continuation carries, and the
//! evidence id it records.

use super::*;

const CORRELATION: &str = "gcr_0f1e2d3c-4b5a-4968-8776-655443322110";

#[test]
fn only_a_terminal_resume_of_the_same_action_replays() {
    for status in ["resumed", "sent"] {
        let resume = json!({"resolution_action": "allow", "status": status});
        assert!(terminal_matches(&resume, "allow"), "{status}");
        assert!(!terminal_matches(&resume, "block"), "{status}");
    }
    for status in ["blocked", "skipped"] {
        let resume = json!({"resolution_action": "block", "status": status});
        assert!(terminal_matches(&resume, "block"), "{status}");
    }
    for resume in [
        json!({"resolution_action": "allow", "status": "waiting"}),
        json!({"resolution_action": "allow", "status": "blocked"}),
        json!({"resolution_action": "block", "status": "resumed"}),
        json!({"resolution_action": "allow"}),
        Value::Null,
    ] {
        assert!(!terminal_matches(&resume, "allow"), "{resume}");
        assert!(!terminal_matches(&resume, "block"), "{resume}");
    }
}

#[test]
fn the_first_carried_correlation_wins() {
    let request = json!({
        "continuation_snapshot": {"correlationId": "not-a-correlation"},
        "decision_v2_json": {"correlation_id": format!(" {CORRELATION} ")},
        "correlation_id": "gcr_ffffffff-ffff-4fff-8fff-ffffffffffff",
    });
    assert_eq!(
        correlation(&request, &Value::Null, "req-1").unwrap(),
        CORRELATION
    );
    let metadata = json!({"correlationId": "gcr_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"});
    assert_eq!(
        correlation(&request, &metadata, "req-1").unwrap(),
        "gcr_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    );
}

#[test]
fn a_request_without_a_carried_correlation_derives_its_own() {
    let derived = correlation(&json!({}), &Value::Null, "req-1").unwrap();
    assert!(correlation_shaped(&derived), "{derived}");
    assert_eq!(derived, correlation_id("req-1").unwrap());
}

#[test]
fn evidence_ids_are_random_v4_uuids() {
    let first = evidence_id().unwrap();
    let hex = first.strip_prefix("evidence-").unwrap();
    assert_eq!(hex.len(), 32);
    assert!(hex
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    assert_eq!(&hex[12..13], "4");
    assert!(matches!(&hex[16..17], "8" | "9" | "a" | "b"));
    assert_ne!(first, evidence_id().unwrap());
}

#[test]
fn a_failure_names_its_code() {
    assert_eq!(
        failure("request_not_found"),
        json!({"completed": false, "error": "request_not_found"})
    );
}
