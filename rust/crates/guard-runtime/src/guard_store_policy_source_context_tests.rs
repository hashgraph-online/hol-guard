use super::*;
use serde_json::json;

fn row(fields: &[(&str, Value)]) -> Row {
    fields
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn approval(request_id: &str, resolved_at: &str, target: &str) -> Row {
    row(&[
        ("request_id", json!(request_id)),
        ("harness", json!("omp")),
        ("artifact_id", json!("omp:native-pretool:bash")),
        ("artifact_hash", json!("native-review-v4:binding")),
        ("artifact_name", json!("bash")),
        ("launch_target", json!(target)),
        ("resolved_at", json!(resolved_at)),
        ("resolution_action", json!("allow")),
        ("resolution_scope", json!("artifact")),
    ])
}

fn token_item(updated_at: &str) -> Item {
    Item {
        harness: "omp".to_owned(),
        artifact_id: Some("omp:native-pretool:bash".to_owned()),
        artifact_hash: Some("guard-approval-context:v1:token".to_owned()),
        workspace: None,
        reason: Some("approved in review".to_owned()),
        action: Some("allow".to_owned()),
        updated_at: Some(updated_at.to_owned()),
    }
}

fn index(approvals: Vec<Row>, receipts: Vec<Row>) -> Index {
    Index {
        receipts: Table::index(receipts),
        inventory: HashMap::new(),
        approvals: Table::index(approvals),
    }
}

#[test]
fn context_token_names_its_own_approval_not_the_newest() {
    let index = index(
        vec![
            approval("req-old", "2026-10-20T10:00:00Z", "cd /repo && git status"),
            approval("req-new", "2026-10-20T11:00:00Z", "rm -rf /tmp/build"),
        ],
        vec![],
    );
    let context = lookup(&index, &token_item("2026-10-20T10:00:00Z"));
    assert_eq!(
        context["remembered_command"],
        json!("cd /repo && git status")
    );
}

#[test]
fn context_token_ambiguous_timestamp_stays_unnamed() {
    let index = index(
        vec![
            approval("req-a", "2026-10-20T10:00:00Z", "git status"),
            approval("req-b", "2026-10-20T10:00:00Z", "git diff"),
        ],
        vec![],
    );
    assert_eq!(
        lookup(&index, &token_item("2026-10-20T10:00:00Z")),
        Value::Null
    );
}

#[test]
fn context_token_receipt_follows_the_timed_approval() {
    let receipt = row(&[
        ("receipt_id", json!("receipt-1")),
        ("harness", json!("omp")),
        ("artifact_id", json!("omp:native-pretool:bash")),
        ("artifact_hash", json!("native-review-v4:binding")),
        ("artifact_name", json!("bash")),
        ("capabilities_summary", json!("approval decision")),
        ("timestamp", json!("2026-10-20T10:00:01Z")),
        ("approval_request_id", json!("req-old")),
    ]);
    let index = index(
        vec![approval("req-old", "2026-10-20T10:00:00Z", "git status")],
        vec![receipt],
    );
    let context = lookup(&index, &token_item("2026-10-20T10:00:00Z"));
    assert_eq!(context["source_receipt_id"], json!("receipt-1"));
    assert_eq!(context["remembered_command"], json!("git status"));
}

#[test]
fn regular_hash_mismatch_still_names_nothing() {
    let mut item = token_item("2026-10-20T10:00:00Z");
    item.artifact_hash =
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned());
    let index = index(
        vec![approval("req-old", "2026-10-20T10:00:00Z", "git status")],
        vec![],
    );
    assert_eq!(lookup(&index, &item), Value::Null);
}

#[test]
fn same_instant_normalizes_utc_spellings() {
    assert!(same_instant(
        Some("2026-10-20T10:00:00Z"),
        Some("2026-10-20T10:00:00.000000+00:00")
    ));
    assert!(same_instant(
        Some("2026-10-20T10:00:00.5Z"),
        Some("2026-10-20T10:00:00.500000+00:00")
    ));
    assert!(!same_instant(
        Some("2026-10-20T10:00:01Z"),
        Some("2026-10-20T10:00:00Z")
    ));
    assert!(!same_instant(Some("2026-10-20T10:00:00Z"), None));
    assert!(!same_instant(None, None));
    assert!(!same_instant(Some("not-a-time"), Some("other-garbage")));
}

#[test]
fn context_token_join_survives_differing_timestamp_spellings() {
    // The policy row canonicalizes updated_at with microseconds; a
    // resolution stored before that canonicalization keeps its caller's
    // spelling. The join must still find the approval.
    let index = index(
        vec![approval("req-old", "2026-10-20T10:00:00Z", "git status")],
        vec![],
    );
    let context = lookup(&index, &token_item("2026-10-20T10:00:00.000000+00:00"));
    assert_eq!(context["remembered_command"], json!("git status"));
}
