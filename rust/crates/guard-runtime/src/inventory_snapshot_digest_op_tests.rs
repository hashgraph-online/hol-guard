use guard_contracts::{
    InventorySnapshotDigestRequestV1, InventorySnapshotDigestResultV1,
    INVENTORY_SNAPSHOT_DIGEST_REQUEST_SCHEMA, INVENTORY_SNAPSHOT_DIGEST_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use super::{digest_for, evaluate_inventory_snapshot_digest_request, refusal};

fn request(items: Vec<Value>, findings: Vec<Value>, sources: Vec<Value>) -> Value {
    json!({
        "schema": INVENTORY_SNAPSHOT_DIGEST_REQUEST_SCHEMA,
        "request_id": "inventory-snapshot-digest-test",
        "agent_type": "codex",
        "runtime_version": "3.44.0",
        "items": items,
        "findings": findings,
        "sources": sources,
    })
}

fn parse(wire: &Value) -> InventorySnapshotDigestRequestV1 {
    serde_json::from_value(wire.clone()).expect("request")
}

fn digest(wire: &Value) -> String {
    digest_for(&parse(wire))
}

fn item(item_id: &str, metadata: Value) -> Value {
    json!({
        "item_id": item_id,
        "item_kind": "skill",
        "display_name": item_id,
        "metadata": metadata,
        "capability_categories": ["filesystem"],
        "content_hash": "sha256:abc",
        "drift_state": "unchanged",
        "risk_level": "low",
        "scanner_sources": ["inventory"],
        "security_score": 90,
        "source_fingerprint": "fingerprint",
    })
}

fn finding(finding_id: &str) -> Value {
    json!({
        "finding_id": finding_id,
        "source": "scanner",
        "severity": "low",
        "confidence": "high",
        "title": "title",
        "artifact_id": "artifact",
        "check_id": "check",
        "summary": "summary",
        "evidence": {"path": "/tmp/thing"},
    })
}

fn source(source_id: &str) -> Value {
    json!({
        "source_id": source_id,
        "source_type": "filesystem",
        "status": "ok",
        "detail": "detail",
        "captured_at": "2026-01-01T00:00:00Z",
    })
}

fn response(wire: &Value) -> InventorySnapshotDigestResultV1 {
    let encoded =
        evaluate_inventory_snapshot_digest_request(&parse(wire)).expect("encoded response");
    serde_json::from_slice(&encoded).expect("result")
}

#[test]
fn answers_with_a_hex_digest_bound_to_its_request() {
    let wire = request(
        vec![item("alpha", json!({"path": "/tmp/alpha"}))],
        vec![finding("f-1")],
        vec![source("s-1")],
    );
    let result = response(&wire);

    assert_eq!(result.schema, INVENTORY_SNAPSHOT_DIGEST_RESULT_SCHEMA);
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    assert!(result.request_sha256.starts_with("sha256:"));

    let payload = result.payload.expect("payload");
    let answered = payload["digest"].as_str().expect("digest");
    assert_eq!(answered, digest(&wire));
    // Recorded from the Python grammar this op replaces, over these exact
    // rows. A conversion that read a field differently would move it.
    assert_eq!(
        answered,
        "123a99335da2a05c89763d91882efa0e517dab2799d7b36d167b986a98f07e02"
    );
}

#[test]
fn two_scans_of_an_unchanged_machine_agree() {
    // The same inventory observed twice: the rows arrive in another order and
    // carry different observation stamps, which is what a second scan of an
    // unchanged machine looks like.
    let first = request(
        vec![
            item(
                "alpha",
                json!({"path": "/tmp/alpha", "observedAt": "08:00"}),
            ),
            item("beta", json!({"path": "/tmp/beta", "scanDurationMs": 12})),
        ],
        vec![finding("f-1"), finding("f-2")],
        vec![source("s-1"), source("s-2")],
    );
    let second = request(
        vec![
            item("beta", json!({"path": "/tmp/beta", "scanDurationMs": 4100})),
            item(
                "alpha",
                json!({"path": "/tmp/alpha", "observedAt": "09:30"}),
            ),
        ],
        vec![finding("f-2"), finding("f-1")],
        vec![source("s-2"), source("s-1")],
    );

    assert_eq!(digest(&first), digest(&second));
}

#[test]
fn a_changed_item_changes_the_digest() {
    let before = request(
        vec![item("alpha", json!({"path": "/tmp/alpha"}))],
        vec![],
        vec![],
    );
    let after = request(
        vec![item("alpha", json!({"path": "/tmp/moved"}))],
        vec![],
        vec![],
    );

    assert_ne!(digest(&before), digest(&after));
}

#[test]
fn an_absent_summary_is_not_an_empty_one() {
    let mut absent = finding("f-1");
    absent.as_object_mut().expect("object").remove("summary");
    let mut empty = finding("f-1");
    empty["summary"] = json!("");

    assert_ne!(
        digest(&request(vec![], vec![absent], vec![])),
        digest(&request(vec![], vec![empty], vec![]))
    );
}

#[test]
fn an_absent_dataclass_field_reads_as_its_default() {
    // `risk_level` defaults to `info`. A row that omits it and a row that
    // spells the default are the same inventory.
    let mut omitted = item("alpha", json!({}));
    omitted
        .as_object_mut()
        .expect("object")
        .remove("risk_level");
    let mut spelled = item("alpha", json!({}));
    spelled["risk_level"] = json!("info");

    assert_eq!(
        digest(&request(vec![omitted], vec![], vec![])),
        digest(&request(vec![spelled], vec![], vec![]))
    );
}

#[test]
fn refuses_a_request_naming_another_contract() {
    let mut wire = request(vec![], vec![], vec![]);
    wire["schema"] = json!("guard-inventory-url-redaction-request.v1");

    assert_eq!(
        refusal(&parse(&wire)),
        Some("native_inventory_snapshot_digest_schema_mismatch")
    );
    let result = response(&wire);
    assert_eq!(result.status, "error");
    assert!(result.payload.is_none());
}

#[test]
fn refuses_a_row_that_is_not_an_object() {
    // A row of another shape would read as a row of defaults, which is a
    // digest over an inventory the caller did not send.
    let wire = request(vec![json!("alpha")], vec![], vec![]);

    assert_eq!(
        refusal(&parse(&wire)),
        Some("native_inventory_snapshot_digest_invalid_row")
    );
    let result = response(&wire);
    assert_eq!(result.code, "native_inventory_snapshot_digest_invalid_row");
    assert!(result.payload.is_none());
}

#[test]
fn refuses_a_snapshot_larger_than_the_request_bound() {
    let filler = "x".repeat(4096);
    let items: Vec<Value> = (0..4096)
        .map(|index| item(&format!("item-{index}"), json!({"blob": filler})))
        .collect();
    let error = evaluate_inventory_snapshot_digest_request(&parse(&request(items, vec![], vec![])))
        .expect_err("refused");

    assert_eq!(error, "native_inventory_snapshot_digest_too_large");
}
