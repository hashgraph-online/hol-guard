//! Policy document imports and the MCP request apply, against rows the Python
//! signer recorded in `testdata/policy_integrity_generation/vectors.json`.

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::{apply_mcp_policy_request, import_policy_rows, policy_rows_fingerprint};
use crate::guard_store_args::Args;
use crate::guard_store_policy_upsert::tests::{
    dump, generation, key, key_id, signed_rows, store, verifies_at,
};

const NOW: &str = "2026-10-16T09:00:00Z";

fn request_store() -> Connection {
    let connection = store(&signed_rows());
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null, \
             updated_at text not null);
             create table mcp_policy_requests (request_id text primary key, \
             idempotency_key_hash text not null unique, status text not null default 'pending', \
             policy_document_id text not null, policy_document_digest text not null, \
             expected_current_digest text, expected_policy_generation integer, \
             mode text not null, canonical_policy_yaml text not null, plan_json text not null, \
             created_at text not null, expires_at text not null, resolved_at text, \
             result_json text, failure_code text);
             insert into mcp_policy_requests values ('r1', 'h', 'pending', 'doc', 'sha256:new', \
             null, 3, 'merge', 'yaml', '{}', '2026-10-16T08:55:00Z', '2026-10-16T09:05:00Z', \
             null, null, null);
             insert into sync_state values ('policy_integrity', '{\"generation\": 3}', 'x');",
        )
        .unwrap();
    connection
}

fn row(artifact_id: &str) -> Value {
    json!({
        "harness": "codex",
        "scope": "artifact",
        "artifact_id": artifact_id,
        "artifact_hash": null,
        "workspace": null,
        "publisher": null,
        "action": "block",
        "reason": "policy",
        "owner": "policy",
        "source": "policy-yaml-import",
        "expires_at": null,
        "rule_id": "rule-1",
        "provenance_json": "{}",
    })
}

fn import_args(mode: &str, rows: Vec<Value>, signed: bool) -> Map<String, Value> {
    let mut args = json!({
        "mode": mode,
        "now": NOW,
        "document": {"api_version": "guard.policy/v1", "id": "doc", "digest": "sha256:new"},
        "rows": rows,
    })
    .as_object()
    .cloned()
    .unwrap();
    if signed {
        args.insert(
            "integrity_key_b64".into(),
            json!(Base64UrlUnpadded::encode_string(&key())),
        );
        args.insert("integrity_key_id".into(), json!(key_id()));
        args.insert("current_generation".into(), json!(3));
    }
    args
}

fn fingerprint(connection: &Connection) -> Value {
    policy_rows_fingerprint(connection, &Args(&Map::new())).unwrap()["fingerprint"].clone()
}

fn apply_args(connection: &Connection, now: &str, candidate: Value) -> Map<String, Value> {
    let mut args = import_args("merge", vec![row("codex:project:tool-9")], true);
    args.insert("request_id".into(), json!("r1"));
    args.insert("now".into(), json!(now));
    args.insert("candidate".into(), candidate);
    args.insert("rows_fingerprint".into(), fingerprint(connection));
    args
}

fn candidate() -> Value {
    json!({
        "policy_document_digest": "sha256:new",
        "canonical_policy_yaml": "yaml",
        "mode": "merge",
        "expected_current_digest": null,
        "expected_policy_generation": 3,
    })
}

fn status(connection: &Connection) -> String {
    connection
        .query_row(
            "select status from mcp_policy_requests where request_id = 'r1'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn an_import_signs_the_new_rows_with_the_ones_that_verify() {
    let connection = store(&signed_rows());

    let reply = import_policy_rows(
        &connection,
        &Args(&import_args(
            "merge",
            vec![row("codex:project:tool-9")],
            true,
        )),
    )
    .unwrap();

    assert_eq!(reply["inserted"], json!(1));
    assert_eq!(reply["replaced"], json!(0));
    assert_eq!(reply["next_control_state"]["generation"], json!(4));
    let stored = dump(&connection);
    assert_eq!(stored.len(), 3);
    assert!(stored.iter().all(|row| generation(row) == Some(4)));
    assert!(stored.iter().all(|row| verifies_at(row, 4)));
}

#[test]
fn a_replace_import_drops_every_earlier_imported_row() {
    let connection = store(&signed_rows());
    import_policy_rows(
        &connection,
        &Args(&import_args(
            "merge",
            vec![row("codex:project:a"), row("codex:project:b")],
            false,
        )),
    )
    .unwrap();

    let reply = import_policy_rows(
        &connection,
        &Args(&import_args("replace", vec![row("codex:project:c")], false)),
    )
    .unwrap();

    assert_eq!(reply["replaced"], json!(2));
    assert_eq!(reply["next_control_state"], Value::Null);
    assert_eq!(dump(&connection).len(), 3);
}

#[test]
fn a_merge_import_replaces_the_row_with_the_same_key() {
    let connection = store(&signed_rows());
    let args = import_args("merge", vec![row("codex:project:a")], false);
    import_policy_rows(&connection, &Args(&args)).unwrap();

    let reply = import_policy_rows(&connection, &Args(&args)).unwrap();

    assert_eq!(reply["replaced"], json!(1));
    assert_eq!(dump(&connection).len(), 3);
}

#[test]
fn an_apply_writes_the_rows_and_marks_the_request_applied() {
    let connection = request_store();

    let args = apply_args(&connection, NOW, candidate());
    let reply = apply_mcp_policy_request(&connection, &Args(&args)).unwrap();

    assert_eq!(
        reply["applied"],
        json!({"request_id": "r1", "resolved_at": NOW, "inserted": 1, "replaced": 0})
    );
    assert_eq!(reply["next_control_state"]["generation"], json!(4));
    assert_eq!(status(&connection), "applied");
    let result: String = connection
        .query_row(
            "select result_json from mcp_policy_requests where request_id = 'r1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(result, r#"{"inserted":1,"replaced":0}"#);
}

#[test]
fn an_expired_request_is_marked_expired_and_writes_no_row() {
    let connection = request_store();

    let args = apply_args(&connection, "2026-10-16T09:10:00Z", candidate());
    let reply = apply_mcp_policy_request(&connection, &Args(&args)).unwrap();

    assert_eq!(reply, json!({"error": "approval_expired"}));
    assert_eq!(status(&connection), "expired");
    assert_eq!(dump(&connection).len(), 2);
}

#[test]
fn a_changed_candidate_is_refused() {
    let connection = request_store();
    let mut changed = candidate();
    changed["canonical_policy_yaml"] = json!("other");

    let args = apply_args(&connection, NOW, changed);
    let reply = apply_mcp_policy_request(&connection, &Args(&args)).unwrap();

    assert_eq!(reply, json!({"error": "candidate_digest_mismatch"}));
    assert_eq!(status(&connection), "pending");
}

#[test]
fn imported_rows_changed_since_the_digest_was_read_are_refused() {
    let connection = request_store();
    let args = apply_args(&connection, NOW, candidate());
    import_policy_rows(
        &connection,
        &Args(&import_args("merge", vec![row("codex:project:z")], false)),
    )
    .unwrap();

    let reply = apply_mcp_policy_request(&connection, &Args(&args)).unwrap();

    assert_eq!(reply, json!({"error": "current_digest_mismatch"}));
    assert_eq!(status(&connection), "pending");
}

#[test]
fn a_moved_generation_is_refused() {
    let connection = request_store();
    connection
        .execute(
            "update sync_state set payload_json = '{\"generation\": 5}'",
            [],
        )
        .unwrap();

    let args = apply_args(&connection, NOW, candidate());
    let reply = apply_mcp_policy_request(&connection, &Args(&args)).unwrap();

    assert_eq!(reply, json!({"error": "stale_policy_generation"}));
}

#[test]
fn a_recovered_request_is_refused() {
    let connection = request_store();
    connection
        .execute(
            "insert into sync_state values \
             ('business_policy_request_recovered_v1/r1', '{}', 'x')",
            [],
        )
        .unwrap();

    let args = apply_args(&connection, NOW, candidate());
    let reply = apply_mcp_policy_request(&connection, &Args(&args)).unwrap();

    assert_eq!(reply, json!({"error": "business_source_already_recovered"}));
}

#[test]
fn a_resolved_or_missing_request_is_refused() {
    let connection = request_store();
    connection
        .execute("update mcp_policy_requests set status = 'declined'", [])
        .unwrap();
    let args = apply_args(&connection, NOW, candidate());

    let reply = apply_mcp_policy_request(&connection, &Args(&args)).unwrap();
    assert_eq!(
        reply,
        json!({"error": "approval_already_resolved", "status": "declined"})
    );

    let mut missing = args.clone();
    missing.insert("request_id".into(), json!("r2"));
    let reply = apply_mcp_policy_request(&connection, &Args(&missing)).unwrap();
    assert_eq!(reply, json!({"error": "policy_request_not_found"}));
}
