use super::*;
use guard_contracts::POLICY_DECISION_LOOKUP_REQUEST_SCHEMA;
use rusqlite::{params, Connection};
use serde_json::json;

use crate::policy_decision_lookup_op::tests::{seed_store, tmp_store};
use crate::policy_decision_lookup_op::{policy_row_to_json, POLICY_LOOKUP_COLUMNS};

const IDENTITY: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const CAPABILITY: &str = "read-only-inspect";
/// `sha256("read-only-inspect")` and `sha256("*")`, the two capability digests
/// the Python selector builds for this eligibility.
const CAPABILITY_DIGEST: &str = "ba31c0bc03d0b765cf7c135722e999bc8781e64809f537ed74d3dec0a1c6c631";
const ANY_DIGEST: &str = "684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1";
const SIGNED_AT: &str = "2029-01-01T00:00:00+00:00";

fn grant(current_action: &str) -> LocalToolGrantLookupV1 {
    LocalToolGrantLookupV1 {
        tool_identity_hash: IDENTITY.to_owned(),
        capability: CAPABILITY.to_owned(),
        current_action: current_action.to_owned(),
    }
}

fn request(store: &std::path::Path) -> PolicyDecisionLookupRequestV1 {
    serde_json::from_value(json!({
        "schema": POLICY_DECISION_LOOKUP_REQUEST_SCHEMA,
        "request_id": "req-local-tool-grant",
        "store_path": store.to_string_lossy(),
        "guard_home": "/tmp/gh",
        "harness": "codex",
        "artifact_id": Value::Null,
        "artifact_hash": Value::Null,
        "workspace": Value::Null,
        "publisher": Value::Null,
        "now": "2030-01-01T00:00:00+00:00",
        "consume_one_shot": false,
        "integrity_state": {
            "backend": "encrypted-file",
            "mode": "protected",
            "generation": 1,
            "enforcement": "enforce",
            "degraded_reasons": [],
        },
        "integrity_key_b64": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
        "integrity_key_id": "test-policy-key",
    }))
    .expect("lookup request")
}

/// One signed artifact-scope row filed under `artifact_id`.
fn insert_row(connection: &Connection, artifact_id: &str, source: &str, reason: &str) {
    connection
        .execute(
            "insert into policy_decisions
             (harness, scope, artifact_id, action, source, reason, created_at, updated_at)
             values ('codex', 'artifact', ?1, 'allow', ?2, ?3, ?4, ?4)",
            params![artifact_id, source, reason, SIGNED_AT],
        )
        .unwrap();
    let id = connection.last_insert_rowid();
    let row = connection
        .query_row(
            &format!("select {POLICY_LOOKUP_COLUMNS} from policy_decisions where decision_id = ?1"),
            params![id],
            policy_row_to_json,
        )
        .unwrap();
    let signed = guard_policy_snapshot::policy_integrity::sign_local_policy_row(
        &row,
        &[7u8; 32],
        "test-policy-key",
        SIGNED_AT,
        1,
    )
    .unwrap();
    connection
        .execute(
            "update policy_decisions set integrity_version = ?1, integrity_generation = ?2,
             payload_hash = ?3, payload_mac = ?4, integrity_key_id = ?5, signed_at = ?6
             where decision_id = ?7",
            params![
                signed["integrity_version"].as_i64(),
                signed["integrity_generation"].as_i64(),
                signed["payload_hash"].as_str(),
                signed["payload_mac"].as_str(),
                signed["integrity_key_id"].as_str(),
                signed["signed_at"].as_str(),
                id
            ],
        )
        .unwrap();
}

fn store(tag: &str) -> (std::path::PathBuf, Connection) {
    let path = tmp_store(&format!("local-tool-grant-{tag}"));
    let _ = std::fs::remove_file(&path);
    seed_store(&path);
    let connection = Connection::open(&path).unwrap();
    (path, connection)
}

#[test]
fn selectors_match_the_python_grant_ids() {
    assert_eq!(
        selector(&grant("review"), "capability"),
        format!("local-tool-grant:v1:{IDENTITY}:capability:{CAPABILITY_DIGEST}")
    );
    assert_eq!(
        selector(&grant("review"), "version"),
        format!("local-tool-grant:v1:{IDENTITY}:version:{ANY_DIGEST}")
    );
}

#[test]
fn the_capability_grant_answers_before_the_version_grant() {
    let (path, connection) = store("both");
    insert_row(
        &connection,
        &selector(&grant("review"), "capability"),
        "trusted-local-tool",
        "capability grant",
    );
    insert_row(
        &connection,
        &selector(&grant("review"), "version"),
        "trusted-local-tool",
        "version grant",
    );
    let answer = evaluate(&request(&path), &grant("review")).unwrap();
    assert_eq!(answer["decision"]["action"], "allow");
    assert_eq!(answer["decision"]["reason"], "capability grant");
}

#[test]
fn the_version_grant_answers_when_the_capability_has_none() {
    let (path, connection) = store("version-only");
    insert_row(
        &connection,
        &selector(&grant("require-reapproval"), "version"),
        "trusted-local-tool",
        "version grant",
    );
    let answer = evaluate(&request(&path), &grant("require-reapproval")).unwrap();
    assert_eq!(answer["decision"]["reason"], "version grant");
}

#[test]
fn a_row_another_source_filed_under_the_selector_is_not_a_grant() {
    let (path, connection) = store("foreign-source");
    insert_row(
        &connection,
        &selector(&grant("review"), "capability"),
        "approval-gate",
        "not a grant",
    );
    let answer = evaluate(&request(&path), &grant("review")).unwrap();
    assert_eq!(answer["decision"], Value::Null);
}

#[test]
fn an_empty_store_answers_no_grant() {
    let (path, _connection) = store("empty");
    let answer = evaluate(&request(&path), &grant("review")).unwrap();
    assert_eq!(answer["decision"], Value::Null);
}

#[test]
fn an_action_no_review_asked_for_is_never_lifted() {
    let (path, connection) = store("blocked");
    insert_row(
        &connection,
        &selector(&grant("block"), "capability"),
        "trusted-local-tool",
        "capability grant",
    );
    let answer = evaluate(&request(&path), &grant("block")).unwrap();
    assert_eq!(answer["decision"], Value::Null);
    // Python decodes the payload as a mapping, so the gate owes one too.
    assert!(answer.is_object(), "{answer}");
}
