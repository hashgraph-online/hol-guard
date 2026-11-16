//! A waiting package install reads and spends only the verified exact Cloud
//! allow issued for its own request, its artifact and its hash.

use super::*;
use crate::local_once_store::{
    EXACT_CLOUD_AUTHORITY_KIND, EXACT_CLOUD_INTEGRITY_PURPOSE, LOCAL_ONCE_INTEGRITY_PURPOSE,
};
use crate::policy_decision_lookup_op::computed_workspace_policy_key;
use base64ct::{Base64UrlUnpadded, Encoding};
use guard_policy_snapshot::local_authority_integrity::sign_local_authority_payload;
use serde_json::Map;

const KEY: &[u8] = b"exact-cloud-local-integrity-key!";
const KEY_ID: &str = "key-1";
const NOW: &str = "2026-11-06T12:00:00+00:00";
const ARTIFACT: &str = "guard-cli:project:package-request:npm-install-left-pad";
const HASH: &str = "sha256:package-context";

fn connection() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(&format!(
            "create table approval_requests (request_id text primary key, status text,
               resolution_action text, resolution_scope text, policy_action text, harness text,
               artifact_id text, artifact_hash text, workspace text, publisher text);
             create table guard_local_once_approvals (approval_id text primary key,
               request_id text not null, harness text not null, artifact_id text not null,
               artifact_hash text not null, workspace text, publisher text, action text not null,
               created_at text not null, expires_at text not null, claimed_at text,
               integrity_version integer, payload_hash text, payload_mac text,
               integrity_key_id text, signed_at text, authority_kind text);
             create table guard_approval_authority_revision (singleton integer primary key,
               revision integer);
             insert into guard_approval_authority_revision values (1, 3);
             insert into approval_requests values ('req-1', 'resolved', 'allow', 'artifact',
               'require-reapproval', 'claude-code', '{ARTIFACT}', '{HASH}', '/work/app', null);"
        ))
        .unwrap();
    connection
}

fn insert_row(connection: &Connection, purpose: &str) {
    let workspace = computed_workspace_policy_key(Some("/work/app"));
    let signed = json!({
        "approval_id": "approval-1",
        "request_id": "req-1",
        "harness": "claude-code",
        "artifact_id": ARTIFACT,
        "artifact_hash": HASH,
        "workspace": workspace,
        "publisher": null,
        "action": "allow",
        "created_at": "2026-11-06T11:59:00+00:00",
        "expires_at": "2026-11-06T12:14:00+00:00",
        "claimed_at": null,
        "authority_kind": EXACT_CLOUD_AUTHORITY_KIND,
    });
    let signature = sign_local_authority_payload(&signed, KEY, KEY_ID, purpose, NOW).unwrap();
    connection
        .execute(
            "insert into guard_local_once_approvals values ('approval-1', 'req-1', 'claude-code',
               ?1, ?2, ?3, null, 'allow', '2026-11-06T11:59:00+00:00',
               '2026-11-06T12:14:00+00:00', null, ?4, ?5, ?6, ?7, ?8, 'exact-cloud')",
            rusqlite::params![
                ARTIFACT,
                HASH,
                workspace,
                signature.integrity_version,
                signature.payload_hash,
                signature.payload_mac,
                signature.integrity_key_id,
                signature.signed_at,
            ],
        )
        .unwrap();
}

fn keyed(mut args: Map<String, Value>, key: Option<&[u8]>) -> Map<String, Value> {
    args.insert("request_id".into(), json!("req-1"));
    args.insert("now".into(), json!(NOW));
    if let Some(key) = key {
        args.insert(
            "integrity_key_b64".into(),
            json!(Base64UrlUnpadded::encode_string(key)),
        );
        args.insert("integrity_key_id".into(), json!(KEY_ID));
    }
    args
}

fn peek_for(connection: &Connection, artifact_id: &str, hash: &str, key: Option<&[u8]>) -> Value {
    let mut args = Map::new();
    args.insert("artifact_id".into(), json!(artifact_id));
    args.insert("artifact_hash".into(), json!(hash));
    peek(connection, &Args(&keyed(args, key))).unwrap()
}

fn consume_with(connection: &Connection, decision: &Value) -> Value {
    let mut args = Map::new();
    args.insert("decision".into(), decision.clone());
    consume(connection, &Args(&keyed(args, Some(KEY)))).unwrap()
}

#[test]
fn the_waiting_install_reads_its_allow_and_spends_it_once() {
    let connection = connection();
    insert_row(&connection, EXACT_CLOUD_INTEGRITY_PURPOSE);
    let decision = peek_for(&connection, ARTIFACT, HASH, Some(KEY));
    assert_eq!(decision["approval_id"], "approval-1");
    assert_eq!(decision["request_id"], "req-1");
    assert_eq!(decision["authority_kind"], "exact-cloud");
    assert_eq!(decision["_approval_authority_revision"], 3);

    assert_eq!(consume_with(&connection, &decision), json!(true));
    assert_eq!(consume_with(&connection, &decision), json!(false));
    assert!(peek_for(&connection, ARTIFACT, HASH, Some(KEY)).is_null());
}

#[test]
fn another_artifact_or_hash_or_a_non_package_artifact_reads_as_no_authority() {
    let connection = connection();
    insert_row(&connection, EXACT_CLOUD_INTEGRITY_PURPOSE);
    assert!(peek_for(&connection, ARTIFACT, "sha256:changed", Some(KEY)).is_null());
    assert!(peek_for(
        &connection,
        "guard-cli:project:package-request:other",
        HASH,
        Some(KEY)
    )
    .is_null());

    let shell = self::connection();
    shell
        .execute_batch(
            "update approval_requests set artifact_id = 'claude-code:bash';
             update approval_requests set policy_action = 'review';",
        )
        .unwrap();
    let workspace = computed_workspace_policy_key(Some("/work/app"));
    let signed = json!({
        "approval_id": "approval-1", "request_id": "req-1", "harness": "claude-code",
        "artifact_id": "claude-code:bash", "artifact_hash": HASH, "workspace": workspace,
        "publisher": null, "action": "allow", "created_at": "2026-11-06T11:59:00+00:00",
        "expires_at": "2026-11-06T12:14:00+00:00", "claimed_at": null,
        "authority_kind": EXACT_CLOUD_AUTHORITY_KIND,
    });
    let signature =
        sign_local_authority_payload(&signed, KEY, KEY_ID, EXACT_CLOUD_INTEGRITY_PURPOSE, NOW)
            .unwrap();
    shell
        .execute(
            "insert into guard_local_once_approvals values ('approval-1', 'req-1', 'claude-code',
               'claude-code:bash', ?1, ?2, null, 'allow', '2026-11-06T11:59:00+00:00',
               '2026-11-06T12:14:00+00:00', null, ?3, ?4, ?5, ?6, ?7, 'exact-cloud')",
            rusqlite::params![
                HASH,
                workspace,
                signature.integrity_version,
                signature.payload_hash,
                signature.payload_mac,
                signature.integrity_key_id,
                signature.signed_at,
            ],
        )
        .unwrap();
    assert!(peek_for(&shell, "claude-code:bash", HASH, Some(KEY)).is_null());
}

#[test]
fn no_key_a_wrong_key_a_local_purpose_or_a_tampered_row_reads_as_no_authority() {
    let connection = connection();
    insert_row(&connection, EXACT_CLOUD_INTEGRITY_PURPOSE);
    assert!(peek_for(&connection, ARTIFACT, HASH, None).is_null());
    assert!(peek_for(
        &connection,
        ARTIFACT,
        HASH,
        Some(&b"another-local-integrity-key-0000"[..])
    )
    .is_null());

    let local = self::connection();
    insert_row(&local, LOCAL_ONCE_INTEGRITY_PURPOSE);
    assert!(peek_for(&local, ARTIFACT, HASH, Some(KEY)).is_null());

    let tampered = self::connection();
    insert_row(&tampered, EXACT_CLOUD_INTEGRITY_PURPOSE);
    tampered
        .execute_batch(
            "update guard_local_once_approvals set expires_at = '2026-11-06T13:00:00+00:00'",
        )
        .unwrap();
    assert!(peek_for(&tampered, ARTIFACT, HASH, Some(KEY)).is_null());
}

#[test]
fn a_decision_for_another_request_or_with_an_edited_field_is_not_spent() {
    let connection = connection();
    insert_row(&connection, EXACT_CLOUD_INTEGRITY_PURPOSE);
    let decision = peek_for(&connection, ARTIFACT, HASH, Some(KEY));

    let mut other_request = decision.clone();
    other_request["request_id"] = json!("req-2");
    assert_eq!(consume_with(&connection, &other_request), json!(false));

    let mut longer = decision.clone();
    longer["expires_at"] = json!("2026-11-06T13:00:00+00:00");
    assert_eq!(consume_with(&connection, &longer), json!(false));

    let mut stale = decision.clone();
    stale["_approval_authority_revision"] = json!(2);
    assert_eq!(consume_with(&connection, &stale), json!(false));

    assert_eq!(consume_with(&connection, &decision), json!(true));
}

fn peek_over(connection: &Connection, ordinary: Value) -> Value {
    let mut args = Map::new();
    args.insert("artifact_id".into(), json!(ARTIFACT));
    args.insert("artifact_hash".into(), json!(HASH));
    args.insert("ordinary_decision".into(), ordinary);
    peek(connection, &Args(&keyed(args, Some(KEY)))).unwrap()
}

#[test]
fn the_allow_outranks_a_family_rule_row_but_not_a_restriction_saved_for_the_artifact() {
    let connection = connection();
    insert_row(&connection, EXACT_CLOUD_INTEGRITY_PURPOSE);
    let family = |action: &str| {
        json!({
            "action": action, "artifact_hash": null, "artifact_id": "family:package-request",
            "decision_id": 3, "harness": "guard-cli", "owner": "rule-1", "scope": "harness",
            "source": "policy-bundle",
        })
    };
    for action in ["block", "sandbox-required", "require-reapproval"] {
        assert_eq!(
            peek_over(&connection, family(action))["request_id"],
            "req-1",
            "family {action}"
        );
    }
    let saved = |action: &str| {
        json!({
            "action": action, "artifact_hash": HASH, "artifact_id": ARTIFACT, "decision_id": 4,
            "harness": "guard-cli", "scope": "artifact", "source": "approval-gate",
        })
    };
    assert_eq!(
        peek_over(&connection, saved("allow"))["request_id"],
        "req-1"
    );
    assert_eq!(
        peek_over(&connection, saved("require-reapproval"))["request_id"],
        "req-1"
    );
    for action in ["block", "sandbox-required"] {
        assert!(peek_over(&connection, saved(action)).is_null(), "{action}");
    }
}
