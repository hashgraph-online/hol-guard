//! The exact Cloud peek returns only the verified allow its request names.

use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use guard_policy_snapshot::local_authority_integrity::sign_local_authority_payload;
use serde_json::Map;

const KEY: &[u8] = b"exact-cloud-local-integrity-key!";
const KEY_ID: &str = "key-1";
const NOW: &str = "2026-10-30T12:00:00+00:00";

fn connection() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
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
             insert into guard_approval_authority_revision values (1, 7);
             insert into approval_requests values ('req-1', 'resolved', 'allow', 'artifact',
               'review', 'codex', 'codex:bash', 'sha256:abc', '/work/a', null);",
        )
        .unwrap();
    connection
}

fn insert_row(connection: &Connection, purpose: &str) {
    let workspace = computed_workspace_policy_key(Some("/work/a"));
    let signed = json!({
        "approval_id": "approval-1",
        "request_id": "req-1",
        "harness": "codex",
        "artifact_id": "codex:bash",
        "artifact_hash": "sha256:abc",
        "workspace": workspace,
        "publisher": null,
        "action": "allow",
        "created_at": "2026-10-30T11:59:00+00:00",
        "expires_at": "2026-10-30T12:09:00+00:00",
        "claimed_at": null,
        "authority_kind": EXACT_CLOUD_AUTHORITY_KIND,
    });
    let signature = sign_local_authority_payload(&signed, KEY, KEY_ID, purpose, NOW).unwrap();
    connection
        .execute(
            "insert into guard_local_once_approvals values ('approval-1', 'req-1', 'codex',
               'codex:bash', 'sha256:abc', ?1, null, 'allow', '2026-10-30T11:59:00+00:00',
               '2026-10-30T12:09:00+00:00', null, ?2, ?3, ?4, ?5, ?6, 'exact-cloud')",
            rusqlite::params![
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

fn peek_with(connection: &Connection, key: Option<&[u8]>) -> Value {
    let mut args = Map::new();
    args.insert("request_id".into(), json!("req-1"));
    args.insert("now".into(), json!(NOW));
    if let Some(key) = key {
        args.insert(
            "integrity_key_b64".into(),
            json!(Base64UrlUnpadded::encode_string(key)),
        );
        args.insert("integrity_key_id".into(), json!(KEY_ID));
    }
    peek(connection, &Args(&args)).unwrap()
}

#[test]
fn a_verified_exact_cloud_allow_is_returned_with_its_revision() {
    let connection = connection();
    insert_row(
        &connection,
        crate::local_once_store::EXACT_CLOUD_INTEGRITY_PURPOSE,
    );
    let decision = peek_with(&connection, Some(KEY));
    assert_eq!(decision["approval_id"], "approval-1");
    assert_eq!(decision["request_id"], "req-1");
    assert_eq!(decision["source"], "approval-gate-once");
    assert_eq!(decision["integrity_status"], "valid");
    assert_eq!(decision["authority_kind"], "exact-cloud");
    assert_eq!(decision["_approval_authority_revision"], 7);
    assert_eq!(decision["updated_at"], "2026-10-30T11:59:00+00:00");
    assert!(decision.get("fresh_local_approval").is_none());
}

#[test]
fn no_key_a_wrong_key_or_a_local_purpose_reads_as_no_authority() {
    let connection = connection();
    insert_row(
        &connection,
        crate::local_once_store::EXACT_CLOUD_INTEGRITY_PURPOSE,
    );
    assert!(peek_with(&connection, None).is_null());
    assert!(peek_with(&connection, Some(&b"another-local-integrity-key-0000"[..])).is_null());

    let local = self::connection();
    insert_row(
        &local,
        crate::local_once_store::LOCAL_ONCE_INTEGRITY_PURPOSE,
    );
    assert!(peek_with(&local, Some(KEY)).is_null());
}

#[test]
fn the_row_must_answer_its_resolved_request() {
    for change in [
        "update approval_requests set status = 'pending'",
        "update approval_requests set resolution_scope = 'publisher'",
        "update approval_requests set policy_action = 'block'",
        "update approval_requests set workspace = '/work/b'",
        "update approval_requests set publisher = 'someone'",
        "update guard_local_once_approvals set claimed_at = '2026-10-30T11:59:30+00:00'",
        "update guard_local_once_approvals set expires_at = '2026-10-30T11:59:59+00:00'",
    ] {
        let connection = connection();
        insert_row(
            &connection,
            crate::local_once_store::EXACT_CLOUD_INTEGRITY_PURPOSE,
        );
        connection.execute_batch(change).unwrap();
        assert!(peek_with(&connection, Some(KEY)).is_null(), "{change}");
    }
}
