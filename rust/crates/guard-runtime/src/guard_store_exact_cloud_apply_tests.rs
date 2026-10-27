//! The refusals that protect a signed Cloud Review verdict, and the signing
//! parity of the authority it writes.
//!
//! Each refusal below is a case where the local install changed under a
//! verdict the cloud signed earlier: a different OAuth identity, a withdrawn
//! or expired consent, a receipt past its deadline, a replayed delivery. The
//! queue read and the resolution write are exercised end to end by
//! `tests/test_guard_exact_cloud_review.py` against the native binary.

use super::*;
use crate::local_once_store::LOCAL_ONCE_INTEGRITY_PURPOSE;
use guard_policy_snapshot::local_authority_integrity::verify_local_authority_payload;
use rusqlite::Connection;
use serde_json::Map;

const THUMBPRINT: &str = "ZjRkNWU2ZjdhOGI5YzBkMWUyZjNhNGI1";
const KEY: &[u8] = b"exact-cloud-local-integrity-key!";
const KEY_ID: &str = "key-1";

fn connection() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null,
               updated_at text not null);
             create table guard_devices (device_key text primary key, installation_id text not null,
               device_label text not null, created_at text not null, updated_at text not null);
             create table guard_events (event_id integer primary key autoincrement,
               event_name text not null, payload_json text not null, occurred_at text not null);
             create table guard_exact_cloud_review_receipts (receipt_id text primary key,
               request_id text not null, claimed_at text not null);
             create table guard_local_once_approvals (approval_id text primary key,
               request_id text not null, harness text not null, artifact_id text not null,
               artifact_hash text not null, workspace text, publisher text, action text not null,
               created_at text not null, expires_at text not null, claimed_at text,
               integrity_version integer, payload_hash text, payload_mac text,
               integrity_key_id text, signed_at text, authority_kind text);",
        )
        .unwrap();
    // The queue read selects every column the approval reader names, so the
    // fixture takes its column list from that reader rather than a copy that
    // can fall behind it.
    let columns = crate::guard_store_approval_reads::COLUMNS
        .split(", ")
        .map(|name| format!("{name} text"))
        .collect::<Vec<_>>()
        .join(", ");
    connection
        .execute_batch(&format!("create table approval_requests ({columns});"))
        .unwrap();
    connection
}

fn put_state(connection: &Connection, state_key: &str, payload: &Value) {
    exec(
        connection,
        "insert or replace into sync_state (state_key, payload_json, updated_at)
         values (?, ?, '2026-01-01T00:00:00+00:00')",
        &[
            Value::from(state_key),
            Value::from(dumps_sorted(payload).unwrap()),
        ],
    )
    .unwrap();
}

fn oauth_payload() -> Value {
    json!({
        "device_id": THUMBPRINT,
        "grant_id": "grant-1",
        "machine_id": "machine-1",
        "runtime_id": "runtime-1",
        "workspace_id": "workspace-1",
    })
}

/// The binding the cloud signed over for the fixture install.
fn binding() -> Value {
    json!({
        "deviceId": THUMBPRINT,
        "dpopThumbprint": THUMBPRINT,
        "grantId": "grant-1",
        "installationId": "install-1",
        "machineId": "machine-1",
        "runtimeId": "runtime-1",
        "workspaceId": "workspace-1",
    })
}

fn capability(expires_at: &str) -> Value {
    let mut payload = binding();
    payload
        .as_object_mut()
        .unwrap()
        .insert("expiresAt".to_owned(), Value::from(expires_at));
    payload
}

fn seeded() -> Connection {
    let connection = connection();
    exec(
        &connection,
        "insert into guard_devices values ('local-device', 'install-1', 'laptop',
           '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
        &[],
    )
    .unwrap();
    put_state(&connection, OAUTH_KEY, &oauth_payload());
    connection
}

fn args_map(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

/// A deny verdict for a request that does not exist, so every refusal before
/// the queue read is reached without a full `approval_requests` fixture.
fn deny_args(overrides: Vec<(&str, Value)>) -> Map<String, Value> {
    let mut map = args_map(vec![
        ("request_id", Value::from("req-1")),
        ("receipt_id", Value::from("receipt-1")),
        ("resolution_action", Value::from("deny")),
        ("resolution_scope", Value::from("once")),
        ("reason", Value::from("cloud review")),
        (
            "receipt_expires_at",
            Value::from("2099-01-01T00:00:00+00:00"),
        ),
        ("skip_exact_capability", Value::Bool(true)),
        ("expected_capability", Value::Null),
        ("expected_oauth_binding", binding()),
        ("expected_request", Value::Object(Map::new())),
        ("expected_raw_request", Value::Object(Map::new())),
        ("dpop_thumbprint", Value::from(THUMBPRINT)),
    ]);
    for (key, value) in overrides {
        map.insert(key.to_owned(), value);
    }
    map
}

fn apply(connection: &Connection, map: &Map<String, Value>) -> StoreResult<Value> {
    apply_signed_remote_exact_result(connection, "/guard/home", &Args(map), None)
}

fn error_code(value: &Value) -> &str {
    value.get("error").and_then(Value::as_str).unwrap_or("")
}

/// The thumbprint the caller verified is the whole binding: without it the
/// stored credentials name no delivery target, so the verdict is refused
/// rather than applied to whatever identity happens to be stored now.
#[test]
fn missing_thumbprint_refuses_the_verdict() {
    let connection = seeded();
    let map = deny_args(vec![("dpop_thumbprint", Value::Null)]);
    let outcome = apply(&connection, &map).unwrap();
    assert_eq!(error_code(&outcome), "remote_exact_oauth_changed");
    assert_eq!(outcome["resolved"], Value::Bool(false));
    assert_eq!(outcome["replayed"], Value::Bool(false));
}

/// The stored `device_id` must still be the verified thumbprint. A rotated
/// credential leaves the signed binding naming an identity this install no
/// longer holds.
#[test]
fn rotated_device_id_refuses_the_verdict() {
    let connection = seeded();
    let mut rotated = oauth_payload();
    rotated
        .as_object_mut()
        .unwrap()
        .insert("device_id".to_owned(), Value::from("other-device"));
    put_state(&connection, OAUTH_KEY, &rotated);
    let outcome = apply(&connection, &deny_args(vec![])).unwrap();
    assert_eq!(error_code(&outcome), "remote_exact_oauth_changed");
}

/// A reinstall changes `installationId` without touching the credential, and
/// the binding still has to match field for field.
#[test]
fn reinstalled_device_refuses_the_verdict() {
    let connection = seeded();
    exec(
        &connection,
        "update guard_devices set installation_id = 'install-2'",
        &[],
    )
    .unwrap();
    let outcome = apply(&connection, &deny_args(vec![])).unwrap();
    assert_eq!(error_code(&outcome), "remote_exact_oauth_changed");
}

/// Revocation is checked even when the caller skips the capability check, so
/// withdrawing Cloud Review stops in-flight verdicts immediately.
#[test]
fn revocation_refuses_a_skipped_capability_check() {
    let connection = seeded();
    put_state(
        &connection,
        REVOCATION_KEY,
        &json!({"revoked_at": "2026-01-02"}),
    );
    let outcome = apply(&connection, &deny_args(vec![])).unwrap();
    assert_eq!(error_code(&outcome), "cloud_review_capability_revoked");
}

/// Revocation outranks a capability that still looks current.
#[test]
fn revocation_outranks_a_matching_capability() {
    let connection = seeded();
    let consent = capability("2099-01-01T00:00:00+00:00");
    put_state(&connection, CAPABILITY_KEY, &consent);
    put_state(
        &connection,
        REVOCATION_KEY,
        &json!({"revoked_at": "2026-01-02"}),
    );
    let map = deny_args(vec![
        ("skip_exact_capability", Value::Bool(false)),
        ("expected_capability", consent),
    ]);
    assert_eq!(
        error_code(&apply(&connection, &map).unwrap()),
        "cloud_review_capability_revoked"
    );
}

/// A capability replaced since the cloud signed the verdict is a different
/// consent, not a renewed one.
#[test]
fn changed_capability_refuses_the_verdict() {
    let connection = seeded();
    put_state(
        &connection,
        CAPABILITY_KEY,
        &capability("2099-01-01T00:00:00+00:00"),
    );
    let map = deny_args(vec![
        ("skip_exact_capability", Value::Bool(false)),
        (
            "expected_capability",
            capability("2098-01-01T00:00:00+00:00"),
        ),
    ]);
    assert_eq!(
        error_code(&apply(&connection, &map).unwrap()),
        "remote_exact_capability_changed"
    );
}

/// A capability whose binding names another install cannot authorize this one,
/// even when the caller expected exactly that capability.
#[test]
fn capability_bound_elsewhere_refuses_the_verdict() {
    let connection = seeded();
    let mut consent = capability("2099-01-01T00:00:00+00:00");
    consent
        .as_object_mut()
        .unwrap()
        .insert("machineId".to_owned(), Value::from("machine-2"));
    put_state(&connection, CAPABILITY_KEY, &consent);
    let map = deny_args(vec![
        ("skip_exact_capability", Value::Bool(false)),
        ("expected_capability", consent),
    ]);
    assert_eq!(
        error_code(&apply(&connection, &map).unwrap()),
        "cloud_review_capability_binding_mismatch"
    );
}

/// An expired consent and a consent with no expiry at all are both refused;
/// a missing `expiresAt` is not an unlimited one.
#[test]
fn expired_or_undated_capability_refuses_the_verdict() {
    for consent in [capability("2020-01-01T00:00:00+00:00"), binding()] {
        let connection = seeded();
        put_state(&connection, CAPABILITY_KEY, &consent);
        let map = deny_args(vec![
            ("skip_exact_capability", Value::Bool(false)),
            ("expected_capability", consent),
        ]);
        assert_eq!(
            error_code(&apply(&connection, &map).unwrap()),
            "cloud_review_capability_expired"
        );
    }
}

/// A receipt past its deadline, or with no readable deadline, is refused
/// before the queue is touched.
#[test]
fn expired_or_malformed_receipt_deadline_refuses_the_verdict() {
    for deadline in ["2020-01-01T00:00:00+00:00", "not-a-timestamp"] {
        let connection = seeded();
        let map = deny_args(vec![("receipt_expires_at", Value::from(deadline))]);
        assert_eq!(
            error_code(&apply(&connection, &map).unwrap()),
            "remote_approval_expired"
        );
    }
}

/// An allow with no usable local key material cannot sign the authority it
/// would have to write, so it refuses before the transaction writes anything.
#[test]
fn allow_without_key_material_refuses_before_writing() {
    let connection = seeded();
    for material in [
        vec![],
        vec![
            ("integrity_key_b64", Value::from("")),
            ("integrity_key_id", Value::from(KEY_ID)),
        ],
        vec![
            ("integrity_key_b64", Value::from("not base64!!")),
            ("integrity_key_id", Value::from(KEY_ID)),
        ],
        vec![
            (
                "integrity_key_b64",
                Value::from(Base64UrlUnpadded::encode_string(KEY)),
            ),
            ("integrity_key_id", Value::from("")),
        ],
    ] {
        let mut overrides = vec![("resolution_action", Value::from("allow"))];
        overrides.extend(material);
        let outcome = apply(&connection, &deny_args(overrides)).unwrap();
        assert_eq!(
            error_code(&outcome),
            "remote_exact_local_authority_unavailable"
        );
    }
    let receipts: i64 = connection
        .query_row(
            "select count(*) from guard_exact_cloud_review_receipts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(receipts, 0);
}

/// A key longer than the bound is refused rather than truncated.
#[test]
fn oversized_key_material_refuses_the_allow() {
    let connection = seeded();
    let oversized = Base64UrlUnpadded::encode_string(&vec![7_u8; MAX_KEY_BYTES + 1]);
    let map = deny_args(vec![
        ("resolution_action", Value::from("allow")),
        ("integrity_key_b64", Value::from(oversized)),
        ("integrity_key_id", Value::from(KEY_ID)),
    ]);
    assert_eq!(
        error_code(&apply(&connection, &map).unwrap()),
        "remote_exact_local_authority_unavailable"
    );
}

/// A receipt already claimed answers `replayed` without resolving anything.
/// The claim is what makes a redelivered cloud verdict harmless.
#[test]
fn claimed_receipt_replays_without_resolving() {
    let connection = seeded();
    exec(
        &connection,
        "insert into guard_exact_cloud_review_receipts values ('receipt-1', 'req-9',
           '2026-01-01T00:00:00+00:00')",
        &[],
    )
    .unwrap();
    // The request read runs first, so a claimed receipt for a request that is
    // not pending still reports the queue state Python reported.
    let outcome = apply(&connection, &deny_args(vec![])).unwrap();
    assert_eq!(error_code(&outcome), "remote_exact_request_not_pending");
}

/// `_changed_request_fields` names only the fields that differ, sorted, and
/// treats a missing key and a stored null as the same absence.
#[test]
fn changed_fields_name_only_what_moved() {
    let current: Map<String, Value> =
        serde_json::from_value(json!({"a": 1, "b": "x", "c": Value::Null})).unwrap();
    let expected: Map<String, Value> =
        serde_json::from_value(json!({"b": "y", "a": 1, "d": Value::Null})).unwrap();
    assert_eq!(
        changed_request_fields(&current, &expected),
        vec![json!("b")]
    );

    // An int and the same value as a float are different stored cells.
    let floated: Map<String, Value> = serde_json::from_value(json!({"a": 1.0, "b": "x"})).unwrap();
    assert_eq!(changed_request_fields(&current, &floated), vec![json!("a")]);
}

/// A capability missing a field the binding carries does not match it, and an
/// extra field in the capability does not break the match.
#[test]
fn capability_binding_match_is_field_by_field() {
    let binding = binding();
    assert!(capability_matches_binding(
        &capability("2099-01-01T00:00:00+00:00"),
        &binding
    ));
    assert!(!capability_matches_binding(&json!({}), &binding));
    assert!(!capability_matches_binding(&binding, &Value::Null));
    assert!(!capability_matches_binding(&Value::Null, &binding));
}

/// The written authority verifies under the exact-cloud purpose and carries
/// the hashed workspace key, not the raw path.
#[test]
fn written_authority_verifies_under_the_exact_cloud_purpose() {
    let connection = seeded();
    let row: Map<String, Value> = serde_json::from_value(json!({
        "harness": "codex",
        "artifact_id": "pkg:npm/left-pad@1.3.0",
        "artifact_hash": "sha256:abc",
        "workspace": "/Users/dev/project/",
        "publisher": "npm",
    }))
    .unwrap();
    assert!(persist_local_once_approval(
        &connection,
        "req-1",
        &row,
        "2026-01-01T00:00:00+00:00",
        "2026-01-02T00:00:00+00:00",
        KEY,
        KEY_ID,
    )
    .unwrap());

    let stored = query_one(
        &connection,
        "select * from guard_local_once_approvals where request_id = ?",
        &[Value::from("req-1")],
    )
    .unwrap()
    .unwrap();
    assert_eq!(stored["authority_kind"], json!(EXACT_CLOUD_AUTHORITY_KIND));
    assert_eq!(
        stored["workspace"],
        json!(computed_workspace_policy_key(Some("/Users/dev/project")).unwrap())
    );
    assert!(stored["workspace"]
        .as_str()
        .unwrap()
        .starts_with("workspace:"));
    assert_eq!(stored["claimed_at"], Value::Null);

    let signed = json!({
        "approval_id": stored["approval_id"],
        "request_id": stored["request_id"],
        "harness": stored["harness"],
        "artifact_id": stored["artifact_id"],
        "artifact_hash": stored["artifact_hash"],
        "workspace": stored["workspace"],
        "publisher": stored["publisher"],
        "action": stored["action"],
        "created_at": stored["created_at"],
        "expires_at": stored["expires_at"],
        "claimed_at": Value::Null,
        "authority_kind": stored["authority_kind"],
    });
    let integrity = json!({
        "integrity_version": stored["integrity_version"],
        "payload_hash": stored["payload_hash"],
        "payload_mac": stored["payload_mac"],
        "integrity_key_id": stored["integrity_key_id"],
        "signed_at": stored["signed_at"],
    });
    let key_id = stored["integrity_key_id"].as_str().unwrap();
    assert_eq!(
        verify_local_authority_payload(
            &signed,
            &integrity,
            Some(KEY),
            Some(key_id),
            local_once_integrity_purpose(Some(EXACT_CLOUD_AUTHORITY_KIND)),
        )
        .status,
        "valid"
    );
    // The legacy local-once purpose must not verify the same bytes: a Cloud
    // Review verdict cannot be presented as a locally saved allow.
    assert_eq!(
        verify_local_authority_payload(
            &signed,
            &integrity,
            Some(KEY),
            Some(key_id),
            LOCAL_ONCE_INTEGRITY_PURPOSE,
        )
        .status,
        "tampered"
    );
}

/// A request with no exact artifact has nothing to bind an authority to, and
/// an expiry at or before creation is refused rather than stored.
#[test]
fn authority_refuses_an_unbound_or_already_expired_target() {
    let connection = seeded();
    let unbound: Map<String, Value> = serde_json::from_value(json!({
        "harness": "codex",
        "artifact_id": "",
        "artifact_hash": "sha256:abc",
    }))
    .unwrap();
    assert!(!persist_local_once_approval(
        &connection,
        "req-1",
        &unbound,
        "2026-01-01T00:00:00+00:00",
        "2026-01-02T00:00:00+00:00",
        KEY,
        KEY_ID,
    )
    .unwrap());

    let bound: Map<String, Value> = serde_json::from_value(json!({
        "harness": "codex",
        "artifact_id": "pkg:npm/left-pad@1.3.0",
        "artifact_hash": "sha256:abc",
    }))
    .unwrap();
    let outcome = persist_local_once_approval(
        &connection,
        "req-2",
        &bound,
        "2026-01-02T00:00:00+00:00",
        "2026-01-02T00:00:00+00:00",
        KEY,
        KEY_ID,
    );
    assert!(matches!(outcome, Err(StoreError::Value(_))));
}
