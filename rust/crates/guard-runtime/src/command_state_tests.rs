use super::*;
use std::path::Path;

use crate::local_store_read::STORE_FILE_NAME;
use base64ct::{Base64UrlUnpadded, Encoding};

const KEY: &[u8] = b"command-state-test-key";
const KEY_ID: &str = "key-1";
const NOW: &str = "2026-09-27T12:00:00+00:00";
const LATER: &str = "2026-09-27T12:30:00+00:00";
const EXPIRES: &str = "2026-09-27T13:00:00+00:00";

pub(super) fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    Connection::open(home.path().join(STORE_FILE_NAME))
        .unwrap()
        .execute_batch(
            "create table sync_state (state_key text primary key, \
             payload_json text not null, updated_at text not null);",
        )
        .unwrap();
    home
}

fn identity(id: &str) -> Map<String, Value> {
    json!({
        "id": id,
        "operation": "guard.example",
        "schemaVersion": 1,
        "deviceId": "device-1",
        "workspaceId": "workspace-1",
        "nonce": "nonce-1",
        "expiresAt": EXPIRES,
        "idempotencyKey": format!("idem-{id}"),
        "payloadDigest": "sha256:payload",
    })
    .as_object()
    .unwrap()
    .clone()
}

pub(super) fn call(home: &Path, op: &str, now: &str, fields: Value) -> Result<Value, String> {
    let mut request = json!({
        "schema": SCHEMA,
        "guard_home": home,
        "op": op,
        "now": now,
    });
    let object = request.as_object_mut().unwrap();
    for (key, value) in fields.as_object().unwrap() {
        object.insert(key.clone(), value.clone());
    }
    handle(&serde_json::from_value(request).unwrap())
}

fn keyed(mut fields: Value) -> Value {
    let object = fields.as_object_mut().unwrap();
    object.insert(
        "integrity_key_b64".to_owned(),
        Value::from(Base64UrlUnpadded::encode_string(KEY)),
    );
    object.insert("integrity_key_id".to_owned(), Value::from(KEY_ID));
    fields
}

fn register(home: &Path, id: &str) -> Value {
    call(
        home,
        "register_pending",
        NOW,
        json!({"identity": identity(id), "issuer": "Guard Cloud", "approve_command": format!("approve {id}")}),
    )
    .unwrap()
}

fn items(home: &Path, key: &str) -> Vec<Map<String, Value>> {
    let conn = Connection::open(home.join(STORE_FILE_NAME)).unwrap();
    state_items(&conn, key).unwrap()
}

#[test]
fn a_registered_job_is_pending_until_it_expires() {
    let home = home();
    let item = register(home.path(), "job-1");
    assert_eq!(item["issuer"], json!("Guard Cloud"));
    assert_eq!(item["recordedAt"], json!(NOW));
    assert_eq!(item["approveCommand"], json!("approve job-1"));
    let listed = call(home.path(), "pending", NOW, json!({})).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let expired = call(
        home.path(),
        "pending",
        "2026-09-27T14:00:00+00:00",
        json!({}),
    )
    .unwrap();
    assert_eq!(expired, json!([]));
}

#[test]
fn registering_a_job_again_replaces_its_row() {
    let home = home();
    register(home.path(), "job-1");
    register(home.path(), "job-2");
    register(home.path(), "job-1");
    let ids: Vec<Value> = items(home.path(), PENDING_KEY)
        .iter()
        .map(|item| item["id"].clone())
        .collect();
    assert_eq!(ids, vec![json!("job-2"), json!("job-1")]);
}

#[test]
fn pending_rows_keep_the_newest_sixty_four() {
    let home = home();
    for index in 0..70 {
        register(home.path(), &format!("job-{index}"));
    }
    let rows = items(home.path(), PENDING_KEY);
    assert_eq!(rows.len(), APPROVALS_MAX_ITEMS);
    assert_eq!(rows[0]["id"], json!("job-6"));
}

#[test]
fn an_approved_job_is_consumed_once() {
    let home = home();
    register(home.path(), "job-1");
    let approved = call(
        home.path(),
        "approve",
        LATER,
        keyed(json!({"job_id": "job-1", "issuer": "local-cli"})),
    )
    .unwrap();
    assert_eq!(
        approved,
        json!({"approved": true, "job_id": "job-1", "operation": "guard.example", "issuer": "local-cli"})
    );
    let grants = items(home.path(), LOCAL_APPROVALS_KEY);
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["keyId"], json!(KEY_ID));
    assert_eq!(grants[0]["approvedAt"], json!(LATER));

    let consume = keyed(json!({"identity": identity("job-1")}));
    assert_eq!(
        call(home.path(), "consume", LATER, consume.clone()),
        Ok(json!(true))
    );
    assert!(items(home.path(), LOCAL_APPROVALS_KEY).is_empty());
    assert!(items(home.path(), PENDING_KEY).is_empty());
    assert_eq!(
        call(home.path(), "consume", LATER, consume),
        Ok(json!(false))
    );
}

#[test]
fn consuming_a_grant_records_its_replay_row_in_the_same_transaction() {
    let home = home();
    register(home.path(), "job-1");
    call(
        home.path(),
        "approve",
        LATER,
        keyed(json!({"job_id": "job-1", "issuer": "local-cli"})),
    )
    .unwrap();

    // A replay row that cannot be written leaves the grant in place.
    let incomplete = keyed(json!({"identity": identity("job-1"), "record_replay": true}));
    assert_eq!(
        call(home.path(), "consume", LATER, incomplete),
        Err(INVALID.to_owned())
    );
    assert_eq!(items(home.path(), LOCAL_APPROVALS_KEY).len(), 1);
    assert!(items(home.path(), REPLAY_KEY).is_empty());

    let consume = keyed(json!({
        "identity": identity("job-1"),
        "operation": "guard.example",
        "record_replay": true,
    }));
    assert_eq!(
        call(home.path(), "consume", LATER, consume),
        Ok(json!(true))
    );
    assert!(items(home.path(), LOCAL_APPROVALS_KEY).is_empty());
    let replay = items(home.path(), REPLAY_KEY);
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0]["jobId"], json!("job-1"));
    assert_eq!(replay[0]["consumedAt"], json!(LATER));
}

#[test]
fn approving_an_unknown_or_expired_job_is_refused() {
    let home = home();
    let approve = keyed(json!({"job_id": "job-1", "issuer": "local-cli"}));
    assert_eq!(
        call(home.path(), "approve", NOW, approve.clone()),
        Err("pending_command_not_found".to_owned())
    );
    register(home.path(), "job-1");
    assert_eq!(
        call(home.path(), "approve", "2026-09-27T14:00:00+00:00", approve),
        Err("pending_command_not_found".to_owned())
    );
}

#[test]
fn approving_without_a_key_is_refused_and_writes_nothing() {
    let home = home();
    register(home.path(), "job-1");
    assert_eq!(
        call(
            home.path(),
            "approve",
            NOW,
            json!({"job_id": "job-1", "issuer": "local-cli"})
        ),
        Err("local_signing_key_unavailable".to_owned())
    );
    assert!(items(home.path(), LOCAL_APPROVALS_KEY).is_empty());
}

#[test]
fn a_grant_for_another_identity_or_key_is_not_spent() {
    let home = home();
    register(home.path(), "job-1");
    call(
        home.path(),
        "approve",
        NOW,
        keyed(json!({"job_id": "job-1", "issuer": "local-cli"})),
    )
    .unwrap();
    let mut changed = identity("job-1");
    changed.insert("nonce".to_owned(), json!("nonce-2"));
    assert_eq!(
        call(
            home.path(),
            "consume",
            NOW,
            keyed(json!({"identity": changed}))
        ),
        Ok(json!(false))
    );
    let wrong_key = json!({
        "identity": identity("job-1"),
        "integrity_key_b64": Base64UrlUnpadded::encode_string(b"another-key"),
        "integrity_key_id": KEY_ID,
    });
    assert_eq!(
        call(home.path(), "consume", NOW, wrong_key),
        Ok(json!(false))
    );
    assert_eq!(items(home.path(), LOCAL_APPROVALS_KEY).len(), 1);
}

#[test]
fn a_tampered_grant_is_not_spent() {
    let home = home();
    register(home.path(), "job-1");
    call(
        home.path(),
        "approve",
        NOW,
        keyed(json!({"job_id": "job-1", "issuer": "local-cli"})),
    )
    .unwrap();
    let mut grants = items(home.path(), LOCAL_APPROVALS_KEY);
    grants[0].insert("issuer".to_owned(), json!("someone-else"));
    let conn = Connection::open(home.path().join(STORE_FILE_NAME)).unwrap();
    save_items(&conn, LOCAL_APPROVALS_KEY, grants, None, NOW).unwrap();
    assert_eq!(
        call(
            home.path(),
            "consume",
            NOW,
            keyed(json!({"identity": identity("job-1")}))
        ),
        Ok(json!(false))
    );
}

#[test]
fn a_claimed_digest_must_match_the_identity() {
    let home = home();
    let fields = json!({"identity": identity("job-1"), "identity_digest": "sha256:other", "operation": "guard.example"});
    assert_eq!(
        call(home.path(), "mark_consumed", NOW, fields),
        Err("command_identity_digest_mismatch".to_owned())
    );
    let digest = envelope_digest(&Value::Object(identity("job-1"))).unwrap();
    let fields = json!({"identity": identity("job-1"), "identity_digest": digest, "operation": "guard.example"});
    assert_eq!(
        call(home.path(), "mark_consumed", NOW, fields),
        Ok(Value::Null)
    );
}

#[test]
fn a_replay_row_names_the_job_and_expired_rows_are_dropped() {
    let home = home();
    let mut stale = identity("job-0");
    stale.insert("expiresAt".to_owned(), json!("2026-09-27T12:10:00+00:00"));
    call(
        home.path(),
        "mark_consumed",
        NOW,
        json!({"identity": stale, "operation": "guard.example"}),
    )
    .unwrap();
    call(
        home.path(),
        "mark_consumed",
        LATER,
        json!({"identity": identity("job-1"), "operation": "guard.example"}),
    )
    .unwrap();
    let rows = items(home.path(), REPLAY_KEY);
    assert_eq!(rows.len(), 1);
    let digest = envelope_digest(&Value::Object(identity("job-1"))).unwrap();
    assert_eq!(
        Value::Object(rows[0].clone()),
        json!({
            "identityDigest": digest,
            "jobId": "job-1",
            "idempotencyKey": "idem-job-1",
            "operation": "guard.example",
            "expiresAt": EXPIRES,
            "consumedAt": LATER,
        })
    );
}

#[test]
fn replay_rows_keep_the_newest_five_hundred_twelve() {
    let home = home();
    for index in 0..515 {
        call(
            home.path(),
            "mark_consumed",
            NOW,
            json!({"identity": identity(&format!("job-{index}")), "operation": "guard.example"}),
        )
        .unwrap();
    }
    let rows = items(home.path(), REPLAY_KEY);
    assert_eq!(rows.len(), REPLAY_MAX_ITEMS);
    assert_eq!(rows[0]["jobId"], json!("job-3"));
}

#[test]
fn unreadable_rows_are_an_error_not_an_empty_ledger() {
    let home = home();
    Connection::open(home.path().join(STORE_FILE_NAME))
        .unwrap()
        .execute(
            "INSERT INTO sync_state VALUES (?1, 'not json', ?2)",
            [PENDING_KEY, NOW],
        )
        .unwrap();
    assert_eq!(
        call(home.path(), "pending", NOW, json!({})),
        Err(UNREADABLE.to_owned())
    );
}

#[test]
fn a_missing_store_has_nothing_pending_and_refuses_writes() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(call(home.path(), "pending", NOW, json!({})), Ok(json!([])));
    assert_eq!(
        call(home.path(), "mark_consumed", NOW, json!({})),
        Err(UNAVAILABLE.to_owned())
    );
    assert!(!home.path().join(STORE_FILE_NAME).exists());
}

#[test]
fn bad_requests_are_refused() {
    let home = home();
    assert_eq!(
        call(home.path(), "pending", "not a time", json!({})),
        Err("invalid_current_time".to_owned())
    );
    assert_eq!(
        call(home.path(), "rewrite", NOW, json!({})),
        Err(INVALID.to_owned())
    );
    assert_eq!(
        call(
            home.path(),
            "register_pending",
            NOW,
            json!({"identity": {"id": ""}, "issuer": "x", "approve_command": "y"})
        ),
        Err(INVALID.to_owned())
    );
    assert_eq!(
        call(
            home.path(),
            "mark_consumed",
            NOW,
            json!({"identity": identity("job-1")})
        ),
        Err(INVALID.to_owned())
    );
    let wrong_schema = json!({"schema": "command-state.v0", "guard_home": home.path(), "op": "pending", "now": NOW});
    assert_eq!(
        handle(&serde_json::from_value(wrong_schema).unwrap()),
        Err(INVALID.to_owned())
    );
}

#[test]
fn the_stdin_command_answers_in_its_envelope() {
    let home = home();
    let request = json!({"schema": SCHEMA, "guard_home": home.path(), "op": "pending", "now": NOW});
    let response: Value =
        serde_json::from_slice(&run_command(request.to_string().as_bytes()).unwrap()).unwrap();
    assert_eq!(response, json!({"ok": true, "result": []}));
    let refused = json!({"schema": SCHEMA, "guard_home": home.path(), "op": "approve", "now": NOW, "job_id": "x", "issuer": "y"});
    let response: Value =
        serde_json::from_slice(&run_command(refused.to_string().as_bytes()).unwrap()).unwrap();
    assert_eq!(
        response,
        json!({"ok": false, "error": "pending_command_not_found"})
    );
    assert_eq!(
        run_command(&b"{\"schema\": 1}"[..]),
        Err(INVALID.to_owned())
    );
    assert!(is_command(COMMAND));
}

#[test]
fn python_equality_matches_integers_and_floats() {
    assert!(py_equal(&json!({"a": [1, 2.0]}), &json!({"a": [1.0, 2]})));
    assert!(!py_equal(&json!({"a": 1}), &json!({"a": 1, "b": 2})));
    assert!(!py_equal(&json!("1"), &json!(1)));
}
