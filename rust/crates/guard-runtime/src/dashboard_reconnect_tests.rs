use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::{dispatch, reconnect_proof, CHALLENGE_TTL_MS, MAX_AUTHORIZATIONS, STORE_FILE};
use crate::runner_authority_op::ERR_INVALID;

const ORIGIN: &str = "http://127.0.0.1:4781";

fn home_with_key(key: &str) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    write_key(home.path(), key);
    home
}

fn write_key(home: &Path, key: &str) {
    let path = home.join("daemon-discovery-key");
    fs::write(&path, key).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn call(home: &Path, args: Value) -> Value {
    dispatch(&args, home.to_str().unwrap()).unwrap()
}

fn prepare(home: &Path, now_ms: i64) -> Map<String, Value> {
    let answer = call(home, json!({"op": "prepare", "now_ms": now_ms}));
    answer["authorization"].as_object().unwrap().clone()
}

fn challenge(home: &Path, reconnect_id: &Value, nonce: &str, now_ms: i64) -> Value {
    call(
        home,
        json!({
            "op": "challenge",
            "reconnect_id": reconnect_id,
            "client_nonce": nonce,
            "candidate_origin": ORIGIN,
            "state_id": "new-state",
            "now_ms": now_ms,
        }),
    )
}

fn without_proof(challenge: &Value) -> Map<String, Value> {
    let mut challenge = challenge.as_object().unwrap().clone();
    challenge.remove("proof");
    challenge
}

fn consume(
    home: &Path,
    challenge: &Map<String, Value>,
    proof: &str,
    state: &str,
    now: i64,
) -> Value {
    call(
        home,
        json!({
            "op": "consume",
            "challenge": challenge,
            "proof": proof,
            "expected_candidate_origin": ORIGIN,
            "expected_state_id": state,
            "now_ms": now,
        }),
    )
}

#[test]
fn proofs_match_the_cross_language_fixture() {
    let challenge = json!({
        "protocol_version": 1,
        "reconnect_id": "11".repeat(32),
        "client_nonce": "66".repeat(32),
        "server_nonce": "55".repeat(32),
        "state_id": "state",
        "candidate_origin": ORIGIN,
        "installation_id": "33".repeat(32),
        "guard_home_id": "44".repeat(32),
        "surface": "dashboard",
        "issued_at_ms": 1_000,
        "expires_at_ms": 2_000,
    });
    let challenge = challenge.as_object().unwrap();
    let verifier = "22".repeat(32);
    assert_eq!(
        reconnect_proof(&verifier, "server", challenge),
        "40dc0312c6c1e1ddcf80f94216b2a18e01a0e77c4233e904012b8491187c3ceb"
    );
    assert_eq!(
        reconnect_proof(&verifier, "client", challenge),
        "1c5d2ef201d59244f432353caefdff67849c4a0fae0fd9201f185f4e4e04240e"
    );
}

#[test]
fn a_prepared_verifier_proves_both_sides_once_per_challenge() {
    let home = home_with_key(&"aa".repeat(32));
    let authorization = prepare(home.path(), 1_000);
    assert_eq!(authorization["protocol_version"], json!(1));
    assert_eq!(authorization["expires_at_ms"], json!(301_000));
    let verifier = authorization["verifier"].as_str().unwrap().to_owned();
    let issued = challenge(
        home.path(),
        &authorization["reconnect_id"],
        &"5A".repeat(32),
        2_000,
    );
    assert_eq!(issued["reason"], "dashboard_reconnect_challenge_issued");
    let payload = &issued["challenge"];
    let challenge = without_proof(payload);
    assert_eq!(challenge["client_nonce"], json!("5a".repeat(32)));
    assert_eq!(challenge["expires_at_ms"], json!(2_000 + CHALLENGE_TTL_MS));
    assert_eq!(
        payload["proof"],
        json!(reconnect_proof(&verifier, "server", &challenge))
    );
    let client = reconnect_proof(&verifier, "client", &challenge);
    let accepted = consume(
        home.path(),
        &challenge,
        &client.to_uppercase(),
        "new-state",
        2_001,
    );
    assert_eq!(
        accepted,
        json!({"verified": true, "reason": "dashboard_reconnect_proof_accepted"})
    );
    let wrong = consume(
        home.path(),
        &challenge,
        &"00".repeat(32),
        "new-state",
        2_001,
    );
    assert_eq!(wrong["reason"], "dashboard_reconnect_proof_invalid");
    let identity = call(
        home.path(),
        json!({"op": "challenge_identity", "challenge": challenge}),
    );
    let mut upper = challenge.clone();
    upper.insert("client_nonce".into(), json!("5A".repeat(32)));
    let variant = call(
        home.path(),
        json!({"op": "challenge_identity", "challenge": upper}),
    );
    assert_eq!(identity["identity"].as_str().map(str::len), Some(64));
    assert_eq!(identity, variant);
}

#[test]
fn expiry_wrong_state_and_previous_installation_are_refused() {
    let home = home_with_key(&"aa".repeat(32));
    let authorization = prepare(home.path(), 1_000);
    let verifier = authorization["verifier"].as_str().unwrap().to_owned();
    let issued = challenge(
        home.path(),
        &authorization["reconnect_id"],
        &"66".repeat(32),
        2_000,
    );
    let challenge_map = without_proof(&issued["challenge"]);
    let client = reconnect_proof(&verifier, "client", &challenge_map);
    let wrong_state = consume(home.path(), &challenge_map, &client, "other-state", 2_001);
    assert_eq!(
        wrong_state["reason"],
        "dashboard_reconnect_proof_context_mismatch"
    );
    let late = 2_000 + CHALLENGE_TTL_MS + 1;
    let expired = consume(home.path(), &challenge_map, &client, "new-state", late);
    assert_eq!(expired["reason"], "dashboard_reconnect_proof_expired");
    let malformed = challenge(
        home.path(),
        &authorization["reconnect_id"],
        "not-a-nonce",
        2_000,
    );
    assert_eq!(
        malformed,
        json!({"challenge": null, "reason": "dashboard_reconnect_malformed_challenge"})
    );
    write_key(home.path(), &"77".repeat(32));
    let replaced = challenge(
        home.path(),
        &authorization["reconnect_id"],
        &"88".repeat(32),
        2_002,
    );
    assert_eq!(
        replaced["reason"],
        "dashboard_reconnect_authorization_unavailable"
    );
    let stale = consume(home.path(), &challenge_map, &client, "new-state", 2_001);
    assert_eq!(
        stale["reason"],
        "dashboard_reconnect_authorization_unavailable"
    );
}

#[test]
fn an_expired_authorization_issues_no_challenge() {
    let home = home_with_key(&"aa".repeat(32));
    let authorization = prepare(home.path(), 1_000);
    let issued = challenge(
        home.path(),
        &authorization["reconnect_id"],
        &"66".repeat(32),
        301_001,
    );
    assert_eq!(
        issued["reason"],
        "dashboard_reconnect_authorization_expired"
    );
    assert_eq!(issued["challenge"], Value::Null);
}

#[test]
fn the_store_is_private_signed_and_keeps_no_verifier() {
    let home = home_with_key(&"aa".repeat(32));
    let authorization = prepare(home.path(), 1_000);
    let path = home.path().join(STORE_FILE);
    let contents = fs::read_to_string(&path).unwrap();
    assert!(!contents.contains(authorization["verifier"].as_str().unwrap()));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::write(&path, contents.replace("dashboard\"", "dashboarD\"")).unwrap();
    let answer = call(home.path(), json!({"op": "prepare", "now_ms": 2_000}));
    assert_eq!(answer, json!({"error": "state_invalid"}));
    fs::remove_file(home.path().join("daemon-discovery-key")).unwrap();
    let answer = call(home.path(), json!({"op": "prepare", "now_ms": 2_000}));
    assert_eq!(answer, json!({"error": "identity_unavailable"}));
}

#[test]
fn prepare_keeps_only_the_newest_live_authorizations() {
    let home = home_with_key(&format!("{}\n", "aa".repeat(32)));
    let first = prepare(home.path(), 1_000);
    for offset in 0..MAX_AUTHORIZATIONS as i64 {
        prepare(home.path(), 2_000 + offset);
    }
    let contents = fs::read_to_string(home.path().join(STORE_FILE)).unwrap();
    let stored: Value = serde_json::from_str(&contents).unwrap();
    let records = stored["records"].as_array().unwrap();
    assert_eq!(records.len(), MAX_AUTHORIZATIONS);
    assert!(!contents.contains(first["reconnect_id"].as_str().unwrap()));
    prepare(home.path(), 400_000);
    let contents = fs::read_to_string(home.path().join(STORE_FILE)).unwrap();
    let stored: Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(stored["records"].as_array().unwrap().len(), 1);
}

#[test]
fn invalid_requests_are_refused() {
    let home = home_with_key(&"aa".repeat(32));
    let home_text = home.path().to_str().unwrap();
    assert_eq!(
        dispatch(&json!({"op": "prepare"}), "relative"),
        Err(ERR_INVALID)
    );
    assert_eq!(
        dispatch(&json!({"op": "other"}), home_text),
        Err(ERR_INVALID)
    );
    assert_eq!(
        dispatch(&json!({"op": "prepare", "now_ms": "1"}), home_text),
        Err(ERR_INVALID)
    );
    let unknown = call(
        home.path(),
        json!({"op": "challenge_identity", "challenge": {}}),
    );
    assert_eq!(unknown, json!({"identity": null}));
}
