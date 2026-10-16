//! Authentication of the signed daemon state and of the daemon's answer to
//! the identity challenge.

use std::os::unix::fs::PermissionsExt;

use serde_json::json;

use super::*;
use crate::claude_hook_bridge_fixture::{challenge_answer, sign, write_private, GuardHome};

fn signed_home(label: &str) -> (GuardHome, AuthenticatedState) {
    let home = GuardHome::new(label);
    home.write_state(&home.state(4100));
    let state = authenticated_state(&home.state_path).expect("authenticated state");
    (home, state)
}

#[test]
fn fromhex_allows_whitespace_only_between_pairs() {
    assert_eq!(py_fromhex("00 ff\n10"), Some(vec![0x00, 0xff, 0x10]));
    assert_eq!(py_fromhex("0 0"), None);
    assert_eq!(py_fromhex("abc"), None);
    assert_eq!(py_fromhex(""), Some(Vec::new()));
}

#[test]
fn json_values_compare_as_python_does() {
    assert_eq!(json_int(Some(&json!(7))), Some(7));
    assert_eq!(json_int(Some(&json!(7.0))), None);
    assert_eq!(json_int(Some(&json!(true))), None);
    assert!(py_eq(Some(&json!(1)), Some(&json!(true))));
    assert!(py_eq(Some(&json!(2)), Some(&json!(2.0))));
    assert!(py_eq(None, Some(&Value::Null)));
    assert!(!py_eq(Some(&json!("1")), Some(&json!(1))));
}

#[test]
fn signed_state_authenticates() {
    let (home, state) = signed_home("auth-valid");
    assert_eq!(state.port(), 4100);
    assert_eq!(state.text("guard_home"), home.home_text());
    let again = authenticated_state(&home.state_path).unwrap();
    assert!(state.same_generation(&again));
}

#[test]
fn tampered_or_stopped_state_is_refused() {
    let home = GuardHome::new("auth-tampered");
    let mut state = home.state(4100);
    let mut signed = state.clone();
    signed.insert("state_signature".to_owned(), json!(sign(&state)));
    signed.insert("port".to_owned(), json!(4101));
    write_private(&home.state_path, &Value::Object(signed).to_string());
    assert_eq!(
        authenticated_state(&home.state_path).unwrap_err(),
        "daemon state authentication failed"
    );
    write_private(&home.state_path, "{}");
    assert_eq!(
        authenticated_state(&home.state_path).unwrap_err(),
        "daemon state records a stopped daemon"
    );
    state.insert("guard_home".to_owned(), json!("/elsewhere"));
    home.write_state(&state);
    assert_eq!(
        authenticated_state(&home.state_path).unwrap_err(),
        "daemon state belongs to a different Guard home"
    );
}

#[test]
fn shared_state_file_is_refused() {
    let (home, _) = signed_home("auth-shared");
    fs::set_permissions(&home.state_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        authenticated_state(&home.state_path).unwrap_err(),
        "daemon state permissions are not owner-only"
    );
}

#[test]
fn missing_home_is_unavailable() {
    let home = GuardHome::new("auth-missing");
    fs::remove_file(home.home.join("daemon-discovery-key")).unwrap();
    assert_eq!(
        authenticated_state(&home.state_path).unwrap_err(),
        "daemon state is unavailable"
    );
}

#[test]
fn challenge_answer_must_match_and_be_signed() {
    let (_home, state) = signed_home("auth-challenge");
    let answer = challenge_answer(&state.payload, "nonce-1", "PreToolUse");
    assert_eq!(
        verify_challenge_response(&answer, &state, "nonce-1", "PreToolUse"),
        Ok(answer["proof"].as_str().unwrap().to_owned())
    );
    assert_eq!(
        verify_challenge_response(&answer, &state, "nonce-2", "PreToolUse"),
        Err(CHALLENGE_MISMATCH.to_owned())
    );
    assert_eq!(
        verify_challenge_response(&answer, &state, "nonce-1", "Stop"),
        Err(CHALLENGE_MISMATCH.to_owned())
    );
    let mut forged = answer.clone();
    forged.insert("proof".to_owned(), json!("00".repeat(32)));
    assert_eq!(
        verify_challenge_response(&forged, &state, "nonce-1", "PreToolUse"),
        Err(CHALLENGE_AUTHENTICATION_FAILED.to_owned())
    );
    let mut stale = answer.clone();
    stale.remove("proof");
    stale.insert("issued_at_ms".to_owned(), json!(1_000));
    stale.insert("expires_at_ms".to_owned(), json!(6_000));
    let proof = sign(&stale);
    stale.insert("proof".to_owned(), json!(proof));
    assert_eq!(
        verify_challenge_response(&stale, &state, "nonce-1", "PreToolUse"),
        Err(CHALLENGE_EXPIRED.to_owned())
    );
}
