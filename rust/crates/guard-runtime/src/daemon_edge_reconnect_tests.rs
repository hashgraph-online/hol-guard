use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde_json::json;

use super::*;
use crate::daemon_edge::standalone::{publish, LaunchConfig};
use crate::daemon_policy_authority::{canonical_discovery_payload, hmac_sha256_raw};

const PORT: u16 = 4791;

fn private_home() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("reconnect")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// Publishes this process's daemon state and answers its `state_id`.
fn published(home: &Path) -> String {
    let launch = json!({
        "schema": "guard-daemon-serve-launch.v1",
        "guard_home": home.to_str().unwrap(),
        "port": 0,
        "store_path": home.join("guard.db").to_str().unwrap(),
        "source": "daemon",
        "busy_timeout_ms": 5000,
        "cli_command": ["/usr/bin/false"],
        "state": {"compatibility_version": 2, "package_version": "9.9.9"},
    });
    let config = LaunchConfig::parse(&serde_json::to_vec(&launch).unwrap()).unwrap();
    publish(home, &config, PORT, std::process::id()).unwrap();
    let state = crate::daemon_policy_authority::load_authenticated_daemon_state(home).unwrap();
    state["state_id"].as_str().unwrap().to_owned()
}

fn daemon<'a>(home: &'a str, state_id: Option<&'a str>) -> Daemon<'a> {
    Daemon {
        guard_home: home,
        local: SocketAddr::from(([127, 0, 0, 1], PORT)),
        pid: std::process::id(),
        state_id,
    }
}

fn client_proof(verifier: &str, challenge: &Value) -> String {
    let mut payload = challenge.as_object().unwrap().clone();
    payload.remove("proof");
    payload.insert("proof_context".into(), json!("client"));
    let key = hex::decode(verifier).unwrap();
    hex::encode(hmac_sha256_raw(
        &key,
        &canonical_discovery_payload(&payload),
    ))
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[test]
fn the_daemon_issues_and_verifies_a_reconnect_proof_once() {
    let dir = private_home();
    let home = fs::canonicalize(dir.path()).unwrap();
    let state_id = published(&home);
    let home_text = home.to_str().unwrap();
    let daemon = daemon(home_text, Some(&state_id));
    let prepared =
        crate::dashboard_reconnect::dispatch(&json!({"op": "prepare"}), home_text).unwrap();
    let authorization = &prepared["authorization"];
    let request = object(json!({
        "protocol_version": 1,
        "reconnect_id": authorization["reconnect_id"],
        "client_nonce": "ab".repeat(32),
        "candidate_origin": format!("http://127.0.0.1:{PORT}"),
    }));
    let (status, challenge) = challenge(&request, &daemon);
    assert_eq!(status, 200, "{challenge}");
    assert_eq!(challenge["state_id"], json!(state_id));
    let proof = client_proof(authorization["verifier"].as_str().unwrap(), &challenge);
    let verification =
        object(json!({"protocol_version": 1, "challenge": challenge, "proof": proof}));
    assert_eq!(
        verify(&verification, &daemon),
        (
            200,
            json!({"verified": true, "reason_code": "dashboard_reconnect_proof_accepted"})
        )
    );
    assert_eq!(
        verify(&verification, &daemon),
        candidate_failure("dashboard_reconnect_proof_replayed")
    );
}

#[test]
fn the_daemon_refuses_a_reconnect_meant_for_another_daemon() {
    let dir = private_home();
    let home = fs::canonicalize(dir.path()).unwrap();
    let state_id = published(&home);
    let home_text = home.to_str().unwrap();
    let request = |origin: String| {
        object(json!({
            "protocol_version": 1,
            "reconnect_id": "cd".repeat(32),
            "client_nonce": "ab".repeat(32),
            "candidate_origin": origin,
        }))
    };
    let ours = daemon(home_text, Some(&state_id));
    assert_eq!(
        challenge(&request(format!("http://127.0.0.1:{}", PORT + 1)), &ours),
        candidate_failure("dashboard_reconnect_origin_mismatch")
    );
    let mut stale = request(format!("http://127.0.0.1:{PORT}"));
    stale.insert("protocol_version".into(), json!(2));
    assert_eq!(
        challenge(&stale, &ours),
        candidate_failure("dashboard_reconnect_protocol_mismatch")
    );
    let replaced = daemon(home_text, Some("another-state"));
    assert_eq!(
        challenge(&request(format!("http://127.0.0.1:{PORT}")), &replaced),
        candidate_failure("dashboard_reconnect_state_unavailable")
    );
    assert_eq!(
        challenge(&request(format!("http://127.0.0.1:{PORT}")), &ours),
        candidate_failure("dashboard_reconnect_authorization_unavailable")
    );
    assert_eq!(
        verify(
            &object(json!({"protocol_version": 1, "challenge": "x"})),
            &ours
        ),
        candidate_failure("dashboard_reconnect_malformed_proof")
    );
}
