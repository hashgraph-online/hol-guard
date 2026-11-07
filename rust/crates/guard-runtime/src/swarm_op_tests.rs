use super::*;
use serde_json::{json, Value};
use std::io::Write;

#[test]
fn swarm_routes_reject_approval_links_repair_tokens_and_wrong_verbs() {
    for (method, path) in [
        ("GET", "/v1/swarm"),
        ("POST", "/v1/swarm/launch"),
        ("POST", "/v1/swarm/action"),
        ("POST", "/v1/swarm/events"),
    ] {
        assert!(crate::daemon_route_paths::requires_header_token(path));
        assert!(crate::daemon_route_paths::session_path(method, path));
        assert!(!crate::daemon_route_paths::protection_repair_session_allowed(method, path));
        for (claims, allowed) in [
            (json!({"surface":"dashboard"}), true),
            (
                json!({"surface":"approval-center", "request_id":"request-1"}),
                false,
            ),
            (json!({"surface":"protection-repair"}), false),
        ] {
            let frame = json!({"operation":"daemon_route", "request":{"schema":"guard-daemon-route-request.v1", "request_id":"route-swarm",
                "query":{"kind":"session_authorize", "method":method, "path":path, "claims":claims, "payload":null}}});
            let output: Value = serde_json::from_slice(
                &crate::resident_protocol::evaluate_resident_bytes(
                    frame.to_string().as_bytes(),
                    None,
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                output["payload"]["allowed"], allowed,
                "{method} {path} {claims}"
            );
        }
    }
    assert!(!crate::daemon_route_paths::session_path(
        "GET",
        "/v1/swarm/launch"
    ));
    assert!(!crate::daemon_route_paths::session_path(
        "POST",
        "/v1/swarm"
    ));
}

#[test]
fn swarm_needs_the_scoped_resident_and_binds_each_reply() {
    let temp = tempfile::tempdir().unwrap();
    let home =
        crate::resident_state::ensure_private_directory(&temp.path().join("home"), true).unwrap();
    crate::resident_state::private_file(&home.join("policy-verifier.key"), true, &home)
        .unwrap()
        .write_all(&[31u8; 32])
        .unwrap();
    let store = PolicySnapshotStore::new(&home, &"a".repeat(64)).unwrap();
    let frame = json!({"operation":"swarm", "request":{"schema":"guard-swarm-request.v1", "request_id":"snapshot-1",
        "query":{"guard_home":home,"input":{"action":"snapshot"}}}});
    assert_eq!(
        crate::resident_protocol::evaluate_resident_bytes(frame.to_string().as_bytes(), None)
            .unwrap_err(),
        "native_swarm_resident_required"
    );
    let answer: Value = serde_json::from_slice(
        &crate::resident_protocol::evaluate_resident_bytes(
            frame.to_string().as_bytes(),
            Some(&store),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(answer["status"], "ok");
    assert_eq!(answer["request_id"], "snapshot-1");
    assert!(answer["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(
        answer["payload"]["snapshot"]["schema"],
        "guard-swarm-snapshot.v1"
    );
    let mut foreign = frame.clone();
    foreign["request"]["query"]["guard_home"] = json!(temp.path().join("foreign"));
    assert_eq!(
        crate::resident_protocol::evaluate_resident_bytes(
            foreign.to_string().as_bytes(),
            Some(&store)
        )
        .unwrap_err(),
        "native_guard_home_mismatch"
    );
    let mut bad = frame;
    bad["request"]["query"]["input"]["executable"] = json!("/bin/sh");
    assert!(crate::resident_protocol::evaluate_resident_bytes(
        bad.to_string().as_bytes(),
        Some(&store)
    )
    .is_err());
}
