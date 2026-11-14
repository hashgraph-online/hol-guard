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
        "query":{"guard_home":home,"cli_path":"/usr/bin:/bin","input":{"action":"snapshot"}}}});
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

#[cfg(unix)]
#[test]
fn resident_drain_stops_swarm_even_when_another_request_retains_the_store() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let temp = tempfile::tempdir().unwrap();
    let home =
        crate::resident_state::ensure_private_directory(&temp.path().join("home"), true).unwrap();
    crate::resident_state::private_file(&home.join("policy-verifier.key"), true, &home)
        .unwrap()
        .write_all(&[31u8; 32])
        .unwrap();
    let executable = temp.path().join("codex");
    fs::write(
        &executable,
        "#!/bin/sh\ncat >/dev/null\nsleep 60 &\nprintf '%s' \"$!\" > child.pid\nwait\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let store = Arc::new(PolicySnapshotStore::new(&home, &"a".repeat(64)).unwrap());
    let cli_path = std::env::join_paths([
        temp.path(),
        std::path::Path::new("/usr/bin"),
        std::path::Path::new("/bin"),
    ])
    .unwrap();
    let send = |input: Value| -> Value {
        let frame = json!({"operation":"swarm", "request":{
            "schema":"guard-swarm-request.v1", "request_id":"drain-test",
            "query":{"guard_home":home, "cli_path":cli_path.to_str().unwrap(), "input":input}
        }});
        serde_json::from_slice(
            &crate::resident_protocol::evaluate_resident_bytes(
                frame.to_string().as_bytes(),
                Some(&store),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let snapshot = send(json!({"action":"snapshot"}));
    let launch = json!({"request_id":"launch-drain", "epoch":snapshot["payload"]["snapshot"]["epoch"],
        "harness":"codex", "workspace":temp.path(), "task":"shutdown fixture", "model":null});
    let reply = send(json!({"action":"launch", "launch":launch}));
    assert_eq!(reply["status"], "ok", "{reply}");
    let id = reply["payload"]["agent"]["id"].as_str().unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    let (root, child) = loop {
        let snapshot = store.swarm().service.snapshot().unwrap();
        let root = snapshot.agents.iter().find(|a| a.id == id).unwrap().pid;
        let child = fs::read_to_string(temp.path().join("child.pid"))
            .ok()
            .and_then(|value| value.parse::<u32>().ok());
        if let (Some(root), Some(child)) = (root, child) {
            break (root, child);
        }
        assert!(Instant::now() < deadline, "fixture did not start");
        std::thread::sleep(Duration::from_millis(20));
    };
    let admission = crate::resident_transport::start_resident_workers(
        Arc::new([0u8; crate::AUTH_TOKEN_BYTES]),
        Some(Arc::clone(&store)),
    );
    // Keep the store alive exactly as a request that outlasts bounded draining
    // would. Cleanup must not depend on the last Arc or Service::drop.
    crate::resident_transport::drain_resident_workers(admission);
    assert!(!store.swarm().has_active_runs());
    assert_eq!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(root as i32), None),
        Err(nix::errno::Errno::ESRCH)
    );
    let mut processes = sysinfo::System::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let pid = sysinfo::Pid::from_u32(child);
        processes.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        if processes.process(pid).is_none_or(|process| {
            matches!(
                process.status(),
                sysinfo::ProcessStatus::Zombie | sysinfo::ProcessStatus::Dead
            )
        }) {
            break;
        }
        assert!(Instant::now() < deadline, "owned descendant survived drain");
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut late = launch;
    late["request_id"] = json!("launch-after-drain");
    let denied = send(json!({"action":"launch", "launch":late}));
    assert_eq!(denied["code"], "swarm_unavailable");
}

/// The dashboard sends `model: null` and `text: null`. Python checks the
/// reply's digest against a digest of what it sent, so the decoded request
/// must hash the same. `tests/test_native_swarm.py` pins the same digests.
#[test]
fn reply_digest_matches_the_request_as_the_dashboard_sent_it() {
    let launch = json!({"action":"launch", "launch":{"request_id":"launch-1", "epoch":"epoch-1",
        "harness":"codex", "workspace":"/tmp", "task":"Review the tests", "model":null}});
    let stop = json!({"action":"direct", "request":{"request_id":"stop-1", "epoch":"epoch-1",
        "run_id":"run-1", "expected_revision":3, "action":"stop", "text":null}});
    let pinned = [(launch, PINNED_LAUNCH_DIGEST), (stop, PINNED_STOP_DIGEST)];
    for (input, pinned) in pinned {
        let raw = json!({"schema":"guard-swarm-request.v1", "request_id":"swarm-1",
            "query":{"guard_home":"/tmp/guard", "cli_path":"/usr/bin", "input":input}});
        let decoded: Request = serde_json::from_value(raw.clone()).unwrap();
        let sent = request_digest_with_limit(&raw, 32_768).unwrap();
        assert_eq!(request_digest_with_limit(&decoded, 32_768).unwrap(), sent);
        assert_eq!(sent, pinned);
    }
}

const PINNED_LAUNCH_DIGEST: &str =
    "sha256:e2f5ebd4b8eadd7f92c5df32b6502fe34a854c96dd704d4b6e0708603f72fa6e";
const PINNED_STOP_DIGEST: &str =
    "sha256:e4f082fc952347382792c109a421bc80432923b9930d0a98fd7ebf93e55b76a8";
