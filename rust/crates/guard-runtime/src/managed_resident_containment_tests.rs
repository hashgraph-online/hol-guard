use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn abort_reaps_child_and_reports_state_discovery_failure_after_deadline() {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-abort-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).expect("test directory should be created");
    let invalid_scope = root.join("not-a-directory");
    fs::write(&invalid_scope, b"invalid scope").expect("fixture should be written");
    for (scope, expected) in [
        (&root, Ok(())),
        (
            &invalid_scope,
            Err("native_resident_spawn_containment_failed".to_owned()),
        ),
    ] {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("disposable child should start");
        let result = abort_spawned_managed(
            &mut child,
            scope,
            &"0".repeat(64),
            1,
            &[0; crate::AUTH_TOKEN_BYTES],
            Instant::now(),
        );
        assert!(child.try_wait().unwrap().is_some(), "child must be reaped");
        assert_eq!(result, expected);
    }
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn stop_retires_only_generations_whose_resident_exited() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-managed-exited-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&scope).expect("test directory should be created");
    let digest = runtime_digest().unwrap();
    let token = [7u8; crate::AUTH_TOKEN_BYTES];
    let publish = |generation| {
        crate::resident_state::publish_state(
            &scope,
            generation,
            std::process::id(),
            &digest,
            "loopback",
            "127.0.0.1:1".to_owned(),
            &token,
        )
        .unwrap()
    };
    publish(1);
    let mut exited = publish(2);
    // A different start marker is how a killed resident's reused PID looks.
    exited.process_start_marker = "exited-resident-start-marker".to_owned();
    exited.state_mac = crate::resident_state::state_mac(&exited, &token);
    fs::write(
        scope.join("generation-00000000000000000002.json"),
        serde_json::to_vec(&exited).unwrap(),
    )
    .unwrap();
    assert_eq!(discover_states(&scope, &digest).unwrap().len(), 2);

    retire_exited_states(&scope, &digest).unwrap();

    let remaining = discover_states(&scope, &digest).unwrap();
    assert_eq!(
        remaining
            .iter()
            .map(|state| state.generation)
            .collect::<Vec<_>>(),
        [1]
    );
    fs::remove_dir_all(scope).expect("test directory should be removable");
}
