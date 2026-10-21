use super::*;
use std::fs;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Start a child that waits on stdin, so the test controls when it exits.
fn stdin_bound_child() -> std::process::Child {
    #[cfg(windows)]
    let mut command = Command::new("findstr.exe");
    #[cfg(windows)]
    command.arg("x");
    #[cfg(not(windows))]
    let mut command = Command::new("cat");
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("disposable child should start")
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
    crate::resident_state::ensure_private_directory(&scope, true)
        .expect("test directory should be created");
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

    // Bind generation 2 to a real child, then let that child exit the way a
    // killed resident does: without a shutdown request.
    let mut child = stdin_bound_child();
    exited.process_id = child.id();
    exited.process_start_marker = process_start_marker(child.id()).unwrap();
    exited.state_mac = crate::resident_state::state_mac(&exited, &token);
    drop(child.stdin.take());
    child.wait().expect("child should exit");
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
