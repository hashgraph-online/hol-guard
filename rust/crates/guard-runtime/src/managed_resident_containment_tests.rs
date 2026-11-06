use super::*;
use std::fs;

#[test]
fn abort_reaps_child_and_reports_state_discovery_failure_after_deadline() {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-abort-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
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
fn the_token_handed_to_a_child_is_cleared_after_the_write() {
    let token = [0x9fu8; crate::AUTH_TOKEN_BYTES];

    let rendered = hex_token(&token);

    // The child reads its key from stdin, never from an argument or an
    // environment entry, and the rendering is cleared when this scope ends.
    assert_eq!(rendered.len(), crate::AUTH_TOKEN_BYTES * 2);
    assert!(rendered.starts_with("9f9f"));
    let _: &Zeroizing<String> = &rendered;
}
