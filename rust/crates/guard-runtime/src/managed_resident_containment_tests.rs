use super::*;
use std::fs;
use zeroize::Zeroizing;

#[test]
fn abort_reaps_unverified_child_without_claiming_group_containment_after_deadline() {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-abort-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir(&root).expect("test directory should be created");
    let invalid_scope = root.join("not-a-directory");
    fs::write(&invalid_scope, b"invalid scope").expect("fixture should be written");
    for scope in [&root, &invalid_scope] {
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
        assert_eq!(
            result,
            Err("native_resident_spawn_containment_failed".to_owned())
        );
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

#[test]
fn a_reaped_child_never_adopts_a_replacement_process_identity() {
    let mut child = std::process::Command::new("/bin/false").spawn().unwrap();
    assert!(!child.wait().unwrap().success());
    // Once reaped, this PID is eligible for reuse, even by this runtime. The
    // cleanup must fail without adopting an identity sampled from that PID.
    // This does not depend on forcing the OS to reuse a particular PID.
    for _ in 0..2 {
        assert_eq!(
            spawned_process_identities(&mut child).unwrap_err(),
            "native_resident_spawn_containment_failed"
        );
    }
}

#[test]
fn unpublished_descendant_cannot_be_declared_contained_after_supervisor_exit() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let root = std::env::temp_dir().join(format!(
        "hol-guard-unpublished-descendant-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir(&root).unwrap();
    for expired in [false, true] {
        // The supervisor exits after spawning a descendant, which announces
        // readiness but publishes no resident state and waits on our pipe.
        // Closing stdin releases it even if a test assertion panics.
        let mut supervisor = Command::new("/bin/sh")
            .args([
                "-c",
                "exec 3<&0; (printf 'ready\n'; read answer <&3; printf 'done\n') &",
            ])
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut release = supervisor.stdin.take().unwrap();
        let mut output = BufReader::new(supervisor.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        assert!(supervisor.wait().unwrap().success());
        assert!(fs::read_dir(&root).unwrap().next().is_none());
        let deadline = if expired {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(2)
        };
        let result = abort_spawned_managed(
            &mut supervisor,
            &root,
            &"0".repeat(64),
            1,
            &[0; crate::AUTH_TOKEN_BYTES],
            deadline,
        );
        // The original PID/group must not be signalled after reaping. Release
        // the unpublished descendant through its owned pipe, not a PID lookup.
        release.write_all(b"release\n").unwrap();
        drop(release);
        line.clear();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "done\n");
        assert_eq!(
            result,
            Err("native_resident_spawn_containment_failed".to_owned())
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn exit_after_live_snapshot_does_not_become_successful_tree_containment() {
    use std::process::{Command, Stdio};

    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    assert_eq!(spawned_process_identities(&mut child).unwrap().len(), 1);
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    assert_eq!(
        terminate_spawned_managed(&mut child, Duration::ZERO),
        Err("native_resident_spawn_containment_failed".to_owned())
    );
}
