#[cfg(unix)]
use super::*;

#[cfg(unix)]
#[test]
fn stop_retires_generation_after_publisher_exits() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const CHILD_ENV: &str = "HOL_GUARD_DEAD_RESIDENT_CHILD";
    if let Ok(root) = std::env::var(CHILD_ENV) {
        let root = std::path::PathBuf::from(root);
        let digest = runtime_digest().unwrap();
        let scope = state_scope(&root, &digest).unwrap();
        crate::resident_state::publish_state(
            &scope,
            1,
            std::process::id(),
            &digest,
            "loopback",
            "127.0.0.1:9".to_owned(),
            &[7u8; crate::AUTH_TOKEN_BYTES],
        )
        .unwrap();
        fs::write(root.join("child-ready"), []).unwrap();
        return;
    }

    let root = std::env::temp_dir().join(format!(
        "hol-guard-dead-resident-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let test_name =
        "managed_resident::dead_generation_tests::stop_retires_generation_after_publisher_exits";
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env(CHILD_ENV, &root)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    for _ in 0..6_000 {
        if root.join("child-ready").is_file() || child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let ready = root.join("child-ready").is_file();
    let status = child.wait().unwrap();
    if !ready || !status.success() {
        let _ = fs::remove_dir_all(&root);
        panic!("publisher child did not leave a generation file: ready={ready} status={status}");
    }
    let stopped = stop_managed(&root, false);
    let digest = runtime_digest().unwrap();
    let scope = state_scope(&root, &digest).unwrap();
    let remaining = fs::read_dir(&scope).unwrap().any(|entry| {
        entry.ok().is_some_and(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("generation-")
        })
    });
    let again = stop_managed(&root, false);
    let _ = fs::remove_dir_all(&root);
    assert_eq!(stopped, Ok(()));
    assert!(!remaining, "generation file should be removed");
    assert_eq!(again, Err("native_resident_stop_unavailable".to_owned()));
}
