use super::*;
use std::fs;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn labels_keep_the_code_and_drop_paths_and_messages() {
    assert_eq!(
        safe_label("native_response_write_failed"),
        "native_response_write_failed"
    );
    assert_eq!(
        safe_label("daemon-serve: cannot listen: /Users/someone/.hol-guard"),
        "daemon-serve:"
    );
    assert_eq!(safe_label("/private/path"), "unlabelled");
    assert_eq!(safe_label(&"a".repeat(400)).len(), MAX_LABEL_BYTES);
}

#[test]
fn the_failure_home_comes_from_the_command_line_first() {
    let named = arguments(&[
        "daemon-serve",
        "--guard-home",
        "/tmp/named-home",
        "--port",
        "1",
    ]);
    assert_eq!(
        failure_guard_home(&named),
        Some(PathBuf::from("/tmp/named-home"))
    );
    let joined = arguments(&["doctor", "--guard-home=/tmp/joined-home"]);
    assert_eq!(
        failure_guard_home(&joined),
        Some(PathBuf::from("/tmp/joined-home"))
    );
}

#[test]
fn an_installed_runtime_finds_the_home_it_lives_in() {
    let executable = Path::new("/h/.hol-guard/native-runtime/abc123/hol-guard-runtime");
    assert_eq!(
        installed_guard_home(executable),
        Some(PathBuf::from("/h/.hol-guard"))
    );
    let build = Path::new("/w/rust/target/release/hol-guard-runtime");
    assert_eq!(installed_guard_home(build), None);
}

#[test]
fn a_failure_record_holds_labels_and_no_arguments() {
    let record = failure_record(
        "native_request_read_failed: /secret/place",
        "error",
        None,
        &arguments(&["pre-tool", "--stdin", "/Users/someone/private"]),
    )
    .unwrap();
    assert_eq!(record["code"], "native_request_read_failed:");
    assert_eq!(record["kind"], "error");
    assert_eq!(record["subcommand"], "pre-tool");
    assert_eq!(record["pid"], std::process::id());
    assert!(!record.to_string().contains("/Users/someone"));
    assert!(!record.to_string().contains("/secret/place"));
    let hook = failure_record("x", "error", None, &[]).unwrap();
    assert_eq!(hook["subcommand"], "hook");
}

#[test]
fn panic_locations_keep_only_the_file_name() {
    assert_eq!(
        panic_location("/home/builder/rust/crates/guard-runtime/src/lib.rs", 12),
        "lib.rs:12"
    );
    assert_eq!(
        panic_location("src\\daemon_edge_serve.rs", 7),
        "daemon_edge_serve.rs:7"
    );
}

#[test]
fn failures_append_private_lines_and_rotate_at_the_bound() {
    let home = tempfile::tempdir().unwrap();
    let named = arguments(&[
        "daemon-serve",
        "--guard-home",
        home.path().to_str().unwrap(),
    ]);
    record_failure("first_failure", "error", None, &named);
    record_failure("second_failure", "error", None, &named);
    let path = home.path().join(LOG_DIRECTORY).join(FAILURE_LOG);
    let text = fs::read_to_string(&path).unwrap();
    let lines: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["code"], "first_failure");
    assert_eq!(lines[1]["code"], "second_failure");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let directory = fs::metadata(path.parent().unwrap()).unwrap();
        assert_eq!(directory.permissions().mode() & 0o777, 0o700);
    }
    fs::write(&path, vec![b'x'; MAX_FAILURE_LOG_BYTES as usize]).unwrap();
    record_failure("after_rotation", "error", None, &named);
    let rotated = home.path().join(LOG_DIRECTORY).join(ROTATED_FAILURE_LOG);
    assert_eq!(fs::metadata(&rotated).unwrap().len(), MAX_FAILURE_LOG_BYTES);
    let fresh = fs::read_to_string(&path).unwrap();
    assert_eq!(fresh.lines().count(), 1);
    assert!(fresh.contains("after_rotation"));
}

#[test]
fn a_missing_home_records_nothing() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("absent");
    let named = arguments(&["daemon-serve", "--guard-home", missing.to_str().unwrap()]);
    record_failure("nothing", "error", None, &named);
    assert!(!missing.exists());
}

#[cfg(unix)]
#[test]
fn a_symlinked_log_directory_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), home.path().join(LOG_DIRECTORY)).unwrap();
    let named = arguments(&[
        "daemon-serve",
        "--guard-home",
        home.path().to_str().unwrap(),
    ]);
    record_failure("redirected", "error", None, &named);
    assert!(!elsewhere.path().join(FAILURE_LOG).exists());
}

#[test]
fn concurrent_failures_at_the_bound_keep_the_rotated_history() {
    let home = tempfile::tempdir().unwrap();
    let named = arguments(&[
        "daemon-serve",
        "--guard-home",
        home.path().to_str().unwrap(),
    ]);
    record_failure("first_failure", "error", None, &named);
    let path = home.path().join(LOG_DIRECTORY).join(FAILURE_LOG);
    fs::write(&path, vec![b'x'; MAX_FAILURE_LOG_BYTES as usize]).unwrap();
    let launches = 16;
    let barrier = std::sync::Barrier::new(launches);
    std::thread::scope(|scope| {
        for _ in 0..launches {
            scope.spawn(|| {
                barrier.wait();
                record_failure("concurrent_failure", "error", None, &named);
            });
        }
    });
    // One launch moved the full log aside; no other moved the fresh log
    // over it, and no record was lost.
    let rotated = home.path().join(LOG_DIRECTORY).join(ROTATED_FAILURE_LOG);
    assert_eq!(fs::metadata(&rotated).unwrap().len(), MAX_FAILURE_LOG_BYTES);
    let fresh = fs::read_to_string(&path).unwrap();
    assert_eq!(fresh.lines().count(), launches, "{fresh}");
}

#[test]
fn a_held_rotation_lock_still_records_without_rotating() {
    let home = tempfile::tempdir().unwrap();
    let named = arguments(&[
        "daemon-serve",
        "--guard-home",
        home.path().to_str().unwrap(),
    ]);
    record_failure("first_failure", "error", None, &named);
    let directory = home.path().join(LOG_DIRECTORY);
    let path = directory.join(FAILURE_LOG);
    fs::write(&path, vec![b'x'; MAX_FAILURE_LOG_BYTES as usize]).unwrap();
    let log_directory = LogDirectory::open(home.path(), LOG_DIRECTORY).unwrap();
    let held = rotation_lock(&log_directory).expect("rotation lock");
    let started = Instant::now();
    record_failure("while_locked", "error", None, &named);
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(held);
    assert!(!directory.join(ROTATED_FAILURE_LOG).exists());
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.ends_with("\n") && text.contains("while_locked"));
}

#[cfg(unix)]
#[test]
fn a_fifo_in_place_of_the_log_does_not_hold_up_the_exit() {
    let home = tempfile::tempdir().unwrap();
    let directory = home.path().join(LOG_DIRECTORY);
    fs::create_dir(&directory).unwrap();
    let path = directory.join(FAILURE_LOG);
    let made = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success());
    let named = arguments(&[
        "daemon-serve",
        "--guard-home",
        home.path().to_str().unwrap(),
    ]);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        record_failure("behind_a_fifo", "error", None, &named);
        let _ = sender.send(());
    });
    assert!(
        receiver.recv_timeout(Duration::from_secs(10)).is_ok(),
        "recording a failure blocked on a FIFO"
    );
}

#[test]
fn an_unknown_first_argument_is_not_recorded() {
    let record = failure_record("x", "error", None, &arguments(&["customer-alice"])).unwrap();
    assert_eq!(record["subcommand"], "other");
    assert!(!record.to_string().contains("customer-alice"));
    let known = failure_record("x", "error", None, &arguments(&["daemon-serve"])).unwrap();
    assert_eq!(known["subcommand"], "daemon-serve");
}

#[test]
fn every_literal_runtime_subcommand_is_a_known_label() {
    let source = include_str!("runtime_cli.rs");
    let mut missing = Vec::new();
    for piece in source.split("command == \"").skip(1) {
        let name = piece.split('"').next().unwrap_or_default();
        if !KNOWN_SUBCOMMANDS.contains(&name) {
            missing.push(name.to_owned());
        }
    }
    assert!(missing.is_empty(), "add to KNOWN_SUBCOMMANDS: {missing:?}");
    let mut sorted = KNOWN_SUBCOMMANDS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted, KNOWN_SUBCOMMANDS);
}

#[cfg(unix)]
#[test]
fn an_existing_wide_log_is_made_private_before_it_is_written() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let directory = home.path().join(LOG_DIRECTORY);
    fs::create_dir(&directory).unwrap();
    let path = directory.join(FAILURE_LOG);
    fs::write(&path, b"").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let named = arguments(&[
        "daemon-serve",
        "--guard-home",
        home.path().to_str().unwrap(),
    ]);
    record_failure("widened", "error", None, &named);
    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(fs::read_to_string(&path).unwrap().contains("widened"));
}

#[cfg(unix)]
#[test]
fn a_log_directory_swapped_for_a_symlink_after_opening_keeps_its_writes() {
    let home = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let directory = LogDirectory::open(home.path(), LOG_DIRECTORY).unwrap();
    let moved = home.path().join("moved-logs");
    fs::rename(home.path().join(LOG_DIRECTORY), &moved).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), home.path().join(LOG_DIRECTORY)).unwrap();
    let mut file = directory.open_file(FAILURE_LOG, true).unwrap();
    file.write_all(b"kept\n").unwrap();
    assert!(!elsewhere.path().join(FAILURE_LOG).exists());
    assert_eq!(
        fs::read_to_string(moved.join(FAILURE_LOG)).unwrap(),
        "kept\n"
    );
}
