use super::*;

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
