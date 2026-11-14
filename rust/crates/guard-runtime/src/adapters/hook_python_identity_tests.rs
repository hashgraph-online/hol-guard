use std::fs;
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::dispatch;

fn ask(path: &Path) -> Value {
    dispatch(&json!({"op": "executable", "path": path})).unwrap()
}

fn write_executable(path: &Path, content: &[u8]) {
    fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn a_regular_executable_answers_its_stat_and_digest() {
    let home = tempfile::tempdir().unwrap();
    let python = super::resolve(home.path()).unwrap().join("python");
    write_executable(&python, b"interpreter");
    let identity = &ask(&python)["identity"];
    assert_eq!(identity["invocation_type"], "file");
    assert_eq!(identity["invocation_link_target"], Value::Null);
    assert_eq!(identity["target_path"], json!(python));
    assert_eq!(
        identity["target_sha256"],
        format!("{:x}", Sha256::digest(b"interpreter"))
    );
    assert_eq!(identity["invocation_stat"], identity["target_stat"]);
    let stat = identity["target_stat"].as_object().unwrap();
    assert_eq!(stat["size"], 11);
    let mut keys: Vec<&String> = stat.keys().collect();
    keys.sort();
    assert_eq!(keys, ["device", "inode", "mode", "mtime_ns", "size"]);
}

#[cfg(unix)]
#[test]
fn a_symlink_records_where_it_points_and_the_stat_os_stat_reports() {
    use std::os::unix::fs::MetadataExt;

    let home = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(home.path()).unwrap();
    let target = root.join("python3.12");
    write_executable(&target, b"interpreter");
    let link = root.join("python");
    std::os::unix::fs::symlink("python3.12", &link).unwrap();
    let identity = &ask(&link)["identity"];
    assert_eq!(identity["invocation_type"], "symlink");
    assert_eq!(identity["invocation_link_target"], "python3.12");
    assert_eq!(identity["invocation_path"], json!(link));
    assert_eq!(identity["target_path"], json!(target));
    let lstat = fs::symlink_metadata(&link).unwrap();
    let expected = json!({
        "device": lstat.dev(),
        "inode": lstat.ino(),
        "mode": lstat.mode(),
        "size": lstat.size(),
        "mtime_ns": i128::from(lstat.mtime()) * 1_000_000_000 + i128::from(lstat.mtime_nsec()),
    });
    assert_eq!(identity["invocation_stat"], expected);
}

#[test]
fn a_missing_directory_or_unexecutable_path_is_refused_by_name() {
    let home = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(home.path()).unwrap();
    assert_eq!(
        ask(&root.join("absent")),
        json!({"error": "guard_hook_python_interpreter_unavailable"})
    );
    assert_eq!(
        ask(&root),
        json!({"error": "guard_hook_python_interpreter_untrusted"})
    );
    #[cfg(unix)]
    {
        let plain = root.join("plain");
        fs::write(&plain, b"x").unwrap();
        assert_eq!(
            ask(&plain),
            json!({"error": "guard_hook_python_interpreter_untrusted"})
        );
    }
}

#[test]
fn a_malformed_request_is_refused() {
    for request in [
        json!({"op": "executable"}),
        json!({"op": "executable", "path": "relative/python"}),
        json!({"op": "other", "path": "/usr/bin/python"}),
        json!({"op": "executable", "path": "/usr/bin/python", "extra": 1}),
        json!({"op": "executable", "path": 1}),
    ] {
        assert!(dispatch(&request).is_err());
    }
}
