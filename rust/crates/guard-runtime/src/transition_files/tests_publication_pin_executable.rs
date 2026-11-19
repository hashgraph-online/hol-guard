use std::path::Path;

use serde_json::{json, Value};

use super::dispatch;

fn pin_with(fields: Value) -> Result<Value, Value> {
    let mut request = json!({"op": "publication_pin_executable", "deadline": 105.0, "now": 100.0});
    for (key, value) in fields.as_object().unwrap() {
        request[key] = value.clone();
    }
    let answer = dispatch(&request).unwrap();
    match answer.get("error") {
        Some(error) => Err(error.clone()),
        None => Ok(answer["value"].clone()),
    }
}

fn pin(path: &Path, fields: Value) -> Result<Value, Value> {
    let mut request = json!({"path": path.to_string_lossy()});
    for (key, value) in fields.as_object().unwrap() {
        request[key] = value.clone();
    }
    pin_with(request)
}

fn transition(error: &Value) -> &str {
    error["transition"].as_str().unwrap_or_default()
}

fn integrity(error: &Value) -> &str {
    error["integrity"].as_str().unwrap_or_default()
}

#[cfg(unix)]
mod posix {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use sha2::{Digest, Sha256};

    use super::*;

    fn executable(directory: &Path, name: &str, bytes: &[u8], mode: u32) -> std::path::PathBuf {
        let path = directory.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn a_pinned_executable_reports_its_owner_mode_size_and_digest() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = executable(directory.path(), "runtime", b"binary bytes", 0o700);
        let record = pin(&runtime, json!({})).unwrap();
        assert_eq!(record["path"], json!(runtime.to_string_lossy()));
        assert_eq!(record["mode"], json!(0o700));
        assert_eq!(
            record["owner_uid"],
            json!(fs::metadata(&runtime).unwrap().uid())
        );
        assert_eq!(record["size"], json!(12));
        assert_eq!(record["role"], "artifact");
        assert_eq!(
            record["sha256"],
            json!(format!("{:x}", Sha256::digest(b"binary bytes")))
        );
    }

    #[test]
    fn a_large_file_is_hashed_across_chunks() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = vec![7_u8; 3 * 64 * 1024 + 5];
        let runtime = executable(directory.path(), "runtime", &bytes, 0o700);
        let record = pin(&runtime, json!({})).unwrap();
        assert_eq!(record["size"], json!(bytes.len()));
        assert_eq!(
            record["sha256"],
            json!(format!("{:x}", Sha256::digest(&bytes)))
        );
    }

    #[test]
    fn a_reviewed_digest_must_match_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = executable(directory.path(), "runtime", b"binary bytes", 0o700);
        let digest = format!("{:x}", Sha256::digest(b"binary bytes"));
        assert!(pin(&runtime, json!({"expected_sha256": digest})).is_ok());
        let wrong = pin(&runtime, json!({"expected_sha256": "0".repeat(64)})).unwrap_err();
        assert_eq!(transition(&wrong), "artifact_generation_changed");
    }

    #[test]
    fn an_inspected_identity_must_still_be_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = executable(directory.path(), "runtime", b"binary bytes", 0o700);
        let metadata = fs::metadata(&runtime).unwrap();
        let identity = json!({
            "sha256": format!("{:x}", Sha256::digest(b"binary bytes")),
            "size": 12,
            "mtime_ns": metadata.mtime() * 1_000_000_000 + metadata.mtime_nsec(),
        });
        assert!(pin(&runtime, json!({"expected": identity})).is_ok());
        for (key, value) in [
            ("sha256", json!("0".repeat(64))),
            ("size", json!(13)),
            ("mtime_ns", json!(1)),
        ] {
            let mut changed = identity.clone();
            changed[key] = value;
            let error = pin(&runtime, json!({"expected": changed})).unwrap_err();
            assert_eq!(
                transition(&error),
                "native_runtime_generation_changed",
                "{key}"
            );
        }
        let mut absent = identity.clone();
        absent.as_object_mut().unwrap().remove("size");
        assert_eq!(
            transition(&pin(&runtime, json!({"expected": absent})).unwrap_err()),
            "native_runtime_generation_changed"
        );
    }

    #[test]
    fn a_file_that_is_not_a_safe_executable_is_refused_by_the_integrity_checks() {
        let directory = tempfile::tempdir().unwrap();
        for (name, mode) in [("plain", 0o600), ("group", 0o770), ("world", 0o707)] {
            let path = executable(directory.path(), name, b"x", mode);
            let error = pin(&path, json!({})).unwrap_err();
            assert!(
                integrity(&error).starts_with("codex_hook_artifact_"),
                "{name}: {error}"
            );
        }
        let target = executable(directory.path(), "target", b"x", 0o700);
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            integrity(&pin(&link, json!({})).unwrap_err()),
            "codex_hook_artifact_not_regular"
        );
        assert_eq!(
            integrity(&pin(&directory.path().join("missing"), json!({})).unwrap_err()),
            "codex_hook_artifact_missing"
        );
    }

    #[test]
    fn the_hook_validation_budget_bounds_the_checks() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = executable(directory.path(), "runtime", b"x", 0o700);
        let error = pin(&runtime, json!({"budget": {"hook_ms": 0}})).unwrap_err();
        assert_eq!(integrity(&error), "codex_hook_validation_deadline_expired");
    }
}

#[test]
fn an_expired_or_unusable_deadline_is_refused_before_the_file_is_read() {
    let missing = Path::new("/nonexistent/runtime");
    for fields in [
        json!({"deadline": 100.0}),
        json!({"deadline": 99.0}),
        json!({"deadline": null}),
        json!({"now": null}),
        json!({"deadline": "soon"}),
    ] {
        let error = pin(missing, fields.clone()).unwrap_err();
        assert_eq!(transition(&error), "deadline_exceeded", "{fields}");
    }
}

#[test]
fn a_malformed_request_is_refused() {
    let path = Path::new("/nonexistent/runtime");
    for fields in [json!({"expected": "text"}), json!({"expected_sha256": 5})] {
        let error = pin(path, fields).unwrap_err();
        assert_eq!(transition(&error), "files_invalid");
    }
    let error = pin_with(json!({})).unwrap_err();
    assert_eq!(transition(&error), "files_invalid");
}
