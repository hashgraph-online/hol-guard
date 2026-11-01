use serde_json::{json, Value};

use super::run_command;

fn run(request: &Value) -> Result<Value, String> {
    let bytes = serde_json::to_vec(request).expect("request encodes");
    let answer = run_command(bytes.as_slice())?;
    Ok(serde_json::from_slice(&answer).expect("answer decodes"))
}

#[test]
fn malformed_requests_fail_the_command() {
    let absolute = std::env::temp_dir().join("policy.yaml");
    let requests = [
        json!({"schema": "policy-file-io.v0", "op": "read", "path": absolute}),
        json!({"schema": "policy-file-io.v1", "op": "read", "path": "policy.yaml"}),
        json!({"schema": "policy-file-io.v1", "op": "remove", "path": absolute}),
        json!({"schema": "policy-file-io.v1", "op": "read", "path": absolute, "content": ""}),
        json!({"schema": "policy-file-io.v1", "op": "write", "path": absolute}),
        json!({"schema": "policy-file-io.v1", "op": "read", "path": absolute, "extra": 1}),
    ];
    for request in requests {
        assert_eq!(
            run(&request).unwrap_err(),
            "policy_file_io_request_invalid",
            "{request}"
        );
    }
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use serde_json::{json, Value};

    use super::run;
    use crate::policy_file_io::platform::write_private_with;
    use crate::policy_file_io::MAX_POLICY_BYTES;

    struct Folder {
        _root: tempfile::TempDir,
        path: PathBuf,
    }

    fn private_folder() -> Folder {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().canonicalize().expect("canonical tempdir");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod");
        Folder { _root: root, path }
    }

    fn private_file(path: &Path, content: &[u8]) {
        fs::write(path, content).expect("write");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    fn read(path: &Path) -> Value {
        run(&json!({"schema": "policy-file-io.v1", "op": "read", "path": path})).expect("answer")
    }

    fn write(path: &Path, content: &str) -> Value {
        run(&json!({
            "schema": "policy-file-io.v1",
            "op": "write",
            "path": path,
            "content": content,
        }))
        .expect("answer")
    }

    fn failure(code: &str) -> Value {
        json!({ "failure": code })
    }

    fn leftover_temporaries(folder: &Path) -> Vec<String> {
        fs::read_dir(folder)
            .expect("list")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.starts_with('.') && name.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn writes_an_owner_only_file_and_reads_it_back() {
        let folder = private_folder();
        let policy = folder.path.join("policy.yaml");
        assert_eq!(write(&policy, "rules: []\n"), json!({"written": true}));
        assert_eq!(fs::metadata(&policy).expect("stat").mode() & 0o777, 0o600);
        assert_eq!(read(&policy), json!({"text": "rules: []\n"}));
        assert_eq!(write(&policy, "rules: [1]\n"), json!({"written": true}));
        assert_eq!(read(&policy), json!({"text": "rules: [1]\n"}));
        assert!(leftover_temporaries(&folder.path).is_empty());
    }

    #[test]
    fn writes_a_file_far_larger_than_one_write_call() {
        let folder = private_folder();
        let policy = folder.path.join("policy.yaml");
        let content = "x".repeat(MAX_POLICY_BYTES);
        assert_eq!(write(&policy, &content), json!({"written": true}));
        assert_eq!(fs::read(&policy).expect("read").len(), MAX_POLICY_BYTES);
    }

    #[test]
    fn refuses_a_missing_file() {
        let folder = private_folder();
        assert_eq!(
            read(&folder.path.join("absent.yaml")),
            failure("policy_file_unavailable")
        );
    }

    #[test]
    fn refuses_a_symlinked_file() {
        let folder = private_folder();
        let target = folder.path.join("target.yaml");
        private_file(&target, b"rules: []\n");
        let policy = folder.path.join("policy.yaml");
        symlink(&target, &policy).expect("symlink");
        assert_eq!(read(&policy), failure("policy_file_not_regular"));
        assert_eq!(
            write(&policy, "rules: []\n"),
            failure("policy_file_not_regular")
        );
        assert!(fs::symlink_metadata(&policy)
            .expect("stat")
            .file_type()
            .is_symlink());
    }

    #[test]
    fn refuses_a_symlinked_ancestor() {
        let folder = private_folder();
        let real = folder.path.join("real");
        fs::create_dir(&real).expect("mkdir");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("chmod");
        private_file(&real.join("policy.yaml"), b"rules: []\n");
        let linked = folder.path.join("linked");
        symlink(&real, &linked).expect("symlink");
        let policy = linked.join("policy.yaml");
        assert_eq!(read(&policy), failure("policy_parent_unavailable"));
        assert_eq!(
            write(&policy, "rules: []\n"),
            failure("policy_parent_unavailable")
        );
    }

    #[test]
    fn refuses_a_hardlinked_file() {
        let folder = private_folder();
        let policy = folder.path.join("policy.yaml");
        private_file(&policy, b"rules: []\n");
        fs::hard_link(&policy, folder.path.join("alias.yaml")).expect("hardlink");
        assert_eq!(read(&policy), failure("policy_file_link_count"));
        assert_eq!(
            write(&policy, "rules: [1]\n"),
            failure("policy_file_link_count")
        );
        assert_eq!(fs::read(&policy).expect("read"), b"rules: []\n");
    }

    #[test]
    fn refuses_a_group_writable_file() {
        let folder = private_folder();
        let policy = folder.path.join("policy.yaml");
        private_file(&policy, b"rules: []\n");
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o620)).expect("chmod");
        assert_eq!(read(&policy), failure("policy_file_insecure_mode"));
    }

    #[test]
    fn refuses_a_world_writable_folder() {
        let folder = private_folder();
        let policy = folder.path.join("policy.yaml");
        private_file(&policy, b"rules: []\n");
        fs::set_permissions(&folder.path, fs::Permissions::from_mode(0o777)).expect("chmod");
        assert_eq!(read(&policy), failure("policy_parent_insecure_mode"));
        assert_eq!(
            write(&policy, "rules: []\n"),
            failure("policy_parent_insecure_mode")
        );
        fs::set_permissions(&folder.path, fs::Permissions::from_mode(0o700)).expect("chmod");
    }

    #[test]
    fn refuses_a_folder_that_is_a_file() {
        let folder = private_folder();
        let file = folder.path.join("file");
        private_file(&file, b"");
        assert_eq!(
            read(&file.join("policy.yaml")),
            failure("policy_parent_unavailable")
        );
    }

    #[test]
    fn refuses_an_oversized_file() {
        let folder = private_folder();
        let policy = folder.path.join("policy.yaml");
        private_file(&policy, &vec![b'x'; MAX_POLICY_BYTES + 1]);
        assert_eq!(read(&policy), failure("policy_file_too_large"));
    }

    #[test]
    fn refuses_a_file_that_is_not_utf8() {
        let folder = private_folder();
        let policy = folder.path.join("policy.yaml");
        private_file(&policy, b"rules: \xff\n");
        assert_eq!(read(&policy), failure("policy_file_not_utf8"));
    }

    #[test]
    fn refuses_oversized_output_without_touching_the_file() {
        let folder = private_folder();
        let policy = folder.path.join("policy.yaml");
        private_file(&policy, b"rules: []\n");
        let content = "x".repeat(MAX_POLICY_BYTES + 1);
        assert_eq!(write(&policy, &content), failure("policy_output_too_large"));
        assert_eq!(fs::read(&policy).expect("read"), b"rules: []\n");
    }

    #[test]
    fn a_failed_replace_keeps_the_existing_file_and_no_temporary() {
        let folder = private_folder();
        let policy = folder.path.join("policy.yaml");
        private_file(&policy, b"rules: []\n");
        let refused = write_private_with(&policy, b"rules: [1]\n", &|_, _, _| {
            Err(nix::errno::Errno::EIO)
        });
        assert_eq!(refused, Err("policy_output_write_failed"));
        assert_eq!(fs::read(&policy).expect("read"), b"rules: []\n");
        assert!(leftover_temporaries(&folder.path).is_empty());
    }
}
