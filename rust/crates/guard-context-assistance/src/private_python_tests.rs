use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

static FIXTURE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    selection: RuntimeSelection,
}
fn write(path: &Path, bytes: &[u8], mode: u32) {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
impl Fixture {
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "guard-cigar-python-binding-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let python = root.join("python");
        for path in [
            "python",
            "python/bin",
            "python/lib",
            "python/lib/python3.14",
            "work",
            "packages",
        ] {
            let path = root.join(path);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let executable = format!(
            "#!/bin/sh\n/usr/bin/touch '{}'\nexit 79\n",
            root.join("launched").display()
        );
        let entries = [
            ("bin/python3.14", executable.as_bytes(), 0o500),
            (
                "lib/python3.14/os.py",
                b"# original standard library\n".as_slice(),
                0o400,
            ),
        ];
        let mut tree = Sha256::new();
        tree.update(b"guard-cigar-python-tree.v1\0");
        let mut bytes = 0;
        for (name, content, mode) in entries {
            write(&python.join(name), content, mode);
            tree.update((name.len() as u64).to_be_bytes());
            tree.update(name.as_bytes());
            tree.update(format!("{:x}", Sha256::digest(content)).as_bytes());
            bytes += content.len() as u64;
        }
        let binding = InterpreterBinding {
            build_id: "synthetic-private-python-test".into(),
            python_version: [3, 14, 10],
            platform: "darwin-arm64".into(),
            source_revision: "a".repeat(40),
            archive_sha256: "b".repeat(64),
            archive_bytes: 100,
            tree_sha256: format!("{:x}", tree.finalize()),
            files: 2,
            expanded_bytes: bytes,
            executable_sha256: format!("{:x}", Sha256::digest(executable.as_bytes())),
        };
        Self {
            selection: RuntimeSelection {
                verified_python: None,
                python: python.join("bin/python3.14"),
                site_packages: root.join("packages"),
                work_dir: root.join("work"),
                python_bundle: Some(PrivatePythonSelection {
                    root: python,
                    binding,
                }),
            },
            root,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
#[test]
fn protected_private_interpreter_requires_the_full_tree_and_exact_path() {
    let mut fixture = Fixture::new();
    let binding = fixture
        .selection
        .python_bundle
        .as_ref()
        .unwrap()
        .binding
        .clone();
    assert_eq!(
        check_selection(&fixture.selection, Some("darwin-arm64"), None).unwrap(),
        Some(binding)
    );
    assert_eq!(
        check_selection(&fixture.selection, Some("linux-x64-gnu"), None),
        Err(RuntimeError::ApprovalMismatch)
    );
    fixture.selection.python = fixture.root.join("elsewhere/python3.14");
    assert_eq!(
        check_selection(&fixture.selection, None, None),
        Err(RuntimeError::ApprovalMismatch)
    );
}
#[test]
fn unchanged_executable_does_not_hide_a_changed_standard_library_before_launch() {
    let fixture = Fixture::new();
    let original = guard_secure_fs::read_stable(&fixture.selection.python, 4096, false)
        .unwrap()
        .sha256;
    let library = fixture
        .selection
        .python_bundle
        .as_ref()
        .unwrap()
        .root
        .join("lib/python3.14/os.py");
    write(&library, b"# replaced standard library\n", 0o400);
    assert_eq!(
        original,
        guard_secure_fs::read_stable(&fixture.selection.python, 4096, false)
            .unwrap()
            .sha256
    );
    let cancel = AtomicBool::new(false);
    assert_eq!(
        crate::process::probe(&fixture.selection, "print('unsafe')", &cancel).unwrap_err(),
        RuntimeError::ApprovalMismatch
    );
    assert!(!fixture.root.join("launched").exists());
    assert_eq!(
        check_selection(&fixture.selection, None, None),
        Err(RuntimeError::ApprovalMismatch)
    );
}
#[test]
fn writable_code_unexpected_files_and_cancelled_checks_refuse() {
    let fixture = Fixture::new();
    let cancel = AtomicBool::new(true);
    assert_eq!(
        check_selection(&fixture.selection, None, Some(&cancel)),
        Err(RuntimeError::Cancelled)
    );
    cancel.store(false, Ordering::Release);
    let library = fixture
        .selection
        .python_bundle
        .as_ref()
        .unwrap()
        .root
        .join("lib/python3.14/os.py");
    fs::set_permissions(&library, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        check_selection(&fixture.selection, None, Some(&cancel)),
        Err(RuntimeError::ApprovalMismatch)
    );
    fs::set_permissions(&library, fs::Permissions::from_mode(0o400)).unwrap();
    let extra = fixture
        .selection
        .python_bundle
        .as_ref()
        .unwrap()
        .root
        .join("lib/extra.py");
    write(&extra, b"# extra code", 0o400);
    assert_eq!(
        check_selection(&fixture.selection, None, None),
        Err(RuntimeError::ApprovalMismatch)
    );
}
#[test]
fn old_selection_and_approval_serialization_preserve_legacy_receipt_contexts() {
    let old = serde_json::json!({"python":"/private/python", "site_packages":"/private/packages",
        "work_dir":"/private/work"});
    let selection: RuntimeSelection = serde_json::from_value(old.clone()).unwrap();
    assert!(selection.python_bundle.is_none());
    assert_eq!(serde_json::to_value(&selection).unwrap(), old);
    let old = serde_json::json!({"schema":"guard-cigar-bundle-approval.v2", "platform":"darwin-arm64",
        "python_sha256":"a".repeat(64), "package_tree_sha256":"b".repeat(64),
        "worker_sha256":"c".repeat(64), "files": 1, "bytes": 100});
    let approval: crate::BundleApproval = serde_json::from_value(old.clone()).unwrap();
    assert!(approval.python_bundle.is_none());
    assert_eq!(serde_json::to_value(&approval).unwrap(), old);
}

#[test]
fn cached_verification_refuses_changed_code_even_after_length_and_mtime_are_restored() {
    let mut fixture = Fixture::new();
    fixture.selection.verify_private_python(None).unwrap();
    assert!(fixture.selection.verified_python.is_some());
    let library = fixture
        .selection
        .python_bundle
        .as_ref()
        .unwrap()
        .root
        .join("lib/python3.14/os.py");
    let before = fs::metadata(&library).unwrap();
    let mut bytes = fs::read(&library).unwrap();
    bytes[2] ^= 1;
    write(&library, &bytes, 0o400);
    let file = fs::File::open(&library).unwrap();
    file.set_times(fs::FileTimes::new().set_modified(before.modified().unwrap()))
        .unwrap();
    assert_eq!(fs::metadata(&library).unwrap().len(), before.len());
    assert_eq!(
        fs::metadata(&library).unwrap().modified().unwrap(),
        before.modified().unwrap()
    );
    assert_eq!(
        check_selection(&fixture.selection, None, None),
        Err(RuntimeError::ApprovalMismatch)
    );
    assert!(!fixture.root.join("launched").exists());
}
#[test]
fn cached_verification_refuses_extra_directories_and_cannot_rebind_to_another_tree() {
    let mut fixture = Fixture::new();
    fixture.selection.verify_private_python(None).unwrap();
    let mut other = Fixture::new();
    other.selection.verified_python = fixture.selection.verified_python.clone();
    assert_eq!(
        check_selection(&other.selection, None, None),
        Err(RuntimeError::ApprovalMismatch)
    );
    let root = fixture
        .selection
        .python_bundle
        .as_ref()
        .unwrap()
        .root
        .clone();
    fs::create_dir(root.join("unexpected-empty-directory")).unwrap();
    assert_eq!(
        check_selection(&fixture.selection, None, None),
        Err(RuntimeError::ApprovalMismatch)
    );
}
#[test]
fn in_memory_tree_snapshot_never_enters_installation_json_or_survives_deserialization() {
    let mut fixture = Fixture::new();
    let before = serde_json::to_value(&fixture.selection).unwrap();
    fixture.selection.verify_private_python(None).unwrap();
    assert_eq!(serde_json::to_value(&fixture.selection).unwrap(), before);
    let read: RuntimeSelection = serde_json::from_value(before).unwrap();
    assert!(read.verified_python.is_none());
    let mut forged = serde_json::to_value(&read).unwrap();
    forged["verified_python"] = serde_json::json!({"trusted": true});
    assert!(serde_json::from_value::<RuntimeSelection>(forged).is_err());
}
