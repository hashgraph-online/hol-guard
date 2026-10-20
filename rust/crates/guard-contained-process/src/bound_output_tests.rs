use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::time::{Duration, Instant};

use super::*;
use crate::{Isolation, PinnedCommand};

fn directory(path: &Path) -> Arc<Directory> {
    Arc::new(Directory::open(&path.canonicalize().unwrap()).unwrap())
}

#[test]
fn hardlinked_and_symlinked_outputs_preserve_protected_bytes() {
    let root = tempfile::tempdir().unwrap();
    let protected = root.path().join("protected");
    let report = root.path().join("report");
    std::fs::write(&protected, b"protected sentinel").unwrap();
    std::fs::hard_link(&protected, &report).unwrap();
    assert!(Output::open(directory(root.path()), OsStr::new("report"), true).is_err());
    assert_eq!(std::fs::read(&protected).unwrap(), b"protected sentinel");
    std::fs::remove_file(&report).unwrap();
    symlink(&protected, &report).unwrap();
    assert!(Output::open(directory(root.path()), OsStr::new("report"), true).is_err());
    assert_eq!(std::fs::read(&protected).unwrap(), b"protected sentinel");
}

#[test]
fn target_replacement_cannot_redirect_an_acquired_output_handle() {
    let root = tempfile::tempdir().unwrap();
    let report = root.path().join("report");
    let protected = root.path().join("protected");
    std::fs::write(&protected, b"protected sentinel").unwrap();
    let output = Output::open(directory(root.path()), OsStr::new("report"), true).unwrap();
    std::fs::remove_file(&report).unwrap();
    symlink(&protected, &report).unwrap();
    assert!(output.verify().is_err());
    output
        .try_clone_file()
        .unwrap()
        .write_all(b"report bytes")
        .unwrap();
    assert_eq!(std::fs::read(&protected).unwrap(), b"protected sentinel");
}

#[test]
fn inherited_output_descriptor_survives_native_launch_without_reopening_path() {
    let root = tempfile::tempdir().unwrap();
    let parent = directory(root.path());
    let output = Output::open(parent, OsStr::new("report"), true).unwrap();
    let command = PinnedCommand::new(
        Path::new("/bin/bash"),
        &[
            OsStr::new("--noprofile"),
            OsStr::new("--norc"),
            OsStr::new("-c"),
            OsStr::new("printf first >&6; printf second >&6"),
        ],
        &root.path().canonicalize().unwrap(),
        &[],
    )
    .unwrap();
    let result = command
        .capture(
            &[],
            1024,
            Instant::now() + Duration::from_secs(5),
            &std::sync::atomic::AtomicBool::new(false),
            Isolation {
                inherited_files: vec![output.try_clone_file().unwrap()],
                ..Isolation::default()
            },
        )
        .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(
        std::fs::read(root.path().join("report")).unwrap(),
        b"firstsecond"
    );
}

#[test]
fn append_does_not_truncate_and_nonleaf_paths_are_refused() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("report"), b"first").unwrap();
    let parent = directory(root.path());
    let output = Output::open(parent.clone(), OsStr::new("report"), false).unwrap();
    output
        .try_clone_file()
        .unwrap()
        .write_all(b"second")
        .unwrap();
    assert_eq!(
        std::fs::read(root.path().join("report")).unwrap(),
        b"firstsecond"
    );
    assert!(Output::open(parent, OsStr::new("../protected"), true).is_err());
}
