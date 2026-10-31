use super::{file_identity, validate_process_runtime_digest, verified_cache};
use crate::resident_process_identity::{executable_digest, process_start_marker};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MISMATCH: &str = "native_resident_process_identity_mismatch";

/// This test process, which is alive and has a start marker to check.
fn this_process() -> (u32, String) {
    let process_id = std::process::id();
    let marker = process_start_marker(process_id).expect("read this process's start marker");
    (process_id, marker)
}

/// A runtime file whose last change is old enough to be remembered.
fn settled_runtime(directory: &Path, bytes: &[u8]) -> PathBuf {
    let path = directory.join("hol-guard-runtime");
    fs::write(&path, bytes).expect("write the runtime");
    std::thread::sleep(Duration::from_millis(1_100));
    fs::canonicalize(path).expect("resolve the runtime")
}

fn remembered(process_id: u32, marker: &str, path: &Path, digest: &str) -> bool {
    verified_cache::contains(&verified_cache::VerifiedRuntime {
        process_id,
        start_marker: marker.to_owned(),
        path: path.to_owned(),
        digest: digest.to_owned(),
        file: file_identity::read(path).expect("read the runtime identity"),
    })
}

#[test]
fn a_verified_runtime_is_remembered_for_its_process_lifetime() {
    let directory = tempfile::tempdir().expect("create a directory");
    let path = settled_runtime(directory.path(), b"runtime one");
    let digest = executable_digest(&path).expect("hash the runtime");
    let (process_id, marker) = this_process();

    assert_eq!(
        validate_process_runtime_digest(process_id, &marker, path.clone(), &digest),
        Ok(())
    );
    assert!(remembered(process_id, &marker, &path, &digest));
    assert_eq!(
        validate_process_runtime_digest(process_id, &marker, path, &digest),
        Ok(())
    );
}

#[test]
fn a_runtime_with_another_digest_is_refused_and_not_remembered() {
    let directory = tempfile::tempdir().expect("create a directory");
    let path = settled_runtime(directory.path(), b"runtime two");
    let other = "0".repeat(64);
    let (process_id, marker) = this_process();

    assert_eq!(
        validate_process_runtime_digest(process_id, &marker, path.clone(), &other),
        Err(MISMATCH.to_owned())
    );
    assert!(!remembered(process_id, &marker, &path, &other));
}

#[test]
fn a_remembered_runtime_is_refused_for_a_process_that_started_later() {
    let directory = tempfile::tempdir().expect("create a directory");
    let path = settled_runtime(directory.path(), b"runtime three");
    let digest = executable_digest(&path).expect("hash the runtime");
    let (process_id, marker) = this_process();
    validate_process_runtime_digest(process_id, &marker, path.clone(), &digest)
        .expect("verify the runtime");

    assert_eq!(
        validate_process_runtime_digest(process_id, "reused-pid", path, &digest),
        Err(MISMATCH.to_owned())
    );
}

#[cfg(unix)]
mod unix {
    use super::*;

    #[test]
    fn a_runtime_changed_moments_ago_is_verified_but_not_remembered() {
        let directory = tempfile::tempdir().expect("create a directory");
        let path = directory.path().join("hol-guard-runtime");
        fs::write(&path, b"fresh runtime").expect("write the runtime");
        let path = fs::canonicalize(path).expect("resolve the runtime");
        let digest = executable_digest(&path).expect("hash the runtime");
        let (process_id, marker) = this_process();

        assert_eq!(
            validate_process_runtime_digest(process_id, &marker, path.clone(), &digest),
            Ok(())
        );
        assert!(!remembered(process_id, &marker, &path, &digest));
    }

    #[test]
    fn a_rewrite_in_place_with_its_old_modified_time_is_hashed_again() {
        let directory = tempfile::tempdir().expect("create a directory");
        let path = settled_runtime(directory.path(), b"trusted runtime");
        let digest = executable_digest(&path).expect("hash the runtime");
        let (process_id, marker) = this_process();
        validate_process_runtime_digest(process_id, &marker, path.clone(), &digest)
            .expect("verify the runtime");
        assert!(remembered(process_id, &marker, &path, &digest));

        let modified = fs::metadata(&path).and_then(|metadata| metadata.modified());
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open the runtime in place");
        std::io::Write::write_all(&mut &file, b"swapped runtime").expect("rewrite the runtime");
        file.set_modified(modified.expect("read the modified time"))
            .expect("restore the modified time");
        drop(file);

        assert_eq!(
            validate_process_runtime_digest(process_id, &marker, path, &digest),
            Err(MISMATCH.to_owned())
        );
    }

    #[test]
    fn a_file_renamed_over_the_runtime_is_hashed_again() {
        let directory = tempfile::tempdir().expect("create a directory");
        let path = settled_runtime(directory.path(), b"trusted runtime");
        let digest = executable_digest(&path).expect("hash the runtime");
        let (process_id, marker) = this_process();
        validate_process_runtime_digest(process_id, &marker, path.clone(), &digest)
            .expect("verify the runtime");

        let replacement = directory.path().join("replacement");
        fs::write(&replacement, b"swapped runtime").expect("write the replacement");
        fs::rename(&replacement, &path).expect("rename over the runtime");

        assert_eq!(
            validate_process_runtime_digest(process_id, &marker, path, &digest),
            Err(MISMATCH.to_owned())
        );
    }
}
