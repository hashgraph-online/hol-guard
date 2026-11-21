//! Proofs for the executable digest used to pin a contained command's
//! interpreter: it hashes the exact bytes of one bounded regular file opened
//! without following a symlink, and refuses anything else rather than
//! returning a digest that a later execution could not be held to.

use std::fs;
use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

use super::common::{file_sha256, MAX_EXECUTABLE_BYTES};
use super::vector_support::Workspace;

fn expected_digest(payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(payload);
    hex::encode(digest.finalize())
}

fn make_fifo(path: &Path) {
    // The crate forbids unsafe code, so the named pipe comes from the system
    // tool rather than a direct `mkfifo(2)` call.
    let created = Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("run mkfifo");
    assert!(
        created.success(),
        "mkfifo must succeed for {}",
        path.display()
    );
}

#[test]
fn an_ordinary_executable_hashes_to_bare_hex() {
    let workspace = Workspace::new();
    // A leading space is a legal file name. The digest reads the path as a
    // path, so it must not be split, trimmed or passed through a shell.
    let target = workspace.path.join(" spaced interpreter");
    let payload = b"#!/bin/sh\nexec \"$@\"\n";
    fs::write(&target, payload).expect("write interpreter");

    let digest = file_sha256(&target).expect("digest");

    assert_eq!(digest, expected_digest(payload));
    assert_eq!(digest.len(), 64, "the digest must be bare hex, unprefixed");
    assert!(digest
        .chars()
        .all(|character| character.is_ascii_hexdigit()));
}

#[test]
fn a_symlinked_executable_is_refused() {
    let workspace = Workspace::new();
    let real = workspace.path.join("real");
    fs::write(&real, b"payload").expect("write real");
    let link = workspace.path.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    // Following the link would pin the digest of a file the caller never named,
    // so the open itself refuses rather than resolving it.
    assert_eq!(
        file_sha256(&link),
        Err("executable must not be a symlink".to_owned())
    );
}

#[test]
fn a_non_regular_executable_is_refused() {
    let workspace = Workspace::new();

    // A FIFO opens successfully under O_NONBLOCK and would then read whatever a
    // writer supplies, so its content is not a file identity at all.
    let fifo = workspace.path.join("fifo");
    make_fifo(&fifo);
    assert_eq!(
        file_sha256(&fifo),
        Err("executable must be a bounded regular file".to_owned())
    );

    let directory = workspace.path.join("directory");
    fs::create_dir(&directory).expect("create directory");
    assert_eq!(
        file_sha256(&directory),
        Err("executable must be a bounded regular file".to_owned())
    );

    // Character devices are an unbounded stream behind a regular-looking path.
    assert_eq!(
        file_sha256(Path::new("/dev/zero")),
        Err("executable must be a bounded regular file".to_owned())
    );
}

#[test]
fn an_oversized_executable_is_refused_before_it_is_read() {
    let workspace = Workspace::new();
    let huge = workspace.path.join("huge");
    let file = fs::File::create(&huge).expect("create huge");
    // Sparse: the bound is decided from the reported size, so no real bytes are
    // written and nothing of this size is ever read into memory.
    file.set_len(MAX_EXECUTABLE_BYTES + 1).expect("set_len");
    drop(file);

    assert_eq!(
        file_sha256(&huge),
        Err("executable must be a bounded regular file".to_owned())
    );
}

#[test]
#[cfg(target_os = "linux")]
fn a_file_whose_bytes_disagree_with_its_size_is_refused() {
    // procfs reports size 0 while serving real bytes: exactly the shape of a
    // file that grew or shrank under the hash. Reading more than the size the
    // bound was checked against must fail closed, not pin a partial digest.
    assert_eq!(
        file_sha256(Path::new("/proc/self/status")),
        Err("executable identity changed while hashing".to_owned())
    );
}
