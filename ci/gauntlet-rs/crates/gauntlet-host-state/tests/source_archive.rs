use flate2::write::GzEncoder;
use flate2::Compression;
use gauntlet_host_state::{verify_retained_source_archive, SourceArchiveError};
use sha2::{Digest, Sha256};
use std::fs::{self, Permissions};
use std::io::Cursor;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use tar::{Builder, EntryType, Header};
use tempfile::TempDir;

const JOB_ID: &str = "0123456789abcdef";

fn fixture() -> (TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let mut path = state.clone();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    for part in ["private", "local-builds", JOB_ID] {
        path.push(part);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    }
    (temp, fs::canonicalize(state).unwrap())
}

fn archive_path(state: &Path) -> PathBuf {
    state
        .join("private/local-builds")
        .join(JOB_ID)
        .join("source.tar.gz")
}

fn add_file(tar: &mut Builder<GzEncoder<Vec<u8>>>, name: &str, bytes: &[u8]) {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    tar.append_data(&mut header, name, Cursor::new(bytes))
        .unwrap();
}

fn bare_git_archive(extra: Option<(&str, EntryType)>) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = Builder::new(encoder);
    add_file(&mut tar, "repository.git/HEAD", b"ref: refs/heads/main\n");
    add_file(
        &mut tar,
        "repository.git/config",
        b"[core]\n\tbare = true\n",
    );
    add_file(
        &mut tar,
        "repository.git/objects/pack/pack-test.pack",
        b"PACK test",
    );
    if let Some((name, kind)) = extra {
        let mut header = Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(0);
        header.set_mode(0o600);
        if kind.is_symlink() {
            header.set_link_name("/tmp/escape").unwrap();
        }
        if name.contains("..") {
            header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            tar.append(&header, Cursor::new([])).unwrap();
        } else {
            header.set_cksum();
            tar.append_data(&mut header, name, Cursor::new([])).unwrap();
        }
    }
    tar.into_inner().unwrap().finish().unwrap()
}

fn write_archive(state: &Path, bytes: &[u8]) -> String {
    let path = archive_path(state);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn authentic_bounded_git_object_archive_is_inert() {
    let (_temp, state) = fixture();
    let bytes = bare_git_archive(None);
    let digest = write_archive(&state, &bytes);
    let result = verify_retained_source_archive(&state, JOB_ID, &digest).unwrap();
    assert_eq!(result.archive_sha256, digest);
    assert_eq!(result.compressed_bytes, bytes.len() as u64);
    assert_eq!(result.entries, 3);
    assert_eq!(result.regular_files, 3);
    assert_eq!(result.directories, 0);
    assert_eq!(result.file_bytes, 50);
    assert!(!result.execution_eligible);
}

#[test]
fn wrong_pin_and_unsafe_private_path_refuse() {
    let (_temp, state) = fixture();
    let bytes = bare_git_archive(None);
    let digest = write_archive(&state, &bytes);
    assert_eq!(
        verify_retained_source_archive(&state, JOB_ID, &"0".repeat(64)),
        Err(SourceArchiveError::DigestMismatch)
    );
    assert_eq!(
        verify_retained_source_archive(&state, "../escape", &digest),
        Err(SourceArchiveError::InvalidInput)
    );
    let path = archive_path(&state);
    fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        verify_retained_source_archive(&state, JOB_ID, &digest),
        Err(SourceArchiveError::UnsafeArchive)
    );
    fs::remove_file(&path).unwrap();
    let target = state.join("private/target.tar.gz");
    fs::write(&target, bytes).unwrap();
    symlink(&target, path).unwrap();
    assert!(verify_retained_source_archive(&state, JOB_ID, &digest).is_err());
}

#[test]
fn duplicate_escaping_and_link_members_refuse() {
    for (name, kind) in [
        ("repository.git/HEAD", EntryType::Regular),
        ("repository.git/../outside", EntryType::Regular),
        ("repository.git/link", EntryType::Symlink),
    ] {
        let (_temp, state) = fixture();
        let bytes = bare_git_archive(Some((name, kind)));
        let digest = write_archive(&state, &bytes);
        assert_eq!(
            verify_retained_source_archive(&state, JOB_ID, &digest),
            Err(SourceArchiveError::InvalidTar),
            "{name}"
        );
    }
}

#[test]
fn malformed_or_truncated_compressed_data_refuses() {
    let (_temp, state) = fixture();
    let mut bytes = bare_git_archive(None);
    bytes.pop();
    let digest = write_archive(&state, &bytes);
    assert_eq!(
        verify_retained_source_archive(&state, JOB_ID, &digest),
        Err(SourceArchiveError::InvalidTar)
    );
}
