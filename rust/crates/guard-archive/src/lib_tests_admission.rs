//! Blob-admission and lifecycle coverage: deadline and halt semantics plus
//! the on-disk identity checks that run before a blob is trusted. Test
//! directories are unique per process and invocation so parallel runs never
//! collide on stale read-only blobs.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::tests::{caps, never_halt, sha256_hex, tar_archive, tar_member};
use crate::{inspect_path, ArchiveStatus};

fn unique_dir(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "guard-archive-admission-{}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        label,
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_blob(dir: &std::path::Path, bytes: &[u8]) -> PathBuf {
    let path = dir.join("blob.tar");
    std::fs::write(&path, bytes).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&path, permissions).unwrap();
    path
}

#[test]
fn elapsed_deadline_produces_timeout() {
    let tar = tar_archive(vec![tar_member("a", b'0', 1, "", b"x")]);
    let dir = unique_dir("deadline");
    let path = write_blob(&dir, &tar);
    let sha = sha256_hex(&tar);
    let outcome = inspect_path(
        &path,
        &sha,
        &caps(),
        Instant::now() - Duration::from_secs(1),
        &never_halt,
    );
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(outcome.status, ArchiveStatus::Incomplete);
    assert_eq!(outcome.code, "external_archive_inspection_timeout");
}

#[test]
fn halt_predicate_stops_inspection() {
    let tar = tar_archive(vec![tar_member("a", b'0', 1, "", b"x")]);
    let dir = unique_dir("halt");
    let path = write_blob(&dir, &tar);
    let sha = sha256_hex(&tar);
    let outcome = inspect_path(
        &path,
        &sha,
        &caps(),
        Instant::now() + Duration::from_secs(30),
        &|| true,
    );
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(outcome.status, ArchiveStatus::Halted);
    assert_eq!(outcome.code, "external_archive_inspection_incomplete");
}

#[test]
fn missing_blob_is_incomplete_not_blocked() {
    let dir = unique_dir("missing");
    let path = dir.join("absent.tar");
    let outcome = inspect_path(
        &path,
        &"0".repeat(64),
        &caps(),
        Instant::now() + Duration::from_secs(5),
        &never_halt,
    );
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(outcome.status, ArchiveStatus::Incomplete);
    assert_eq!(outcome.code, "external_archive_inspection_incomplete");
}

#[test]
fn symlink_leaf_blob_rejected() {
    let tar = tar_archive(vec![tar_member("a", b'0', 1, "", b"x")]);
    let dir = unique_dir("symlink-leaf");
    let real = write_blob(&dir, &tar);
    let link = dir.join("link.tar");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let sha = sha256_hex(&tar);
    let outcome = inspect_path(
        &link,
        &sha,
        &caps(),
        Instant::now() + Duration::from_secs(5),
        &never_halt,
    );
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(outcome.status, ArchiveStatus::Blocked);
    assert_eq!(outcome.code, "external_archive_blob_rejected");
}

#[test]
fn hardlinked_blob_rejected() {
    let tar = tar_archive(vec![tar_member("a", b'0', 1, "", b"x")]);
    let dir = unique_dir("hardlink");
    let path = write_blob(&dir, &tar);
    std::fs::hard_link(&path, dir.join("second.tar")).unwrap();
    let sha = sha256_hex(&tar);
    let outcome = inspect_path(
        &path,
        &sha,
        &caps(),
        Instant::now() + Duration::from_secs(5),
        &never_halt,
    );
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(outcome.status, ArchiveStatus::Blocked);
    assert_eq!(outcome.code, "external_archive_blob_rejected");
}
