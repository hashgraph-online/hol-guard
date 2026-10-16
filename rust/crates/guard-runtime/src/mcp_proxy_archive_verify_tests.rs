//! Download verification vectors, matching the retired Python verifier: the
//! path must still be the recorded single-link, read-only regular file with the
//! recorded size and SHA-256.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use guard_contracts::McpExternalArchiveDownloadV1;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::mcp_proxy_archive::bind;
use crate::mcp_proxy_archive_verify::verified_replacements;

const URL: &str = "https://example.com/pkg-1.0.0.tgz";
const BYTES: &[u8] = b"archive bytes";

fn record(path: &Path, bytes: &[u8]) -> McpExternalArchiveDownloadV1 {
    McpExternalArchiveDownloadV1 {
        source_url: URL.to_owned(),
        path: path.to_string_lossy().into_owned(),
        size: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

fn write_read_only(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}

#[test]
fn unchanged_read_only_download_binds_a_launch_argv() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("pkg.tgz");
    write_read_only(&path, BYTES);
    let download = record(&path, BYTES);
    let local = download.path.clone();
    let query = guard_contracts::McpExternalArchiveBindQueryV1 {
        params: json!(["pip", "install", URL]),
        downloads: vec![download],
        requires_binding: true,
    };
    assert_eq!(
        bind(&query),
        json!({"kind": "bound", "edits": [{"path": [2], "value": local}]})
    );
}

#[test]
fn every_changed_download_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("pkg.tgz");
    write_read_only(&path, BYTES);
    let good = record(&path, BYTES);

    let mut wrong_hash = good.clone();
    wrong_hash.sha256 = hex::encode(Sha256::digest(b"other bytes!!"));
    let mut wrong_size = good.clone();
    wrong_size.size += 1;
    let mut upper_hash = good.clone();
    upper_hash.sha256 = upper_hash.sha256.to_uppercase();
    for changed in [wrong_hash, wrong_size, upper_hash] {
        assert_eq!(verified_replacements(&[changed]), None);
    }

    let writable = root.path().join("writable.tgz");
    fs::write(&writable, BYTES).unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(verified_replacements(&[record(&writable, BYTES)]), None);

    let linked = root.path().join("linked.tgz");
    fs::hard_link(&path, &linked).unwrap();
    assert_eq!(verified_replacements(&[record(&linked, BYTES)]), None);
    fs::remove_file(&linked).unwrap();

    let link = root.path().join("link.tgz");
    symlink(&path, &link).unwrap();
    assert_eq!(verified_replacements(&[record(&link, BYTES)]), None);

    let fifo = root.path().join("fifo.tgz");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    assert_eq!(verified_replacements(&[record(&fifo, BYTES)]), None);

    let mut oversized = good.clone();
    oversized.size = guard_contracts::ARCHIVE_ACQUISITION_MAX_BYTES + 1;
    assert_eq!(verified_replacements(&[oversized]), None);

    let missing = root.path().join("missing.tgz");
    assert_eq!(verified_replacements(&[record(&missing, BYTES)]), None);

    assert_eq!(
        verified_replacements(&[good.clone(), record(&missing, BYTES)]),
        None
    );
    assert!(verified_replacements(&[good]).is_some());
}

#[test]
fn repeated_source_url_keeps_its_position_and_takes_the_later_path() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("first.tgz");
    let second = root.path().join("second.tgz");
    write_read_only(&first, BYTES);
    write_read_only(&second, BYTES);
    let mut other = record(&first, BYTES);
    other.source_url = "https://example.com/other.tgz".to_owned();
    let replacements =
        verified_replacements(&[record(&first, BYTES), other.clone(), record(&second, BYTES)])
            .unwrap();
    assert_eq!(
        replacements,
        vec![
            (URL.to_owned(), second.to_string_lossy().into_owned()),
            (other.source_url, other.path),
        ]
    );
}
