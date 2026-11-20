//! Loader admission, mapping-record validation and credential-free discovery.
use super::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn root() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    (directory, root)
}

fn executable(path: &Path, interpreter: Option<&[u8]>) {
    let count: u16 = if interpreter.is_some() { 2 } else { 1 };
    let mut bytes = b"\x7fELF\x02\x01\x01".to_vec();
    bytes.extend([0u8; 9]);
    bytes.extend(2u16.to_le_bytes());
    bytes.extend(183u16.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend(0u64.to_le_bytes());
    bytes.extend(64u64.to_le_bytes());
    bytes.extend(0u64.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(64u16.to_le_bytes());
    bytes.extend(56u16.to_le_bytes());
    bytes.extend(count.to_le_bytes());
    bytes.extend([0u8; 6]);
    let mut program = |kind: u32, flags: u32, offset: u64, size: u64, align: u64| {
        bytes.extend(kind.to_le_bytes());
        bytes.extend(flags.to_le_bytes());
        for value in [offset, 0, 0, size, size, align] {
            bytes.extend(value.to_le_bytes());
        }
    };
    program(1, 5, 0, 64, 4096);
    if let Some(interpreter) = interpreter {
        program(3, 4, 64 + 56 * count as u64, interpreter.len() as u64, 1);
    }
    if let Some(interpreter) = interpreter {
        bytes.extend(interpreter);
    }
    fs::write(path, bytes).unwrap();
}

#[test]
fn a_static_image_does_not_receive_a_loader() {
    let (_directory, root) = root();
    let image = root.join("native");
    executable(&image, None);
    assert_eq!(elf::resolve(&image), Ok(None));
}

#[test]
fn an_unapproved_or_malformed_loader_cannot_receive_an_exec_grant() {
    let (_directory, root) = root();
    let image = root.join("native");
    for interpreter in [
        &b"/tmp/loader\x00"[..],
        b"/bin/sh\x00",
        b"/lib/ld-linux-aarch64.so.1",
        b"/lib/ld\x00extra\x00",
    ] {
        executable(&image, Some(interpreter));
        assert!(
            elf::resolve(&image).is_err(),
            "interpreter={:?}",
            String::from_utf8_lossy(interpreter)
        );
    }
}

#[test]
fn bad_native_metadata_does_not_fall_back_to_a_guessed_loader() {
    let (_directory, root) = root();
    let image = root.join("native");
    for content in [&b""[..], b"\x7fELF", &[0u8; 4096]] {
        fs::write(&image, content).unwrap();
        assert!(elf::resolve(&image).is_err(), "length={}", content.len());
    }
}

#[test]
fn an_executable_symlink_must_already_be_resolved_by_its_owner() {
    let (_directory, root) = root();
    let actual = root.join("native");
    let alias = root.join("alias");
    executable(&actual, None);
    symlink(&actual, &alias).unwrap();
    assert_eq!(elf::resolve(&actual), Ok(None));
    assert!(elf::resolve(&alias).is_err());
}

fn record(path: &Path) -> Value {
    fs::write(path, b"synthetic approved executable").unwrap();
    let metadata = fs::metadata(path).unwrap();
    json!({
        "path": path,
        "identity": [
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime() as u64 * 1_000_000_000 + metadata.mtime_nsec() as u64,
            metadata.mode(),
        ],
        "sha256": "ab".repeat(32),
        "targets": [path],
    })
}

#[test]
fn malformed_mapping_evidence_is_rejected() {
    let (_directory, root) = root();
    let path = root.join("approved");
    let approved = BTreeSet::from([path.clone()]);
    let valid = record(&path);
    let records = mapping_records::validate(&json!([&valid]), &approved).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].aliases, vec![path.clone()]);
    for mutation in [
        "extra",
        "relative",
        "parent",
        "unbound",
        "boolean",
        "size",
        "hash",
        "alias",
        "duplicate",
    ] {
        let mut record = valid.clone();
        let mut approved = approved.clone();
        let mut records = vec![];
        match mutation {
            "extra" => record["override"] = json!(true),
            "relative" => record["path"] = json!("relative"),
            "parent" => record["targets"] = json!([path, "/tmp/../escape"]),
            "unbound" => approved.clear(),
            "boolean" => record["identity"][0] = json!(true),
            "size" => record["identity"][2] = json!(1024u64 * 1024 * 1024),
            "hash" => record["sha256"] = json!("z".repeat(64)),
            "alias" => record["targets"] = json!([path, path]),
            _ => records.push(record.clone()),
        }
        records.push(record);
        assert!(
            mapping_records::validate(&json!(records), &approved).is_err(),
            "mutation={mutation}"
        );
    }
}

#[test]
fn ordinary_source_is_admitted_without_reading_credential_data() {
    let (_directory, root) = root();
    let source = root.join("source.py");
    fs::write(&source, "ordinary source").unwrap();
    for name in [
        ".env",
        ".ENV.local",
        ".npmrc",
        "private-key.pem",
        "wallet.key",
    ] {
        fs::write(root.join(name), "synthetic fixture only").unwrap();
    }
    fs::create_dir(root.join(".ssh")).unwrap();
    fs::write(root.join(".ssh/config"), "synthetic fixture only").unwrap();
    let (grants, _) =
        paths::collect_with_candidates(&root, 100, Instant::now() + Duration::from_secs(5))
            .unwrap();
    let metadata = fs::metadata(&source).unwrap();
    assert_eq!(grants, vec![(source, metadata.dev(), metadata.ino())]);
}
