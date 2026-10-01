use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::{inspect_path, ArchiveCaps, ArchiveStatus};

fn caps() -> ArchiveCaps {
    ArchiveCaps {
        max_archive_bytes: 6 * 1024 * 1024,
        max_files: 500,
        max_expanded_bytes: 32 * 1024 * 1024,
        max_member_bytes: 8 * 1024 * 1024,
        max_package_json_bytes: 256 * 1024,
        max_decompression_ratio: 200.0,
        max_nested_archives: 8,
        max_path_depth: 64,
    }
}

fn never_halt() -> bool {
    false
}

fn inspect_bytes(bytes: &[u8]) -> crate::ArchiveOutcome {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "guard-archive-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("blob.tar");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
    }
    let sha = sha256_hex(bytes);
    let outcome = inspect_path(
        &path,
        &sha,
        &caps(),
        Instant::now() + Duration::from_secs(30),
        &never_halt,
    );
    std::fs::remove_dir_all(&dir).ok();
    outcome
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn tar_member(name: &str, typeflag: u8, size: u64, linkname: &str, data: &[u8]) -> Vec<u8> {
    let mut block = [0u8; 512];
    let name_bytes = name.as_bytes();
    block[..name_bytes.len().min(100)].copy_from_slice(&name_bytes[..name_bytes.len().min(100)]);
    block[100..108].copy_from_slice(b"0000644\0");
    block[108..116].copy_from_slice(b"0000000\0");
    block[116..124].copy_from_slice(b"0000000\0");
    let size_field = format!("{size:011o}\0");
    block[124..136].copy_from_slice(size_field.as_bytes());
    block[136..148].copy_from_slice(b"00000000000\0");
    block[156] = typeflag;
    let link_bytes = linkname.as_bytes();
    block[157..157 + link_bytes.len().min(100)]
        .copy_from_slice(&link_bytes[..link_bytes.len().min(100)]);
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    let mut checksum: u32 = 0;
    for (i, b) in block.iter().enumerate() {
        checksum += if (148..156).contains(&i) {
            32
        } else {
            *b as u32
        };
    }
    let checksum_field = format!("{checksum:06o}\0 ");
    block[148..156].copy_from_slice(checksum_field.as_bytes());
    let mut out = block.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - (data.len() % 512)) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

fn tar_archive(members: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    for member in members {
        out.extend(member);
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

#[test]
fn clean_simple_tar() {
    let tar = tar_archive(vec![tar_member("pkg/index.js", b'0', 4, "", b"x\ny\n")]);
    let outcome = inspect_bytes(&tar);
    assert_eq!(outcome.status, ArchiveStatus::Clean, "{outcome:?}");
    assert_eq!(outcome.code, "external_archive_inspection_clean");
}

#[test]
fn zip_slip_dotdot() {
    let tar = tar_archive(vec![tar_member("../evil", b'0', 1, "", b"x")]);
    let outcome = inspect_bytes(&tar);
    assert_eq!(outcome.status, ArchiveStatus::Blocked);
    assert_eq!(outcome.code, "tarball_zip_slip");
}

#[test]
fn unsafe_symlink_absolute() {
    let tar = tar_archive(vec![tar_member("link", b'2', 0, "/etc/passwd", b"")]);
    let outcome = inspect_bytes(&tar);
    assert_eq!(outcome.status, ArchiveStatus::Blocked);
    assert_eq!(outcome.code, "tarball_zip_slip");
}

#[test]
fn posix_normpath_edges() {
    assert_eq!(crate::posix_path::normpath(b"a/./b/../c"), b"a/c");
    assert_eq!(crate::posix_path::normpath(b".."), b"..");
    assert_eq!(crate::posix_path::normpath(b"./"), b".");
    assert_eq!(crate::posix_path::normpath(b"a/b/"), b"a/b");
    assert_eq!(crate::posix_path::normpath(b""), b".");
    assert_eq!(crate::posix_path::normpath(b"//x"), b"//x");
    assert_eq!(crate::posix_path::normpath(b"///x"), b"/x");
    assert_eq!(crate::posix_path::dirname(b"a/b/c"), b"a/b");
    assert_eq!(crate::posix_path::basename(b"a/b/c"), b"c");
    assert_eq!(crate::posix_path::basename(b"a/b/"), b"");
}

#[test]
fn install_script_blocked() {
    let pkg = br#"{"name":"x","scripts":{"install":"node pwn.js"}}"#;
    let tar = tar_archive(vec![
        tar_member("p/index.js", b'0', 1, "", b"x"),
        tar_member("p/package.json", b'0', pkg.len() as u64, "", pkg),
    ]);
    let outcome = inspect_bytes(&tar);
    assert_eq!(outcome.status, ArchiveStatus::Blocked);
    assert_eq!(outcome.code, "tarball_install_script");
}

#[test]
fn dependency_external_source_blocked() {
    let pkg = br#"{"dependencies":{"x":"file:../local"}}"#;
    let tar = tar_archive(vec![tar_member(
        "package.json",
        b'0',
        pkg.len() as u64,
        "",
        pkg,
    )]);
    let outcome = inspect_bytes(&tar);
    assert_eq!(outcome.status, ArchiveStatus::Blocked);
    assert_eq!(outcome.code, "external_archive_nested_source_dependency");
}

#[test]
fn manifest_bom_rejected() {
    // The retired worker's decode+json.loads rejected BOM-prefixed manifests.
    let pkg = b"\xef\xbb\xbf{}";
    let tar = tar_archive(vec![tar_member(
        "package.json",
        b'0',
        pkg.len() as u64,
        "",
        pkg,
    )]);
    let outcome = inspect_bytes(&tar);
    assert_eq!(outcome.status, ArchiveStatus::Blocked);
    assert_eq!(outcome.code, "external_archive_manifest_invalid");
}

#[test]
fn manifest_null_fields_are_absent() {
    let pkg = br#"{"name":"x","scripts":null,"dependencies":null}"#;
    let tar = tar_archive(vec![tar_member(
        "package.json",
        b'0',
        pkg.len() as u64,
        "",
        pkg,
    )]);
    let outcome = inspect_bytes(&tar);
    assert_eq!(outcome.status, ArchiveStatus::Clean, "{outcome:?}");
}

#[test]
fn setup_py_blocked() {
    let tar = tar_archive(vec![tar_member(
        "pkg/setup.py",
        b'0',
        10,
        "",
        b"print(1)\n\n",
    )]);
    let outcome = inspect_bytes(&tar);
    assert_eq!(outcome.status, ArchiveStatus::Blocked);
    assert_eq!(outcome.code, "python_build_script_risk");
}

#[test]
fn digest_mismatch_blocked() {
    let tar = tar_archive(vec![tar_member("a", b'0', 1, "", b"x")]);
    let dir = std::env::temp_dir().join("guard-archive-digest-mismatch");
    std::fs::create_dir_all(&dir).unwrap();
    let path: PathBuf = dir.join("blob.tar");
    std::fs::write(&path, &tar).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
    }
    let outcome = inspect_path(
        &path,
        &"0".repeat(64),
        &caps(),
        Instant::now() + Duration::from_secs(5),
        &never_halt,
    );
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(outcome.status, ArchiveStatus::Blocked);
    assert_eq!(outcome.code, "external_archive_digest_mismatch");
}

#[test]
fn writable_blob_rejected() {
    let tar = tar_archive(vec![tar_member("a", b'0', 1, "", b"x")]);
    let dir = std::env::temp_dir().join("guard-archive-writable");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("blob.tar");
    std::fs::write(&path, &tar).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
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

#[test]
fn gzip_tar_clean() {
    let tar = tar_archive(vec![tar_member("a", b'0', 1, "", b"x")]);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&tar).unwrap();
    let gz = encoder.finish().unwrap();
    let outcome = inspect_bytes(&gz);
    assert_eq!(outcome.status, ArchiveStatus::Clean, "{outcome:?}");
}

#[test]
fn bzip2_unsupported() {
    let outcome = inspect_bytes(b"BZh91AY&SYfake");
    assert_eq!(outcome.status, ArchiveStatus::Blocked);
    assert_eq!(outcome.code, "external_archive_unsupported_format");
}
