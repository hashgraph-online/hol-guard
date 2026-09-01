use guard_secure_fs::{read_bounded, SecureReadError};
use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::Write;

fn fixture_root(name: &str) -> std::path::PathBuf {
    #[cfg(unix)]
    let temporary_root =
        fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
    #[cfg(not(unix))]
    let temporary_root = std::env::temp_dir();
    temporary_root.join(format!("guard-secure-fs-{name}-{}", std::process::id()))
}

#[cfg(unix)]
#[test]
fn bounded_read_rejects_truncation_limit_before_materializing_more_bytes() {
    let dir = fixture_root("truncation");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    fs::write(&path, b"0123456789").unwrap();

    assert!(matches!(
        read_bounded(&path, 4),
        Err(SecureReadError::TooLarge)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn bounded_read_rejects_source_growth_beyond_limit() {
    let dir = fixture_root("growth");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    fs::write(&path, b"safe").unwrap();
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b" growth").unwrap();
    drop(file);

    assert!(matches!(
        read_bounded(&path, 4),
        Err(SecureReadError::TooLarge)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[cfg(not(unix))]
#[test]
fn bounded_read_fail_closes_without_handle_bound_walk() {
    let dir = fixture_root("windows-fail-closed");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    fs::write(&path, b"fn main() {}\n").unwrap();
    assert!(matches!(
        read_bounded(&path, 4),
        Err(SecureReadError::PathChanged)
    ));
    let _ = fs::remove_dir_all(dir);
}
