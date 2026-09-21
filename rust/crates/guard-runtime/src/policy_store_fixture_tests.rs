use super::{fixture_file, test_root};
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn fixture_rewrite_truncates_private_file_without_weakening_create_new() {
    let root = test_root("fixture-private-rewrite");
    let path = root.join("private.json");
    {
        let mut file = crate::resident_state::private_file(&path, true, &root).unwrap();
        file.write_all(b"original-long-fixture").unwrap();
    }
    fixture_file(&path, b"short");
    assert_eq!(fs::read(&path).unwrap(), b"short");

    // The production create-only contract must remain non-mutating. Fixing the
    // test writer must not reopen or truncate a pre-existing private object.
    assert!(crate::resident_state::private_file(&path, true, &root).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"short");

    fixture_file(&path, b"");
    assert!(fs::read(&path).unwrap().is_empty());
    #[cfg(windows)]
    crate::resident_state::verify_windows_private_path(&path, false, &root).unwrap();
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_dir_all(root).unwrap();
}
