use std::fs;
use std::path::{Path, PathBuf};

use super::{load, load_or_create, parse, KEY_BYTES};

fn key_path(home: &Path) -> PathBuf {
    home.join("managed").join("adapter-state.key")
}

/// The file text the Python key writer produced, so a key created before the
/// move keeps signing.
const PYTHON_KEY: &str = "{\"key\": \"a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=\", \"key_id\": \"race-key\", \"schema_version\": 1}\n";

#[test]
fn creates_a_key_once_and_reloads_it() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard-home");

    let created = load_or_create(&guard_home).expect("created");
    let again = load_or_create(&guard_home).expect("reused");
    let loaded = load(&guard_home).expect("loaded");

    assert_eq!(created.bytes.len(), KEY_BYTES);
    assert_eq!(created.id.len(), 24);
    assert_eq!(
        (again.id.as_str(), &again.bytes),
        (created.id.as_str(), &created.bytes)
    );
    assert_eq!(
        (loaded.id.as_str(), &loaded.bytes),
        (created.id.as_str(), &created.bytes)
    );
    let text = fs::read_to_string(key_path(&guard_home)).expect("text");
    assert!(text.starts_with("{\"key\": \"") && text.ends_with("\"schema_version\": 1}\n"));
}

#[test]
fn reads_a_key_the_python_writer_stored() {
    let home = tempfile::tempdir().expect("home");
    fs::create_dir_all(home.path().join("managed")).expect("managed");
    fs::write(key_path(home.path()), PYTHON_KEY).expect("key");
    private(home.path());

    let key = load(home.path()).expect("loaded");

    assert_eq!(key.id, "race-key");
    assert_eq!(key.bytes, vec![b'k'; KEY_BYTES]);
}

#[test]
fn a_missing_key_is_not_created_by_a_read() {
    let home = tempfile::tempdir().expect("home");

    assert!(load(home.path()).is_err());
    assert!(!home.path().join("managed").exists());
}

#[test]
fn a_managed_path_that_is_a_file_holds_no_key() {
    let home = tempfile::tempdir().expect("home");
    fs::write(home.path().join("managed"), "not a directory").expect("file");

    assert!(load(home.path()).is_err());
    assert!(load_or_create(home.path()).is_err());
}

#[test]
fn malformed_key_files_are_refused() {
    let home = tempfile::tempdir().expect("home");
    fs::create_dir_all(home.path().join("managed")).expect("managed");
    let oversized = format!("{{\"pad\": \"{}\"}}", "x".repeat(16_384));
    for raw in [&b"not utf-8: \xff"[..], b"[]", b"{", oversized.as_bytes()] {
        fs::write(key_path(home.path()), raw).expect("key");
        private(home.path());
        assert!(load(home.path()).is_err());
        assert!(load_or_create(home.path()).is_err());
    }
}

#[test]
fn malformed_key_material_is_refused() {
    let short = "c2hvcnQ=";
    for document in [
        "{}".to_owned(),
        "{\"schema_version\": 2, \"key_id\": \"id\", \"key\": \"\"}".to_owned(),
        "{\"schema_version\": true, \"key_id\": \"id\"}".to_owned(),
        "{\"schema_version\": 1, \"key_id\": \"\"}".to_owned(),
        "{\"schema_version\": 1, \"key_id\": \"id\"}".to_owned(),
        "{\"schema_version\": 1, \"key_id\": \"id\", \"key\": 7}".to_owned(),
        "{\"schema_version\": 1, \"key_id\": \"id\", \"key\": \"%%%\"}".to_owned(),
        format!("{{\"schema_version\": 1, \"key_id\": \"id\", \"key\": \"{short}\"}}"),
    ] {
        assert!(parse(document.as_bytes()).is_err(), "{document}");
    }
    assert!(parse(PYTHON_KEY.as_bytes()).is_ok());
}

#[cfg(unix)]
fn private(home: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(home.join("managed"), fs::Permissions::from_mode(0o700)).expect("dir");
    fs::set_permissions(key_path(home), fs::Permissions::from_mode(0o600)).expect("key");
}

#[cfg(not(unix))]
fn private(_home: &Path) {}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::{key_path, load, load_or_create, private, PYTHON_KEY};

    fn mode(path: &std::path::Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn a_created_key_is_owner_only() {
        let home = tempfile::tempdir().expect("home");
        fs::create_dir_all(home.path().join("managed")).expect("managed");
        fs::set_permissions(
            home.path().join("managed"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("open folder");

        load_or_create(home.path()).expect("created");

        assert_eq!(mode(&home.path().join("managed")), 0o700);
        assert_eq!(mode(&key_path(home.path())), 0o600);
    }

    #[test]
    fn a_folder_others_can_read_signs_nothing() {
        let home = tempfile::tempdir().expect("home");
        fs::create_dir_all(home.path().join("managed")).expect("managed");
        fs::write(key_path(home.path()), PYTHON_KEY).expect("key");
        private(home.path());
        fs::set_permissions(
            home.path().join("managed"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("open folder");

        assert!(load(home.path()).is_err());
    }

    #[test]
    fn a_key_others_can_read_signs_nothing() {
        let home = tempfile::tempdir().expect("home");
        fs::create_dir_all(home.path().join("managed")).expect("managed");
        fs::write(key_path(home.path()), PYTHON_KEY).expect("key");
        private(home.path());
        fs::set_permissions(key_path(home.path()), fs::Permissions::from_mode(0o644))
            .expect("open key");

        assert!(load(home.path()).is_err());
        assert!(load_or_create(home.path()).is_err());
    }

    #[test]
    fn links_are_never_followed() {
        let elsewhere = tempfile::tempdir().expect("elsewhere");
        fs::create_dir_all(elsewhere.path().join("managed")).expect("managed");
        fs::write(key_path(elsewhere.path()), PYTHON_KEY).expect("key");
        private(elsewhere.path());

        let linked_folder = tempfile::tempdir().expect("linked folder");
        symlink(
            elsewhere.path().join("managed"),
            linked_folder.path().join("managed"),
        )
        .expect("folder link");
        assert!(load(linked_folder.path()).is_err());
        assert!(load_or_create(linked_folder.path()).is_err());

        let linked_key = tempfile::tempdir().expect("linked key");
        fs::create_dir_all(linked_key.path().join("managed")).expect("managed");
        fs::set_permissions(
            linked_key.path().join("managed"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("private");
        symlink(key_path(elsewhere.path()), key_path(linked_key.path())).expect("key link");
        assert!(load(linked_key.path()).is_err());
        assert!(load_or_create(linked_key.path()).is_err());
    }
}
