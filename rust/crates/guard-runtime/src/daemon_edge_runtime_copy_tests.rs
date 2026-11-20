use super::*;

/// A fresh fixture folder. On Windows only a Guard home under the user's
/// profile keeps a copy, and the temporary folder may sit elsewhere.
fn fixture_dir() -> tempfile::TempDir {
    #[cfg(windows)]
    {
        let profile = PathBuf::from(std::env::var_os("USERPROFILE").expect("USERPROFILE"));
        tempfile::Builder::new()
            .prefix("guard-runtime-copy-")
            .tempdir_in(profile)
            .unwrap()
    }
    #[cfg(not(windows))]
    {
        tempfile::tempdir().unwrap()
    }
}

fn private_home() -> (tempfile::TempDir, PathBuf) {
    let base = fixture_dir();
    let home = base.path().join(".hol-guard");
    create_private_directory(&home).unwrap();
    (base, home)
}

fn runtime(base: &Path, bytes: &[u8]) -> PathBuf {
    let path = base.join("source-runtime");
    fs::write(&path, bytes).unwrap();
    path
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn a_fresh_home_gets_the_copy_the_host_looks_for() {
    let (base, home) = private_home();
    let bytes = b"runtime image bytes".repeat(1000);
    let source = runtime(base.path(), &bytes);

    let copy = place(&home, &source).expect("copy placed");

    let expected = home
        .join(PRIVATE_ROOT_NAME)
        .join(format!("{KEPT_PREFIX}{}", digest(&bytes)))
        .join(EXECUTABLE_NAME);
    assert_eq!(copy, expected);
    assert_eq!(fs::read(&copy).unwrap(), bytes);
    // Nothing but the kept copy is left in the private folder.
    let names: Vec<_> = fs::read_dir(home.join(PRIVATE_ROOT_NAME))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, [format!("{KEPT_PREFIX}{}", digest(&bytes))]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let folder = copy.parent().unwrap();
        assert_eq!(
            fs::metadata(folder).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let root = home.join(PRIVATE_ROOT_NAME);
        assert_eq!(
            fs::metadata(root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[test]
fn a_warm_start_leaves_the_copy_in_place_and_runs_nothing() {
    let (base, home) = private_home();
    let bytes = b"same runtime".to_vec();
    let source = runtime(base.path(), &bytes);
    let first = place(&home, &source).unwrap();
    let modified = fs::metadata(&first).unwrap().modified().unwrap();

    assert_eq!(place(&home, &source), None);

    assert_eq!(fs::read(&first).unwrap(), bytes);
    assert_eq!(fs::metadata(&first).unwrap().modified().unwrap(), modified);
}

#[cfg(unix)]
#[test]
fn a_linked_kept_folder_is_never_run_through() {
    let (base, home) = private_home();
    let bytes = b"runtime".to_vec();
    let source = runtime(base.path(), &bytes);
    let elsewhere = base.path().join("elsewhere");
    create_private_directory(&elsewhere).unwrap();
    fs::write(elsewhere.join(EXECUTABLE_NAME), &bytes).unwrap();
    let root = home.join(PRIVATE_ROOT_NAME);
    create_private_directory(&root).unwrap();
    std::os::unix::fs::symlink(
        &elsewhere,
        root.join(format!("{KEPT_PREFIX}{}", digest(&bytes))),
    )
    .unwrap();

    assert_eq!(place(&home, &source), None);
}

#[test]
fn a_different_copy_under_the_name_is_left_for_the_host_and_never_run() {
    let (base, home) = private_home();
    let bytes = b"verified runtime".to_vec();
    let source = runtime(base.path(), &bytes);
    let kept = home
        .join(PRIVATE_ROOT_NAME)
        .join(format!("{KEPT_PREFIX}{}", digest(&bytes)));
    create_private_directory(&home.join(PRIVATE_ROOT_NAME)).unwrap();
    create_private_directory(&kept).unwrap();
    fs::write(kept.join(EXECUTABLE_NAME), b"something else").unwrap();

    assert_eq!(place(&home, &source), None);
    assert_eq!(
        fs::read(kept.join(EXECUTABLE_NAME)).unwrap(),
        b"something else"
    );
}

#[cfg(unix)]
#[test]
fn a_guard_home_other_accounts_can_write_gets_no_copy() {
    use std::os::unix::fs::PermissionsExt;
    let (base, home) = private_home();
    let source = runtime(base.path(), b"runtime");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o770)).unwrap();

    assert_eq!(place(&home, &source), None);
    assert!(!home.join(PRIVATE_ROOT_NAME).exists());
}

#[cfg(unix)]
#[test]
fn an_open_private_folder_gets_no_copy() {
    use std::os::unix::fs::PermissionsExt;
    let (base, home) = private_home();
    let source = runtime(base.path(), b"runtime");
    let root = home.join(PRIVATE_ROOT_NAME);
    create_private_directory(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(place(&home, &source), None);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn a_linked_private_folder_gets_no_copy() {
    let (base, home) = private_home();
    let source = runtime(base.path(), b"runtime");
    let elsewhere = base.path().join("elsewhere");
    create_private_directory(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, home.join(PRIVATE_ROOT_NAME)).unwrap();

    assert_eq!(place(&home, &source), None);
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn a_directory_above_the_home_that_others_can_rename_in_gets_no_copy() {
    use std::os::unix::fs::PermissionsExt;
    let base = fixture_dir();
    let shared = base.path().join("shared");
    fs::create_dir(&shared).unwrap();
    // Group- and world-writable without the sticky bit.
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let home = shared.join(".hol-guard");
    create_private_directory(&home).unwrap();
    let source = runtime(base.path(), b"runtime");

    assert_eq!(place(&home, &source), None);
}

#[test]
fn a_test_home_is_never_primed() {
    assert!(super::super::resident_prewarm::ephemeral_home(Path::new(
        "/tmp/pytest-of-user/pytest-3/home/.hol-guard"
    )));
}

fn manifest(base: &Path, size: usize, digest: &str) {
    let body = serde_json::json!({"compiler_size": size, "compiler_sha256": digest});
    fs::write(base.join(MANIFEST_NAME), body.to_string()).unwrap();
}

#[test]
fn the_packaged_manifest_names_the_copy() {
    let (base, home) = private_home();
    let bytes = b"runtime named by its manifest".to_vec();
    let source = runtime(base.path(), &bytes);
    manifest(base.path(), bytes.len(), &digest(&bytes));

    let copy = place(&home, &source).expect("copy placed");

    assert_eq!(
        copy.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap(),
        format!("{KEPT_PREFIX}{}", digest(&bytes))
    );
    assert_eq!(fs::read(copy).unwrap(), bytes);
}

#[test]
fn a_manifest_digest_the_bytes_do_not_have_places_nothing() {
    let (base, home) = private_home();
    let bytes = b"runtime".to_vec();
    let source = runtime(base.path(), &bytes);
    let wrong = digest(b"another runtime");
    manifest(base.path(), bytes.len(), &wrong);

    assert_eq!(place(&home, &source), None);
    assert_eq!(
        fs::read_dir(home.join(PRIVATE_ROOT_NAME)).unwrap().count(),
        0
    );
}

#[test]
fn a_manifest_for_another_size_is_ignored() {
    let (base, home) = private_home();
    let bytes = b"runtime".to_vec();
    let source = runtime(base.path(), &bytes);
    manifest(base.path(), bytes.len() + 1, &digest(b"another runtime"));

    let copy = place(&home, &source).expect("copy placed from the bytes' own digest");

    assert_eq!(
        copy.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap(),
        format!("{KEPT_PREFIX}{}", digest(&bytes))
    );
}
