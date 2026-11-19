use std::fs;

use serde_json::Value;

use super::{answer, key_path, read_matching};

fn home() -> tempfile::TempDir {
    tempfile::tempdir().expect("home")
}

fn ask(op: &str, home: &tempfile::TempDir) -> Value {
    answer(op, home.path().to_str().expect("utf-8 home")).expect("known op")
}

#[test]
fn ensure_creates_one_private_key_and_answers_only_its_identity() {
    let home = home();
    let first = ask("key_ensure", &home);
    let again = ask("key_ensure", &home);
    assert_eq!(first, again);
    assert_eq!(first, ask("key_identity", &home));
    let object = first.as_object().expect("identity");
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["fingerprint", "installation_id", "key_id"]);
    assert_eq!(first["installation_id"].as_str().map(str::len), Some(32));
    assert_eq!(first["key_id"].as_str().map(str::len), Some(24));
    let stored = fs::read_to_string(key_path(home.path())).expect("key");
    assert!(stored.ends_with("}\n"));
    assert!(!stored.contains(first["fingerprint"].as_str().expect("fingerprint")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(key_path(home.path()))
            .expect("key")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn a_key_written_by_earlier_releases_still_reads() {
    let home = home();
    let path = key_path(home.path());
    fs::create_dir_all(path.parent().expect("dir")).expect("dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path.parent().expect("dir"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("mode");
    }
    let key = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=";
    let text = format!(
        "{{\"installation_id\":\"{}\",\"key\":\"{key}\",\"key_id\":\"{}\",\"schema_version\":1}}\n",
        "1".repeat(32),
        "2".repeat(24)
    );
    fs::write(&path, text).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    }
    let identity = ask("key_identity", &home);
    assert_eq!(identity["key_id"], "2".repeat(24));
    let held = read_matching(
        home.path().to_str().expect("home"),
        Some(&"2".repeat(24)),
        None,
    )
    .expect("key");
    assert_eq!(held.key.as_slice(), b"k".repeat(32).as_slice());
}

#[test]
fn a_missing_or_mismatched_key_is_refused_with_its_reason() {
    let home = home();
    assert_eq!(
        ask("key_identity", &home)["error"],
        "codex_hook_manifest_secret_missing"
    );
    ask("key_ensure", &home);
    let text = home.path().to_str().expect("home");
    assert_eq!(
        read_matching(text, Some("other"), None).err(),
        Some("codex_hook_manifest_key_mismatch")
    );
    assert_eq!(
        read_matching(text, None, Some("other")).err(),
        Some("codex_hook_manifest_key_mismatch")
    );
    assert_eq!(
        read_matching("relative", None, None).err(),
        Some("codex_hook_manifest_secret_invalid")
    );
}

#[cfg(unix)]
#[test]
fn a_shared_key_file_or_a_link_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let home = home();
    ask("key_ensure", &home);
    let path = key_path(home.path());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode");
    assert_eq!(
        ask("key_identity", &home)["error"],
        "codex_hook_manifest_secret_permissions_unsafe"
    );
    let target = home.path().join("elsewhere");
    fs::rename(&path, &target).expect("move");
    std::os::unix::fs::symlink(&target, &path).expect("link");
    assert_eq!(
        ask("key_identity", &home)["error"],
        "codex_hook_manifest_secret_not_regular"
    );
}

#[test]
fn the_key_stays_while_a_manifest_needs_it() {
    let home = home();
    ask("key_ensure", &home);
    let manifest = key_path(home.path()).with_file_name("hooks-abc.manifest.json");
    fs::write(&manifest, "{}").expect("manifest");
    assert_eq!(ask("key_remove_if_unused", &home)["removed"], false);
    fs::remove_file(manifest).expect("remove");
    assert_eq!(ask("key_remove_if_unused", &home)["removed"], true);
    assert!(!key_path(home.path()).exists());
    assert_eq!(ask("key_remove_if_unused", &home)["removed"], false);
}
