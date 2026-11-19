use std::path::Path;

use super::*;

fn ask(op: &str, mut fields: Value) -> Value {
    fields["op"] = json!(op);
    dispatch(&fields).expect("a well-formed request")
}

fn reason(answer: &Value) -> &str {
    answer["error"]["reason"].as_str().unwrap_or("")
}

fn hook_file(root: &Path, mode: u32) -> PathBuf {
    let path = root.join("hook.py");
    fs::write(&path, b"print('hook')\n").expect("fixture written");
    set_mode(&path, mode);
    path
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode set");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

fn regular(path: &Path, executable_required: bool) -> Value {
    json!({ "path": path, "role": "hook", "executable_required": executable_required })
}

#[test]
fn a_described_file_verifies_until_its_content_changes() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let path = hook_file(root.path(), 0o600);

    let described = ask("describe_regular", regular(&path, false));
    let identity = described["identity"].clone();
    assert_eq!(described["ok"], json!(true));
    assert_eq!(identity["role"], json!("hook"));
    assert_eq!(identity["size"], json!(14));

    let verified = ask("verify_regular", json!({ "identity": identity }));
    assert_eq!(verified, json!({ "ok": true }));

    fs::write(&path, b"print('HOOK')\n").expect("fixture rewritten");
    set_mode(&path, 0o600);
    let changed = ask("verify_regular", json!({ "identity": identity }));
    assert_eq!(reason(&changed), "codex_hook_hook_hash_mismatch");
    assert_eq!(
        changed["error"]["message"],
        json!("The Codex hook hook content changed; repair the installation.")
    );
}

#[test]
fn a_missing_file_and_a_symlink_are_refused() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let missing = ask("validate", regular(&root.path().join("absent.py"), false));
    assert_eq!(reason(&missing), "codex_hook_hook_missing");

    #[cfg(unix)]
    {
        let path = hook_file(root.path(), 0o600);
        let link = root.path().join("link.py");
        std::os::unix::fs::symlink(&path, &link).expect("link created");
        let linked = ask("validate", regular(&link, false));
        assert_eq!(reason(&linked), "codex_hook_hook_not_regular");
        assert_eq!(
            linked["error"]["message"],
            json!(
                "The Codex hook hook must be a regular file, not a symlink; repair the installation."
            )
        );
    }
}

#[cfg(unix)]
#[test]
fn unix_permission_rules_are_applied() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let path = hook_file(root.path(), 0o666);
    let world = ask("validate", regular(&path, false));
    assert_eq!(reason(&world), "codex_hook_hook_permissions_unsafe");

    set_mode(&path, 0o600);
    let plain = ask("validate", regular(&path, true));
    assert_eq!(reason(&plain), "codex_hook_hook_not_executable");

    set_mode(&path, 0o700);
    assert_eq!(ask("validate", regular(&path, true)), json!({ "ok": true }));

    // A group-writable hook outside every package root is never trusted,
    // whatever the group says.
    set_mode(&path, 0o660);
    let group = ask("validate", regular(&path, false));
    assert_eq!(reason(&group), "codex_hook_hook_permissions_unsafe");
}

#[cfg(unix)]
#[test]
fn a_group_writable_package_file_turns_on_its_group() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let path = hook_file(root.path(), 0o660);
    let facts = fs::metadata(&path).expect("fixture metadata");
    let private = {
        use std::os::unix::fs::MetadataExt;
        private_group(&json!({ "owner_uid": facts.uid(), "group_gid": facts.gid() }))
    };
    let mut request = regular(&path, false);
    request["package_roots"] = json!([root.path()]);
    let answer = ask("validate", request);
    if private {
        assert_eq!(answer, json!({ "ok": true }));
    } else {
        assert_eq!(reason(&answer), "codex_hook_hook_permissions_unsafe");
    }
}

#[test]
fn an_identity_that_is_not_an_object_is_refused() {
    let regular = ask("verify_regular", json!({ "identity": "nope" }));
    assert_eq!(reason(&regular), "codex_hook_file_identity_invalid");
    assert_eq!(
        regular["error"]["message"],
        json!(
            "The Codex hook manifest has an invalid packaged-file identity; repair the installation."
        )
    );
    let executable = ask("verify_executable", json!({ "identity": null }));
    assert_eq!(
        reason(&executable),
        "codex_hook_interpreter_identity_invalid"
    );
}

#[test]
fn malformed_requests_are_refused() {
    assert_eq!(dispatch(&json!([])), Err(ERR_INVALID));
    assert_eq!(dispatch(&json!({ "op": "other" })), Err(ERR_INVALID));
    assert_eq!(
        dispatch(&json!({ "op": "validate", "path": "/x", "role": "hook" })),
        Err(ERR_INVALID)
    );
    assert_eq!(
        dispatch(&json!({ "op": "verify_regular", "package_roots": "/x" })),
        Err(ERR_INVALID)
    );
}

#[test]
fn a_replaced_file_no_longer_matches_the_fingerprint_taken_before_the_checks() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let path = hook_file(root.path(), 0o600);
    let print = |path: &Path| fingerprint(path).expect("the file exists");
    let before = print(&path);
    assert_eq!(
        before,
        print(&path),
        "an untouched file keeps its fingerprint"
    );

    fs::write(&path, b"print('replaced hook')\n").expect("fixture rewritten");
    assert_ne!(before, print(&path), "new content must change it");

    let roots: Vec<PathBuf> = Vec::new();
    assert!(validate(&path, "hook", false, &roots).is_ok());
    assert_eq!(
        validate(&root.path().join("absent.py"), "hook", false, &roots),
        Err("codex_hook_hook_missing".to_owned())
    );
}
