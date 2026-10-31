use std::fs;
use std::path::Path;

use base64ct::{Base64, Encoding};
use serde_json::{json, Value};

use super::{run_command, ACK_NAME, MAX_ACK_BYTES, OUTBOX_NAME};

fn state_root() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap().join("state");
    fs::create_dir(&root).unwrap();
    (directory, root)
}

/// The owner of the nearest directory that exists: the account running the
/// tests.
#[cfg(unix)]
fn owner(root: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;

    root.ancestors()
        .find_map(|ancestor| fs::metadata(ancestor).ok())
        .unwrap()
        .uid()
}

#[cfg(not(unix))]
fn owner(_root: &Path) -> u32 {
    0
}

fn request(root: &Path, op: &str, kind: &str) -> Value {
    json!({
        "schema": "health-lease-state.v1",
        "op": op,
        "kind": kind,
        "state_root": root,
        "owner_uid": owner(root),
    })
}

fn carrying(mut request: Value, bytes: &[u8]) -> Value {
    request["content"] = json!(Base64::encode_string(bytes));
    request
}

fn run(request: &Value) -> Result<Value, String> {
    run_command(serde_json::to_vec(request).unwrap().as_slice())
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

fn answer(root: &Path, op: &str, kind: &str) -> Value {
    run(&request(root, op, kind)).unwrap()
}

fn write(root: &Path, op: &str, kind: &str, bytes: &[u8]) -> Value {
    run(&carrying(request(root, op, kind), bytes)).unwrap()
}

fn read(root: &Path, kind: &str) -> Value {
    answer(root, "read", kind)
}

fn refused(class: &str, reason_code: &str) -> Value {
    json!({"ok": false, "error_class": class, "reason_code": reason_code})
}

fn content(bytes: &[u8]) -> Value {
    json!({"ok": true, "content": Base64::encode_string(bytes)})
}

fn names(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_file_that_was_never_written_reads_as_absent() {
    let (_directory, root) = state_root();

    assert_eq!(read(&root, "outbox"), json!({"ok": true, "content": null}));
    assert_eq!(read(&root, "ack"), json!({"ok": true, "content": null}));
}

#[test]
fn a_created_outbox_reads_back_and_leaves_no_temporary_file() {
    let (_directory, root) = state_root();

    assert_eq!(
        write(&root, "create", "outbox", b"{\"a\":1}"),
        json!({"ok": true})
    );

    assert_eq!(read(&root, "outbox"), content(b"{\"a\":1}"));
    assert_eq!(names(&root), vec![OUTBOX_NAME.to_owned()]);
}

#[test]
fn a_pending_outbox_is_never_overwritten() {
    let (_directory, root) = state_root();
    write(&root, "create", "outbox", b"first");

    let second = write(&root, "create", "outbox", b"second");

    assert_eq!(second, refused("exists", "health_lease_pending_conflict"));
    assert_eq!(read(&root, "outbox"), content(b"first"));
    assert_eq!(names(&root), vec![OUTBOX_NAME.to_owned()]);
}

#[test]
fn an_acknowledgement_is_replaced_in_place() {
    let (_directory, root) = state_root();
    write(&root, "replace", "ack", b"first");

    assert_eq!(
        write(&root, "replace", "ack", b"second"),
        json!({"ok": true})
    );

    assert_eq!(read(&root, "ack"), content(b"second"));
    assert_eq!(names(&root), vec![ACK_NAME.to_owned()]);
}

#[test]
fn a_retired_outbox_is_gone_and_retiring_it_again_succeeds() {
    let (_directory, root) = state_root();
    write(&root, "create", "outbox", b"pending");

    assert_eq!(answer(&root, "remove", "outbox"), json!({"ok": true}));
    assert_eq!(answer(&root, "remove", "outbox"), json!({"ok": true}));

    assert_eq!(read(&root, "outbox"), json!({"ok": true, "content": null}));
}

#[test]
fn a_write_needs_a_real_state_root() {
    let (directory, root) = state_root();
    let missing = root.join("missing");
    let invalid = refused("os", "health_lease_state_root_invalid");

    assert_eq!(write(&missing, "create", "outbox", b"x"), invalid);
    assert_eq!(write(&missing, "replace", "ack", b"x"), invalid);
    #[cfg(unix)]
    {
        let linked = directory.path().join("linked");
        std::os::unix::fs::symlink(&root, &linked).unwrap();
        assert_eq!(write(&linked, "create", "outbox", b"x"), invalid);
        assert!(names(&root).is_empty());
    }
    #[cfg(not(unix))]
    let _ = directory;
}

#[test]
fn an_acknowledgement_past_its_bound_is_refused() {
    let (_directory, root) = state_root();
    let oversized = vec![b'a'; usize::try_from(MAX_ACK_BYTES).unwrap() + 1];
    write(&root, "replace", "ack", &oversized);

    assert_eq!(
        read(&root, "ack"),
        refused("permission", "health_lease_ack_acl_invalid")
    );
}

#[test]
fn a_request_outside_the_two_files_and_their_writes_is_refused() {
    let (_directory, root) = state_root();
    let mut wrong_schema = request(&root, "read", "ack");
    wrong_schema["schema"] = json!("health-lease-state.v0");
    let mut extra = request(&root, "read", "ack");
    extra["path"] = json!("/etc/passwd");

    for rejected in [
        carrying(request(&root, "replace", "outbox"), b"x"),
        carrying(request(&root, "create", "ack"), b"x"),
        request(&root, "remove", "ack"),
        carrying(request(&root, "read", "ack"), b"x"),
        request(&root, "create", "outbox"),
        request(&root, "read", "continuity"),
        wrong_schema,
        extra,
    ] {
        assert_eq!(
            run(&rejected),
            Err("health_lease_state_request_invalid".to_owned()),
            "{rejected}"
        );
    }
    let mut undecodable = request(&root, "create", "outbox");
    undecodable["content"] = json!("not base64!");
    assert!(run(&undecodable).is_err());
    assert!(names(&root).is_empty());
}

#[cfg(unix)]
#[test]
fn written_files_are_private_to_their_owner() {
    use std::os::unix::fs::PermissionsExt;

    let (_directory, root) = state_root();
    write(&root, "create", "outbox", b"pending");
    write(&root, "replace", "ack", b"ack");

    for name in [OUTBOX_NAME, ACK_NAME] {
        let mode = fs::metadata(root.join(name)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
}

#[cfg(unix)]
#[test]
fn a_file_others_may_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let (_directory, root) = state_root();
    write(&root, "create", "outbox", b"pending");
    fs::set_permissions(root.join(OUTBOX_NAME), fs::Permissions::from_mode(0o640)).unwrap();

    assert_eq!(
        read(&root, "outbox"),
        refused("permission", "health_lease_outbox_acl_invalid")
    );
}

#[cfg(unix)]
#[test]
fn a_file_of_another_owner_is_refused() {
    let (_directory, root) = state_root();
    write(&root, "replace", "ack", b"ack");
    let mut foreign = request(&root, "read", "ack");
    foreign["owner_uid"] = json!(owner(&root).wrapping_add(1));

    assert_eq!(
        run(&foreign).unwrap(),
        refused("permission", "health_lease_ack_acl_invalid")
    );
}

#[cfg(unix)]
#[test]
fn a_linked_file_is_refused() {
    let (directory, root) = state_root();
    let elsewhere = directory.path().join("elsewhere.json");
    fs::write(&elsewhere, b"{}").unwrap();
    std::os::unix::fs::symlink(&elsewhere, root.join(ACK_NAME)).unwrap();

    assert_eq!(
        read(&root, "ack"),
        refused("permission", "health_lease_ack_acl_invalid")
    );
}

#[cfg(unix)]
#[test]
fn a_planted_link_is_never_written_through() {
    let (directory, root) = state_root();
    let elsewhere = directory.path().join("elsewhere.json");
    fs::write(&elsewhere, b"original").unwrap();
    std::os::unix::fs::symlink(&elsewhere, root.join(OUTBOX_NAME)).unwrap();

    assert_eq!(
        write(&root, "create", "outbox", b"pending"),
        refused("exists", "health_lease_pending_conflict")
    );
    assert_eq!(fs::read(&elsewhere).unwrap(), b"original");
}

#[cfg(not(unix))]
#[test]
fn a_regular_file_reads_back_without_owner_bits() {
    let (_directory, root) = state_root();
    write(&root, "create", "outbox", b"pending");
    let mut any_owner = request(&root, "read", "outbox");
    any_owner["owner_uid"] = json!(4242);

    assert_eq!(run(&any_owner).unwrap(), content(b"pending"));
}
