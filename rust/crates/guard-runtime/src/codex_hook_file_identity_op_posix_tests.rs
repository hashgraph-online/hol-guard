//! The ownership and permission rules only POSIX hosts carry.
//!
//! `#[cfg(unix)]` sits on the `mod posix` declaration in
//! `codex_hook_file_identity_op_tests.rs`, not on a `#![cfg(unix)]` here, so
//! the gate stays where the module is named and a Windows build still reads
//! the module list.

use super::*;

#[test]
fn a_world_writable_file_is_refused_without_asking_about_its_group() {
    let fixture = Fixture::new(0o666);

    let answer = answer_to(&request(fixture.identity(), None));

    assert_eq!(answer["kind"], json!("permissions_unsafe"));
    assert_eq!(answer.get("private_group_question"), None);
}

#[test]
fn a_group_writable_config_target_carries_the_private_group_question() {
    let fixture = Fixture::new(0o664);

    let answer = answer_to(&request(fixture.identity(), None));

    // The file is otherwise exactly what the manifest describes, so the
    // only thing left between it and a verified answer is whether its
    // group is private to its owner - which the caller answers.
    assert_eq!(answer["outcome"], json!("verified"));
    assert_eq!(
        answer["private_group_question"]["owner_uid"],
        json!(fixture.uid())
    );
}

#[test]
fn a_group_writable_file_of_another_role_is_refused_outright() {
    let fixture = Fixture::new(0o664);
    let mut identity = fixture.identity();
    identity["role"] = json!("hook");

    let answer = answer_to(&request(identity, None));

    assert_eq!(answer["kind"], json!("permissions_unsafe"));
    assert_eq!(answer.get("private_group_question"), None);
}

#[test]
fn a_group_writable_interpreter_the_asker_owns_needs_no_question() {
    let fixture = Fixture::new(0o775);
    let mut identity = fixture.identity();
    identity["role"] = json!("interpreter");

    let answer = answer_to(&request(identity, None));

    assert_eq!(answer["outcome"], json!("verified"));
    assert_eq!(answer.get("private_group_question"), None);
}

#[test]
fn a_group_writable_package_file_carries_the_question_the_caller_asked_for() {
    let fixture = Fixture::new(0o664);
    let mut identity = fixture.identity();
    identity["role"] = json!("hook");
    let mut request = request(identity, None);
    request.questions[0].installed_python_package_file = true;

    let answer = answer_to(&request);

    assert_eq!(answer["outcome"], json!("verified"));
    assert!(answer["private_group_question"].is_object());
}

#[test]
fn a_question_still_rides_along_with_a_later_failure() {
    let fixture = Fixture::new(0o664);
    let mut identity = fixture.identity();
    identity["sha256"] = json!("0".repeat(64));

    let answer = answer_to(&request(identity, None));

    // The caller refuses the file either way, but it refuses it for the
    // reason Python reached first, which is the unproven group.
    assert_eq!(answer["kind"], json!("hash_mismatch"));
    assert!(answer["private_group_question"].is_object());
}

#[test]
fn a_file_owned_by_nobody_the_asker_trusts_is_untrusted() {
    let fixture = Fixture::new(0o644);
    let mut request = request(fixture.identity(), None);
    // A uid that is neither the fixture's owner nor root, so the file
    // belongs to someone this process has no reason to trust.
    request.current_uid = Some(fixture.uid() + 7);

    let answer = answer_to(&request);
    // Running as root the file is root's, and root is trusted whoever
    // asks, so there is no untrusted owner to find.
    let expected = if fixture.uid() == 0 {
        json!("verified")
    } else {
        json!("failed")
    };

    assert_eq!(answer["outcome"], expected);
    if fixture.uid() != 0 {
        assert_eq!(answer["kind"], json!("owner_untrusted"));
    }
}

#[test]
fn a_file_the_manifest_says_another_user_owns_is_an_owner_mismatch() {
    let fixture = Fixture::new(0o644);
    let mut identity = fixture.identity();
    identity["owner_uid"] = json!(fixture.uid().wrapping_add(7));

    assert_eq!(
        answer_to(&request(identity, None))["kind"],
        json!("owner_mismatch")
    );
}

#[test]
fn a_boolean_owner_compares_against_uid_one() {
    let fixture = Fixture::new(0o644);
    let mut identity = fixture.identity();
    // `isinstance(True, int)` is true in Python, so a manifest holding a
    // boolean here compares the live uid against 1 rather than skipping
    // the check. The port keeps that reading.
    identity["owner_uid"] = json!(true);

    let answer = answer_to(&request(identity, None));
    let expected = if fixture.uid() == 1 {
        json!("verified")
    } else {
        json!("failed")
    };

    assert_eq!(answer["outcome"], expected);
}

#[test]
fn a_file_without_an_execute_bit_is_not_executable_when_one_is_required() {
    let fixture = Fixture::new(0o644);
    let mut identity = fixture.identity();
    identity["executable_required"] = json!(true);

    assert_eq!(
        answer_to(&request(identity, None))["kind"],
        json!("not_executable")
    );
}

#[test]
fn a_symlink_standing_where_a_file_belongs_is_not_regular() {
    let fixture = Fixture::new(0o644);
    let link = fixture.path.with_file_name("link.py");
    std::os::unix::fs::symlink(&fixture.path, &link).expect("the fixture symlink");
    let mut identity = fixture.identity();
    identity["path"] = json!(link.to_str().expect("a printable fixture path"));

    assert_eq!(
        answer_to(&request(identity, None))["kind"],
        json!("not_regular")
    );
}

#[test]
fn a_pipe_standing_where_a_file_belongs_is_not_regular() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let path = root.path().join("hook.py");
    let status = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo runs");
    assert!(status.success(), "the fixture pipe");
    let identity = json!({
        "role": "config_target",
        "path": path.to_str().expect("a printable fixture path"),
        "sha256": CONTENT_SHA256,
        "mode": 0o644,
        "size": CONTENT.len(),
    });

    // The name check refuses it before the open, and the open refuses it
    // again without waiting for the writer a pipe would otherwise block on.
    assert_eq!(
        answer_to(&request(identity, None))["kind"],
        json!("not_regular")
    );
}
