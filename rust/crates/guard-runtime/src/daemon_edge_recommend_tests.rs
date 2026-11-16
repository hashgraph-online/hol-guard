use serde_json::json;

use super::*;

fn pending(extra: Value) -> Map<String, Value> {
    let mut row = json!({"request_id": "r1", "status": "pending"});
    for (key, value) in extra.as_object().unwrap() {
        row[key] = value.clone();
    }
    row.as_object().unwrap().clone()
}

fn view(health: &str, revision: u64, managed: u64) -> ApprovalExtensionControlViewV1 {
    serde_json::from_value(json!({
        "snapshot": {"health": health, "revision": revision, "catalog_digest": "d", "layers": []},
        "managed_revision": managed,
        "registry_catalog_digest": "d",
    }))
    .unwrap()
}

#[test]
fn only_a_protected_or_never_enrolled_authority_admits_a_live_hint() {
    assert!(hint_authority_admitted(&view("protected", 4, 2)));
    assert!(hint_authority_admitted(&view("unenrolled", 0, 0)));
    assert!(!hint_authority_admitted(&view("unenrolled", 1, 0)));
    assert!(!hint_authority_admitted(&view("unenrolled", 0, 3)));
    assert!(!hint_authority_admitted(&view("degraded", 4, 2)));
}

#[test]
fn a_resolved_or_non_shell_row_is_not_reviewed_again() {
    let mut resolved = pending(json!({"raw_command_text": "git status"}));
    resolved.insert("status".into(), json!("approved"));
    assert_eq!(live_reviewed_command(&resolved, None), None);
    let file = pending(json!({
        "raw_command_text": "git status",
        "action_envelope_json": {"action_type": "file_write"},
    }));
    assert_eq!(live_reviewed_command(&file, None), None);
}

#[test]
fn the_command_falls_back_to_the_envelope() {
    let row = pending(json!({
        "raw_command_text": "  ",
        "action_envelope_json": {"action_type": "shell_command", "command": "git log"},
    }));
    assert_eq!(
        live_reviewed_command(&row, None),
        Some(("git log".to_owned(), None))
    );
    assert_eq!(live_reviewed_command(&pending(json!({})), None), None);
}

#[test]
fn a_tool_input_carrying_content_is_not_reviewed_as_a_command() {
    let row = pending(json!({
        "raw_command_text": "git status",
        "action_envelope_json": {"raw_payload_redacted": {
            "tool_input": {"command": "git status", "content": "x"},
        }},
    }));
    assert_eq!(live_reviewed_command(&row, None), None);
}

#[test]
fn a_named_directory_that_cannot_be_traced_back_recovers_nothing() {
    let row = pending(json!({
        "raw_command_text": "git status",
        "action_envelope_json": {"raw_payload_redacted": {
            "tool_input": {"command": "git status"},
            "cwd": "project",
        }},
    }));
    assert_eq!(live_reviewed_command(&row, None), None);
}

#[test]
fn a_home_relative_directory_expands_against_the_home() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir(home.path().join("work")).unwrap();
    let row = pending(json!({
        "raw_command_text": "git status",
        "action_envelope_json": {"raw_payload_redacted": {
            "toolInput": {"command": "git status", "cwd": "~/work"},
            "cwd": "~/work",
        }},
    }));
    let (_, cwd) = live_reviewed_command(&row, Some(home.path())).unwrap();
    assert_eq!(
        cwd,
        Some(std::fs::canonicalize(home.path().join("work")).unwrap())
    );
}

#[test]
fn without_a_payload_the_workspace_is_the_launch_directory() {
    let workspace = tempfile::tempdir().unwrap();
    let row = pending(json!({
        "raw_command_text": "git status",
        "workspace": workspace.path().to_string_lossy(),
    }));
    let (_, cwd) = live_reviewed_command(&row, None).unwrap();
    assert_eq!(cwd, Some(std::fs::canonicalize(workspace.path()).unwrap()));
    let relative = pending(json!({"raw_command_text": "ls", "workspace": "rel"}));
    assert_eq!(
        live_reviewed_command(&relative, None),
        Some(("ls".to_owned(), None))
    );
}

#[test]
fn a_resident_answer_binds_to_its_request() {
    let request = json!({"schema": "s", "request_id": "q1"});
    let answer = |status: &str, id: &str, sha: &str| {
        json!({
            "schema": "result", "request_id": id, "request_sha256": sha,
            "status": status, "payload": {"kind": "x"},
        })
    };
    assert_eq!(
        bound_payload(
            answer("ok", "q1", "sha256:a"),
            &request,
            "sha256:a",
            "result"
        ),
        Some(json!({"kind": "x"}).as_object().unwrap().clone())
    );
    assert_eq!(
        bound_payload(
            answer("ok", "q2", "sha256:a"),
            &request,
            "sha256:a",
            "result"
        ),
        None
    );
    assert_eq!(
        bound_payload(
            answer("ok", "q1", "sha256:b"),
            &request,
            "sha256:a",
            "result"
        ),
        None
    );
    assert_eq!(
        bound_payload(
            answer("error", "q1", "sha256:a"),
            &request,
            "sha256:a",
            "result"
        ),
        None
    );
    assert_eq!(
        bound_payload(
            answer("ok", "q1", "sha256:a"),
            &request,
            "sha256:a",
            "other"
        ),
        None
    );
}

#[test]
fn a_non_object_hint_has_no_shape() {
    assert_eq!(shape(&Value::Null, "allow"), None);
    assert_eq!(shape(&json!([1]), "coverage"), None);
}
