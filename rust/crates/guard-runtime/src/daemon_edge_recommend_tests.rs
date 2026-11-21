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

fn coverage_hint(digest: &str) -> Value {
    json!({
        "schema": "guard.extension-coverage-hint.v1",
        "catalog_digest": digest,
        "segment_total": 1,
        "segments": [{
            "index": 0,
            "executable": "git",
            "extension_ids": ["command.git"],
            "rule_ids": ["command.git.example"],
            "permission_ids": [],
        }],
    })
}

fn allow_hint() -> Value {
    json!({
        "schema": "guard.extension-allow-hint.v1",
        "permission_ids": ["command.git.permission.example"],
        "rule_ids": ["command.git.example"],
        "extension_ids": ["command.git"],
        "relied_permission_ids": [],
        "catalog_digest": "b".repeat(64),
    })
}

#[test]
fn stored_coverage_stays_attached_to_a_recovered_allow() {
    let stored = coverage_hint(&"a".repeat(64));
    let mut live = allow_hint();
    live["coverage"] = coverage_hint(&"c".repeat(64));

    let result = recovered(stored.clone(), || Some(live));

    assert_eq!(shape(&result, "allow"), shape(&allow_hint(), "allow"));
    assert_eq!(shape(&result, "coverage"), Some(stored));
}

#[test]
fn existing_settlement_and_connector_hints_skip_recovery() {
    let mut combined = allow_hint();
    combined["coverage"] = coverage_hint(&"a".repeat(64));
    let connector =
        json!({"schema": "guard.connector-setup-hint.v1", "cli_id": "local-cli.example"});
    for stored in [combined, allow_hint(), connector] {
        assert_eq!(
            recovered(stored.clone(), || panic!("stored hint was reviewed again")),
            stored
        );
    }
}

#[test]
fn a_row_without_a_hint_uses_the_live_answer_when_available() {
    assert_eq!(recovered(Value::Null, || Some(allow_hint())), allow_hint());
    assert_eq!(recovered(Value::Null, || None), Value::Null);
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
