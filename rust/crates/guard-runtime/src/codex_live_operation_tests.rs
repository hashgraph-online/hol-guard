//! The Codex operation decodes its metadata as `json.loads` does and carries
//! what JSON cannot hold beside the token Python wrote, and only a live,
//! proven hook wait yields a deadline.

use super::*;

const CREATED: &str = "2026-10-30T12:00:00+00:00";

fn row(status: &str, metadata: &str) -> Value {
    json!({
        "operation_id": "op-1",
        "session_id": "session-1",
        "harness": "codex",
        "operation_type": "tool_call",
        "status": status,
        "approval_request_ids_json": "[\"req-1\"]",
        "resume_token": null,
        "metadata_json": metadata,
        "created_at": CREATED,
        "updated_at": CREATED,
    })
}

fn decoded(metadata: &str) -> Operation {
    decode(row("waiting_on_approval", metadata), None)
        .unwrap()
        .unwrap()
}

fn live_identity() -> Value {
    let (pid, token) = crate::codex_hook_identity::current_process_identity().unwrap();
    json!({"pid": pid, "startToken": token})
}

fn live(metadata: Value) -> Operation {
    let mut metadata = metadata;
    metadata["codex_browser_wait_process"] = live_identity();
    decoded(&metadata.to_string())
}

#[test]
fn no_operation_decodes_to_none() {
    assert!(decode(Value::Null, None).unwrap().is_none());
}

#[test]
fn a_repeated_key_keeps_its_last_value() {
    let operation = decoded(r#"{"a": 1, "b": 2, "a": 3}"#);
    assert_eq!(operation.carried["metadata"]["a"], json!(3));
    assert_eq!(operation.carried["metadata"]["b"], json!(2));
    assert_eq!(operation.carried["approval_request_ids"], json!(["req-1"]));
    assert!(operation.nonfinite.is_empty());
}

#[test]
fn nonfinite_floats_are_carried_as_null_beside_their_token() {
    let operation = decoded(r#"{"x": NaN, "y": [1, -Infinity], "z": Infinity}"#);
    let metadata = &operation.carried["metadata"];
    assert_eq!(metadata["x"], Value::Null);
    assert_eq!(metadata["y"], json!([1, null]));
    assert_eq!(metadata["z"], Value::Null);
    assert_eq!(
        operation.nonfinite,
        vec![
            json!([["x"], "NaN"]),
            json!([["y", 1], "-Infinity"]),
            json!([["z"], "Infinity"]),
        ]
    );
    assert_eq!(operation.metadata["x"], Value::Null);
}

#[test]
fn a_lone_surrogate_is_carried_as_the_escape_python_wrote() {
    let operation = decoded(r#"{"s": "a\ud800b", "t": "plain"}"#);
    assert_eq!(operation.carried["metadata"]["s"], Value::Null);
    assert_eq!(operation.carried["metadata"]["t"], json!("plain"));
    assert_eq!(operation.nonfinite, vec![json!([["s"], "\"a\\ud800b\""])]);
    // The facts keep the mapped character, so it never matches real text.
    assert_ne!(operation.metadata["s"], json!("ab"));
}

#[test]
fn a_lone_surrogate_key_is_refused() {
    assert!(matches!(
        decode(row("waiting_on_approval", r#"{"\udc00": 1}"#), None),
        Err(StoreError::Invalid(INVALID))
    ));
}

#[test]
fn ids_that_json_cannot_carry_are_refused() {
    let mut row = row("waiting_on_approval", "{}");
    row["approval_request_ids_json"] = json!("[NaN]");
    assert!(matches!(
        decode(row, None),
        Err(StoreError::Invalid(INVALID))
    ));
}

#[test]
fn an_explicit_project_id_that_is_not_a_path_is_kept() {
    let operation = decoded(r#"{"projectId": " team-project "}"#);
    assert_eq!(
        operation.carried["metadata"]["project_id"],
        json!("team-project")
    );
    let operation = decoded("{}");
    assert!(operation.carried["metadata"].get("project_id").is_none());
}

#[test]
fn local_paths_are_told_from_project_ids() {
    for path in [
        "/work",
        "~/work",
        "./work",
        "../work",
        r"\\server\share",
        r"C:\work",
        "C:/work",
        " /work",
    ] {
        assert!(looks_like_local_path(path), "{path}");
    }
    for id in ["git-project:v1:abc", "team", "C:", "ab:/x"] {
        assert!(!looks_like_local_path(id), "{id}");
    }
}

#[test]
fn json_dumps_escapes_are_ascii() {
    assert_eq!(ascii_literal("é\"\\\n\t"), r#""\u00e9\"\\\n\t""#);
    assert_eq!(ascii_literal("\u{1F600}"), r#""\ud83d\ude00""#);
    assert_eq!(ascii_literal("\u{1}"), r#""\u0001""#);
}

#[test]
fn only_a_live_waiting_hook_has_a_deadline() {
    let waiting = json!({
        "codex_hook_waits_for_browser_approval": true,
        "codex_browser_wait_deadline_at": "2026-10-30T12:05:00Z",
    });
    let operation = live(waiting.clone());
    assert_eq!(
        wait_deadline("/nonexistent-guard-home", &operation).as_deref(),
        Some("2026-10-30T12:05:00+00:00")
    );

    let mut stale = waiting.clone();
    stale["codex_browser_wait_process"] = json!({"pid": 1, "startToken": "not-this-process"});
    assert_eq!(
        wait_deadline("/nonexistent-guard-home", &decoded(&stale.to_string())),
        None
    );

    let mut finished = live(waiting);
    finished.carried["status"] = json!("completed");
    assert_eq!(wait_deadline("/nonexistent-guard-home", &finished), None);
}

#[test]
fn a_naive_explicit_deadline_falls_back_to_the_configured_wait() {
    let naive = live(json!({
        "codex_hook_waits_for_browser_approval": true,
        "codex_browser_wait_deadline_at": "2026-10-30T12:05:00",
    }));
    assert_eq!(wait_deadline("/nonexistent-guard-home", &naive), None);

    let pretool = live(json!({
        "codex_hook_waits_for_browser_approval": true,
        "codex_browser_wait_deadline_at": "2026-10-30T12:05:00",
        "hook_event_name": "PreToolUse",
    }));
    // No config: the default 120 seconds plus the hook's 3 second margin.
    assert_eq!(
        wait_deadline("/nonexistent-guard-home", &pretool).as_deref(),
        Some("2026-10-30T12:02:03+00:00")
    );
}

#[test]
fn first_text_skips_blank_and_non_string_values() {
    let mapping = json!({"a": "  ", "b": 1, "c": " value "});
    assert_eq!(first_text(&mapping, &["a", "b", "c"]), Some("value"));
    assert_eq!(first_text(&mapping, &["a", "b"]), None);
}
