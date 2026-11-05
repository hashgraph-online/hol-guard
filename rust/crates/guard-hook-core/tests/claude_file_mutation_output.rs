//! Claude Code's `Edit` and `Write` results are reviewed for the edit they
//! made, not for the whole pre-edit file the host attaches as
//! `originalFile` and never shows the model.

use guard_contracts::NativeHookRequestV1;
use guard_hook_core::{canonical_observed_output_sha256, review_post_tool};
use serde_json::{json, Value};

fn request(harness: &str, payload: Value) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: 1,
        request_id: Some("test".into()),
        harness: harness.into(),
        event_name: "PostToolUse".into(),
        payload,
        cwd: None,
        home_dir: "/tmp".into(),
        guard_home: "/tmp/guard".into(),
        source_ref_external_allowed: false,
        observe_mode: false,
        deadline_budget_ms: Some(5_000),
    }
}

/// A credential assignment the scanner flags, assembled at run time so the
/// source holds no secret-shaped literal.
fn credential_line() -> String {
    let name = ["api", "_key"].concat();
    let value = ["q7Lp2", "Vx9Rt", "4Kw8Zs"].concat();
    format!("const {name} = \"{value}\";")
}

fn edit(original: &str, old: &str, new: &str, patch_lines: Vec<String>) -> Value {
    json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Edit",
        "tool_input": {"file_path": "src/app.ts", "old_string": old, "new_string": new},
        "tool_response": {
            "filePath": "src/app.ts",
            "oldString": old,
            "newString": new,
            "originalFile": original,
            "structuredPatch": [{
                "oldStart": 1, "oldLines": 1, "newStart": 1, "newLines": patch_lines.len(),
                "lines": patch_lines
            }],
            "userModified": false,
            "replaceAll": false
        }
    })
}

/// A file whose only secret-shaped line sits far from the edited one.
fn file_with_distant_credential() -> String {
    format!("{}\n\nexport const label = \"old\";\n", credential_line())
}

#[test]
fn an_edit_is_not_refused_for_a_credential_elsewhere_in_the_file() {
    let payload = edit(
        &file_with_distant_credential(),
        "export const label = \"old\";",
        "export const label = \"new\";",
        vec![
            "-export const label = \"old\";".into(),
            "+export const label = \"new\";".into(),
        ],
    );
    let response = review_post_tool(&request("claude-code", payload.clone()));
    assert_eq!(response.decision, "allow");
    assert_eq!(response.reason_code, "output_scan_allow");
    // The allow keeps the whole result's identity, originalFile included.
    let digest = canonical_observed_output_sha256(&payload);
    assert!(digest.is_some());
    assert_eq!(response.reviewed_output_sha256, digest);
}

#[test]
fn a_long_patch_is_scanned_in_full_rather_than_excerpted() {
    let lines: Vec<String> = (0..30).map(|index| format!("+line {index}")).collect();
    let payload = edit("a\n", "a", "b", lines);
    let response = review_post_tool(&request("claude-code", payload.clone()));
    assert_eq!(response.decision, "allow");
    assert_eq!(response.reason_code, "output_scan_allow");
    // The generic walk cannot read this result in full, so there is no
    // whole-result digest to record; none is invented.
    assert_eq!(canonical_observed_output_sha256(&payload), None);
    assert_eq!(response.reviewed_output_sha256, None);
}

#[test]
fn a_credential_in_the_edit_itself_is_still_refused() {
    let credential = credential_line();
    let payload = edit(
        "export const label = \"old\";\n",
        "export const label = \"old\";",
        &credential,
        vec![
            "-export const label = \"old\";".into(),
            format!("+{credential}"),
        ],
    );
    let response = review_post_tool(&request("claude-code", payload));
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "output_secret_match");
}

#[test]
fn a_credential_beside_the_edit_in_the_patch_is_still_refused() {
    // Context lines are file content a host could render with the result.
    let credential = credential_line();
    let payload = edit(
        &file_with_distant_credential(),
        "export const label = \"old\";",
        "export const label = \"new\";",
        vec![
            format!(" {credential}"),
            "-export const label = \"old\";".into(),
            "+export const label = \"new\";".into(),
        ],
    );
    let response = review_post_tool(&request("claude-code", payload));
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "output_secret_match");
}

#[test]
fn a_write_is_reviewed_for_its_content_not_the_file_it_replaced() {
    let payload = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "src/app.ts", "content": "export const label = \"new\";\n"},
        "tool_response": {
            "type": "update",
            "filePath": "src/app.ts",
            "content": "export const label = \"new\";\n",
            "originalFile": file_with_distant_credential(),
            "structuredPatch": []
        }
    });
    let response = review_post_tool(&request("claude-code", payload));
    assert_eq!(response.decision, "allow");
    assert_eq!(response.reason_code, "output_scan_allow");
}

#[test]
fn other_harnesses_and_tools_keep_the_full_response_scan() {
    let payload = edit(
        &file_with_distant_credential(),
        "export const label = \"old\";",
        "export const label = \"new\";",
        vec!["+export const label = \"new\";".into()],
    );
    let other_harness = review_post_tool(&request("omp", payload.clone()));
    assert_eq!(other_harness.reason_code, "output_secret_match");

    let mut other_tool = payload;
    other_tool["tool_name"] = json!("NotebookEdit");
    let other_tool = review_post_tool(&request("claude-code", other_tool));
    assert_eq!(other_tool.reason_code, "output_secret_match");
}

#[test]
fn a_patch_shape_this_review_cannot_read_keeps_the_generic_one() {
    let mut payload = edit(
        &file_with_distant_credential(),
        "export const label = \"old\";",
        "export const label = \"new\";",
        vec!["+export const label = \"new\";".into()],
    );
    payload["tool_response"]["structuredPatch"] = json!({"hunks": "not a list"});
    let response = review_post_tool(&request("claude-code", payload));
    assert_eq!(response.reason_code, "output_secret_match");
}
