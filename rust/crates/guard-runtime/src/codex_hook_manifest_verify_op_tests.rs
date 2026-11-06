//! What `_verify_hook_manifest` decided in Python, the resident decides.
//!
//! Each case builds a real installation on disk - a Codex config, a packaged
//! bridge and an interpreter - with the manifest that describes it, then
//! changes one thing and expects the reason and status Python reported.

use super::fixture::*;
use super::*;

#[test]
fn an_unchanged_installation_is_valid() {
    let fixture = Fixture::new();
    let request = fixture.request();
    let answer = evaluate_request(&request);
    let state = &answer["state"];
    assert_eq!(state["integrity_status"], "valid");
    assert_eq!(state["foreign_hook_group_count"], 0);
    assert_eq!(state["foreign_hook_entries_present"], false);
    assert_eq!(state["manifest_package_version"], "1.2.3");
    assert_eq!(
        state["bridge_sha256"],
        identity(&fixture.bridge, "bridge", false)["sha256"]
    );
    assert!(MANAGED_EVENTS
        .iter()
        .all(|event| state["event_matches"][event] == true));
    assert_eq!(answer["private_group_questions"], json!([]));
}

#[test]
fn another_tools_hook_group_is_counted_as_foreign() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    let hooks = request.hooks.as_mut().expect("hooks");
    hooks["PreToolUse"]
        .as_array_mut()
        .expect("a group list")
        .push(json!({ "hooks": [{ "type": "command", "command": "other" }] }));
    let state = state(&request);
    assert_eq!(state["integrity_status"], "valid");
    assert_eq!(state["foreign_hook_group_count"], 1);
    assert_eq!(state["foreign_hook_entries_present"], true);
}

#[test]
fn a_failure_the_caller_met_is_reported_with_the_live_hooks() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.manifest = None;
    request.failure = Some(guard_contracts::CodexHookManifestFailureV1 {
        reason: "codex_hook_manifest_missing".to_owned(),
        message: "missing".to_owned(),
    });
    let state = state(&request);
    assert_eq!(state["integrity_status"], "missing");
    assert_eq!(state["foreign_hook_group_count"], 4);
    assert_eq!(state["foreign_hook_entries_present"], true);
    assert_eq!(state["event_matches"]["PreToolUse"], false);
}

#[test]
fn header_changes_carry_their_python_reasons() {
    let fixture = Fixture::new();
    let cases = [
        (
            "schema_version",
            json!(1),
            "codex_hook_manifest_schema_unsupported",
            "stale",
        ),
        (
            "harness",
            json!("claude"),
            "codex_hook_manifest_context_mismatch",
            "foreign",
        ),
        (
            "config",
            json!({ "scope": "project", "target": "x" }),
            "codex_hook_manifest_config_target_mismatch",
            "foreign",
        ),
        (
            "context",
            json!({}),
            "codex_hook_manifest_context_mismatch",
            "foreign",
        ),
        (
            "package_version",
            json!("1.2.4"),
            "codex_hook_manifest_package_version_stale",
            "stale",
        ),
        (
            "generated_at",
            json!("2026-10-27T12:00:00"),
            "codex_hook_manifest_generated_at_invalid",
            "tampered",
        ),
        (
            "packaged_files",
            json!({}),
            "codex_hook_manifest_packaged_files_invalid",
            "tampered",
        ),
        (
            "transport",
            json!({ "wrapper": "w" }),
            "codex_hook_manifest_transport_invalid",
            "tampered",
        ),
        (
            "fallback",
            json!({}),
            "codex_hook_manifest_fallback_mismatch",
            "tampered",
        ),
        (
            "daemon_start",
            json!(null),
            "codex_hook_manifest_daemon_start_mismatch",
            "tampered",
        ),
        (
            "events",
            json!([]),
            "codex_hook_manifest_registration_stale",
            "stale",
        ),
    ];
    for (key, value, reason, status) in cases {
        let mut request = fixture.request();
        manifest_mut(&mut request).insert(key.to_owned(), value);
        expect(&request, reason, status);
    }
}

#[test]
fn a_whole_float_schema_version_is_python_equal_to_the_integer() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    manifest_mut(&mut request).insert("schema_version".to_owned(), json!(2.0));
    expect(&request, "codex_hook_manifest_valid", "valid");
}

#[test]
fn a_missing_config_is_missing() {
    let fixture = Fixture::new();
    let request = fixture.request();
    fs::remove_file(&fixture.config).expect("remove the config");
    expect(&request, "codex_hook_config_target_missing", "missing");
}

#[test]
fn a_changed_bridge_is_tampered() {
    let fixture = Fixture::new();
    let request = fixture.request();
    fs::write(&fixture.bridge, b"print('other')\n").expect("rewrite the bridge");
    expect(&request, "codex_hook_bridge_hash_mismatch", "tampered");
}

#[test]
fn a_packaged_path_the_installation_no_longer_names_is_stale() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    let expected = request.expected.as_mut().expect("expected");
    expected
        .packaged_paths
        .insert("bridge_runtime".to_owned(), "/elsewhere".to_owned());
    expect(
        &request,
        "codex_hook_manifest_packaged_files_stale",
        "stale",
    );
}

#[test]
fn interpreter_identity_changes_are_refused() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    manifest_mut(&mut request).insert("interpreter".to_owned(), json!("python"));
    expect(
        &request,
        "codex_hook_interpreter_identity_invalid",
        "tampered",
    );

    let mut request = fixture.request();
    let changed_mode = (facts(&fixture.interpreter).mode & 0o7777) ^ 0o001;
    manifest_mut(&mut request)["interpreter"]["invocation_mode"] = json!(changed_mode);
    expect(
        &request,
        "codex_hook_interpreter_invocation_mode_mismatch",
        "tampered",
    );

    let mut request = fixture.request();
    manifest_mut(&mut request)["interpreter"]["link_target"] = json!("python3");
    expect(
        &request,
        "codex_hook_interpreter_invocation_type_mismatch",
        "tampered",
    );

    let mut request = fixture.request();
    request.canonical_paths.remove(&text(&fixture.interpreter));
    // The target's own path is no longer canonical before the invocation is
    // compared, which is the order Python checks them in.
    expect(&request, "codex_hook_interpreter_path_mismatch", "tampered");

    let mut request = fixture.request();
    request
        .expected
        .as_mut()
        .expect("expected")
        .interpreter_path = "/other/python".to_owned();
    expect(&request, "codex_hook_interpreter_path_mismatch", "tampered");
}

#[cfg(unix)]
#[test]
fn a_symlinked_interpreter_is_bound_to_its_link_and_target() {
    let fixture = Fixture::new();
    let link = fixture.interpreter.with_file_name("python3");
    std::os::unix::fs::symlink("python", &link).expect("the link");
    let mut request = fixture.request();
    let link_facts = facts(&link);
    let interpreter = json!({
        "role": "interpreter",
        "invocation_path": text(&link),
        "invocation_mode": link_facts.mode & 0o7777,
        "invocation_owner_uid": link_facts.uid,
        "link_target": "python",
        "target": identity(&fixture.interpreter, "interpreter", true),
    });
    manifest_mut(&mut request).insert("interpreter".to_owned(), interpreter.clone());
    for key in ["fallback", "daemon_start"] {
        manifest_mut(&mut request)[key]["interpreter"] = interpreter.clone();
    }
    request
        .canonical_paths
        .insert(text(&link), text(&fixture.interpreter));
    request
        .expected
        .as_mut()
        .expect("expected")
        .interpreter_path = text(&link);
    expect(&request, "codex_hook_manifest_valid", "valid");

    manifest_mut(&mut request)["interpreter"]["link_target"] = json!("python2");
    expect(
        &request,
        "codex_hook_interpreter_symlink_target_mismatch",
        "tampered",
    );
}

#[test]
fn a_removed_hook_group_reports_which_events_still_match() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.hooks.as_mut().expect("hooks")["PostToolUse"] = json!([]);
    let state = state(&request);
    assert_eq!(
        state["integrity_reason"],
        "codex_hook_registration_mismatch"
    );
    assert_eq!(state["integrity_status"], "tampered");
    assert_eq!(state["event_matches"]["PreToolUse"], true);
    assert_eq!(state["event_matches"]["PostToolUse"], false);
    assert_eq!(state["foreign_hook_group_count"], 3);
}

#[test]
fn hooks_that_are_not_a_table_are_missing() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.hooks = None;
    expect(&request, "codex_hook_registration_missing", "missing");
}

#[test]
fn a_handler_command_that_splits_differently_is_an_argv_mismatch() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.command_argvs.insert(EVENT_COMMAND.to_owned(), None);
    expect(&request, "codex_hook_manifest_argv_mismatch", "tampered");
}

#[test]
fn a_binding_without_its_handler_identity_is_invalid() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    // Changed on both sides, so the registration is not merely stale.
    manifest_mut(&mut request)["events"][1]["handler_index"] = json!(1);
    request.expected.as_mut().expect("expected").event_bindings[1]["handler_index"] = json!(1);
    expect(
        &request,
        "codex_hook_manifest_registration_invalid",
        "tampered",
    );
}

#[cfg(unix)]
#[test]
fn a_group_writable_config_turns_on_whether_its_group_is_private() {
    let fixture = Fixture::new();
    set_mode(&fixture.config, 0o660);
    let config = facts(&fixture.config);
    let mut request = fixture.request();
    let answer = evaluate_request(&request);
    assert_eq!(answer["state"]["integrity_status"], "valid");
    assert_eq!(
        answer["private_group_questions"],
        json!([{ "owner_uid": config.uid, "group_gid": config.gid }])
    );

    request.private_groups = vec![guard_contracts::CodexHookPrivateGroupAnswerV1 {
        owner_uid: config.uid,
        group_gid: config.gid,
        private: false,
    }];
    expect(
        &request,
        "codex_hook_config_target_permissions_unsafe",
        "tampered",
    );

    request.private_groups[0].private = true;
    let answer = evaluate_request(&request);
    assert_eq!(answer["state"]["integrity_status"], "valid");
    assert_eq!(answer["private_group_questions"], json!([]));
}

#[test]
fn malformed_requests_are_refused() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.schema = "other".to_owned();
    assert_eq!(
        refusal(&request),
        Some("native_codex_hook_manifest_verify_schema_mismatch")
    );

    let mut request = fixture.request();
    request.posix = true;
    request.current_uid = None;
    assert_eq!(
        refusal(&request),
        Some("native_codex_hook_manifest_verify_current_uid_missing")
    );

    let mut request = fixture.request();
    request.expected = None;
    assert_eq!(
        refusal(&request),
        Some("native_codex_hook_manifest_verify_incomplete")
    );

    let encoded = evaluate_codex_hook_manifest_verify_request(&request).expect("an encoded answer");
    let result: Value = serde_json::from_slice(&encoded).expect("a JSON answer");
    assert_eq!(result["status"], "error");
    assert!(result.get("payload").is_none());
}
