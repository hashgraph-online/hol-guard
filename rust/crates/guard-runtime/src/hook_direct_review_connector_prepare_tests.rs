//! The lookup a connector-setup candidate prepares, and what defers it.

use super::*;

#[cfg(unix)]
fn with_context<T>(tag: &str, payload: Value, run: impl FnOnce(&Context<'_>, &str) -> T) -> T {
    let binding = super::super::super::tests::binding();
    let workspace = super::super::super::tests::workspace(tag);
    let mut payload = payload;
    if payload.get("cwd").is_none() {
        payload["cwd"] = json!(workspace);
    }
    let payload = payload.as_object().unwrap().clone();
    let context = Context {
        harness: "omp",
        payload: &payload,
        recorded_payload: &payload,
        workspace: &workspace,
        home_dir: "/home/user",
        guard_home: "/guard-home",
        binding: &binding,
        hint: None,
    };
    let answer = run(&context, &workspace);
    std::fs::remove_dir_all(&workspace).ok();
    answer
}

#[cfg(unix)]
fn environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("HOME".to_owned(), "/home/user/".to_owned()),
        ("PATH".to_owned(), "/daemon/bin".to_owned()),
        ("LANG".to_owned(), "C".to_owned()),
    ])
}

#[cfg(unix)]
#[test]
fn a_non_recognition_review_prepares_the_daemon_lookup() {
    let payload = json!({
        "tool_name": "Bash",
        "tool_input": {"command": "acme sync"},
        "guard_execution_environment": {"path": "/agent/bin"},
    });
    let result = json!({"reason_code": "native_command_review_required"});
    with_context("connector-prepare", payload, |context, workspace| {
        let lookup = prepare(
            context,
            result.as_object().unwrap(),
            &environment(),
            "oauth",
        )
        .unwrap()
        .expect("a lookup");
        let request = &lookup.request;
        assert_eq!(request.schema, LOCAL_CLI_HOOK_REQUEST_SCHEMA);
        assert!(request.request_id.starts_with("local-cli-hook-"));
        assert_eq!(request.request_id.len(), "local-cli-hook-".len() + 32);
        assert_eq!(request.store_path, "/guard-home/guard.db");
        assert_eq!(request.guard_home, "/guard-home");
        assert_eq!(request.source, "oauth");
        assert_eq!(request.busy_timeout_ms, BUSY_TIMEOUT_MS);
        assert_eq!(request.command, "acme sync");
        assert_eq!(request.cwd, workspace);
        assert_eq!(request.home_dir.as_deref(), Some("/home/user"));
        assert_eq!(request.user_home, "/home/user");
        assert_eq!(request.env["PATH"], "/agent/bin");
        assert_eq!(request.env["LANG"], "C");
        assert_eq!(request.current_action, REVIEW_ACTION);
        assert_eq!(request.current_reason_code, None);
        assert!(request.grant_allowed);
        assert_eq!(lookup.cause, "unrecognised_tool");
        assert_eq!(lookup.harness.as_deref(), Some("omp"));
        assert_eq!(
            lookup.workspace_label,
            scrub_context_text(pathlib_name(workspace), MAX_LABEL_CHARS)
        );
        assert!(lookup.risk_classes.is_empty());
    });
}

#[cfg(unix)]
#[test]
fn a_review_without_a_connector_candidate_looks_nothing_up() {
    let payload = json!({"tool_name": "Bash", "tool_input": {"command": "acme sync"}});
    with_context("connector-ordinary", payload, |context, _| {
        for result in [
            json!({"reason_code": "native_review"}),
            json!({}),
            json!({"reason_code": null}),
        ] {
            assert!(prepare(
                context,
                result.as_object().unwrap(),
                &environment(),
                "oauth"
            )
            .unwrap()
            .is_none());
        }
    });
    let no_command = json!({"tool_name": "Read", "tool_input": {"file_path": "/a"}});
    with_context("connector-no-command", no_command, |context, _| {
        let result = json!({"reason_code": "native_command_review_required"});
        assert!(prepare(
            context,
            result.as_object().unwrap(),
            &environment(),
            "oauth"
        )
        .unwrap()
        .is_none());
    });
    let relative = json!({"tool_name": "Bash", "tool_input": {"command": "acme"}, "cwd": "rel"});
    with_context("connector-relative", relative, |context, _| {
        let result = json!({"reason_code": "native_command_review_required"});
        assert!(prepare(
            context,
            result.as_object().unwrap(),
            &environment(),
            "oauth"
        )
        .unwrap()
        .is_none());
    });
}

#[cfg(unix)]
#[test]
fn a_lookup_the_resident_cannot_spell_as_the_daemon_defers() {
    let payload = json!({"tool_name": "Bash", "tool_input": {"command": "acme sync"}});
    with_context("connector-defer", payload.clone(), |context, _| {
        let unhashable = json!({"reason_code": ["native_command_review_required"]});
        assert!(matches!(
            prepare(
                context,
                unhashable.as_object().unwrap(),
                &environment(),
                "oauth"
            ),
            Err(HookDirectDefer::ReviewQueue)
        ));
        let result = json!({"reason_code": "native_command_review_required"});
        let mut homeless = environment();
        homeless.remove("HOME");
        assert!(matches!(
            prepare(context, result.as_object().unwrap(), &homeless, "oauth"),
            Err(HookDirectDefer::ReviewQueue)
        ));
    });
    let mut nul = payload;
    nul["cwd"] = json!("/tmp/a\u{0}b");
    with_context("connector-nul", nul, |context, _| {
        let result = json!({"reason_code": "native_command_review_required"});
        assert!(matches!(
            prepare(
                context,
                result.as_object().unwrap(),
                &environment(),
                "oauth"
            ),
            Err(HookDirectDefer::ReviewQueue)
        ));
    });
}

#[cfg(unix)]
#[test]
fn a_daemon_whose_drain_raises_no_setup_notice_keeps_the_review() {
    let mut binding = super::super::super::tests::binding();
    binding.connector_setup_notice = None;
    let workspace = super::super::super::tests::workspace("connector-unbound");
    let payload = json!({
        "tool_name": "Bash",
        "tool_input": {"command": "acme sync"},
        "cwd": workspace,
    });
    let payload = payload.as_object().unwrap().clone();
    let context = Context {
        harness: "omp",
        payload: &payload,
        recorded_payload: &payload,
        workspace: &workspace,
        home_dir: "/home/user",
        guard_home: "/guard-home",
        binding: &binding,
        hint: None,
    };
    let review = json!({"reason_code": "native_command_review_required"});
    assert!(matches!(
        prepare(
            &context,
            review.as_object().unwrap(),
            &environment(),
            "oauth"
        ),
        Err(HookDirectDefer::ReviewQueue)
    ));
    // An ordinary review never needed the notice.
    let ordinary = json!({"reason_code": "native_command_sensitive_access"});
    assert!(prepare(
        &context,
        ordinary.as_object().unwrap(),
        &environment(),
        "oauth"
    )
    .unwrap()
    .is_none());
    // Nor does a tool call with no command, which the daemon never looks up.
    let edit = json!({
        "tool_name": "Edit",
        "tool_input": {"file_path": "notes.txt"},
        "cwd": workspace,
    });
    let edit = edit.as_object().unwrap().clone();
    let context = Context {
        payload: &edit,
        recorded_payload: &edit,
        ..context
    };
    assert!(prepare(
        &context,
        review.as_object().unwrap(),
        &environment(),
        "oauth"
    )
    .unwrap()
    .is_none());
    std::fs::remove_dir_all(&workspace).ok();
}
