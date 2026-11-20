use super::*;
use serde_json::json;

fn run_plan(operation: &str, payload: Value) -> CommandJobPlanV1 {
    plan(
        operation,
        payload.get("harness"),
        payload.get("surface"),
        payload.get("managers"),
    )
}

fn failure(plan: &CommandJobPlanV1) -> (&str, &str) {
    match plan {
        CommandJobPlanV1::Fail {
            failure_code,
            failure_message,
        } => (failure_code.as_str(), failure_message.as_str()),
        other => panic!("expected a failure, got {other:?}"),
    }
}

fn confirmation(plan: &CommandJobPlanV1) -> &Map<String, Value> {
    match plan {
        CommandJobPlanV1::Confirm { data } => data,
        other => panic!("expected a confirmation, got {other:?}"),
    }
}

#[test]
fn unknown_and_missing_operations_are_unsupported() {
    assert_eq!(
        failure(&run_plan("guard.other", json!({}))),
        (
            "unsupported_operation",
            "Unsupported Guard command operation: guard.other"
        )
    );
    assert_eq!(
        failure(&run_plan("", json!({}))),
        (
            "unsupported_operation",
            "Unsupported Guard command operation: unknown"
        )
    );
}

#[test]
fn review_operations_run_in_their_own_family() {
    for (operation, family) in [
        ("guard.review.resolveExact", "exact_cloud_review"),
        ("guard.review.syncPolicyMemory", "policy_memory"),
    ] {
        assert_eq!(
            run_plan(operation, json!({"managers": "ignored"})),
            run(operation, family, None, None, None)
        );
    }
}

#[test]
fn package_shim_managers_are_normalized_and_checked() {
    assert_eq!(
        run_plan(
            "guard.packageShims.install",
            json!({"managers": [" NPM ", "pnpm"]})
        ),
        run(
            "guard.packageShims.install",
            "package_shims",
            Some(Some(vec!["npm".to_owned(), "pnpm".to_owned()])),
            None,
            None
        )
    );
    assert_eq!(
        run_plan("guard.packageShims.test", json!({})),
        run("guard.packageShims.test", "package_shims", None, None, None)
    );
    for (managers, code) in [
        (json!([]), "invalid_managers"),
        (json!("npm"), "invalid_managers"),
        (json!(["npm", 3]), "invalid_managers"),
        (json!(["npm", "  "]), "invalid_managers"),
        (json!(["npm", "NPM"]), "duplicate_manager"),
        (json!(["npm", "apt"]), "unsupported_manager"),
    ] {
        let planned = run_plan("guard.packageShims.repair", json!({ "managers": managers }));
        assert_eq!(failure(&planned), (code, code.replace('_', " ").as_str()));
    }
}

#[test]
fn package_shim_reads_ignore_managers() {
    for operation in [
        "guard.packageShims.status",
        "guard.packageShims.sync",
        "guard.packageShims.audit",
    ] {
        assert_eq!(
            run_plan(operation, json!({"managers": "not checked here"})),
            run(operation, "package_shims", None, None, None)
        );
    }
}

#[test]
fn package_shim_remove_waits_for_the_local_uninstall_command() {
    let data = run_plan(
        "guard.packageShims.remove",
        json!({"managers": ["npm", "uv"]}),
    );
    assert_eq!(
        Value::Object(confirmation(&data).clone()),
        json!({
            "confirm_command": "hol-guard package-shims uninstall --manager npm --manager uv",
            "managers": ["npm", "uv"],
            "summary": "Run the local package-shim uninstall command on this machine to confirm removal for npm, uv.",
        })
    );
    let every = run_plan("guard.packageShims.remove", json!({}));
    assert_eq!(
        Value::Object(confirmation(&every).clone()),
        json!({
            "confirm_command": "hol-guard package-shims uninstall",
            "managers": [],
            "summary": "Run the local package-shim uninstall command on this machine to confirm removal.",
        })
    );
}

#[test]
fn app_surface_is_checked_before_anything_else() {
    for operation in ["guard.app.status", "guard.app.update", "guard.app.connect"] {
        let planned = run_plan(operation, json!({"surface": "desktop"}));
        assert_eq!(
            failure(&planned),
            ("unsupported_surface", "unsupported surface")
        );
    }
    assert_eq!(
        run_plan(
            "guard.app.status",
            json!({"surface": " cli ", "harness": 7})
        ),
        run(
            "guard.app.status",
            "app",
            None,
            None,
            Some("cli".to_owned())
        )
    );
}

#[test]
fn app_harness_must_be_a_registered_spelling() {
    assert_eq!(
        run_plan("guard.app.connect", json!({"harness": " claude "})),
        run(
            "guard.app.connect",
            "app",
            None,
            Some("claude".to_owned()),
            None
        )
    );
    for name in ["Claude", "pi_agent", "unregistered"] {
        let planned = run_plan("guard.app.status", json!({ "harness": name }));
        let code = format!("Unsupported harness: {name}");
        assert_eq!(
            failure(&planned),
            (code.as_str(), code.replace('_', " ").as_str())
        );
    }
}

#[test]
fn app_changes_need_a_harness_but_updates_do_not() {
    for operation in ["guard.app.connect", "guard.app.repair", "guard.app.remove"] {
        assert_eq!(
            failure(&run_plan(operation, json!({"harness": "  "}))),
            ("harness_required", "App command requires a harness.")
        );
    }
    for operation in [
        "guard.app.update",
        "guard.app.updateCheck",
        "guard.app.status",
    ] {
        assert_eq!(
            run_plan(operation, json!({})),
            run(operation, "app", None, None, None)
        );
    }
}

#[test]
fn app_remove_waits_for_the_local_disconnect_command() {
    let data = run_plan(
        "guard.app.remove",
        json!({"harness": "codex", "surface": "editor"}),
    );
    assert_eq!(
        Value::Object(confirmation(&data).clone()),
        json!({
            "confirm_command": "hol-guard apps disconnect codex --surface editor --confirm disconnect-codex",
            "confirmation_phrase": "disconnect-codex",
            "harness": "codex",
            "summary": "Run the local disconnect command on this machine to confirm removing Guard protection for codex.",
            "surface": "editor",
        })
    );
    let bare = run_plan("guard.app.remove", json!({"harness": "cursor"}));
    assert_eq!(
        confirmation(&bare)["confirm_command"],
        json!("hol-guard apps disconnect cursor --confirm disconnect-cursor")
    );
    assert_eq!(confirmation(&bare)["surface"], Value::Null);
    let alias = run_plan("guard.app.remove", json!({"harness": "claude"}));
    assert_eq!(
        confirmation(&alias)["confirm_command"],
        json!("hol-guard apps disconnect claude-code --confirm disconnect-claude-code")
    );
    assert_eq!(confirmation(&alias)["harness"], json!("claude-code"));
}

fn request(schema: &str, query: Value) -> CommandJobPlanRequestV1 {
    serde_json::from_value(json!({
        "schema": schema,
        "request_id": "command-job-plan-1",
        "query": query,
    }))
    .expect("request")
}

#[test]
fn the_op_binds_its_answer_to_the_request() {
    let query = json!({
        "kind": "plan",
        "operation": "guard.app.update",
        "harness": null,
        "surface": null,
        "managers": null,
    });
    let bytes = evaluate_command_job_plan_request(&request(COMMAND_JOB_PLAN_REQUEST_SCHEMA, query))
        .expect("answer");
    let result: CommandJobPlanResultV1 = serde_json::from_slice(&bytes).expect("result");
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    assert_eq!(result.request_id, "command-job-plan-1");
    assert!(result.request_sha256.starts_with("sha256:"));
    assert_eq!(
        result.payload,
        Some(CommandJobPlanPayloadV1::Plan {
            plan: run("guard.app.update", "app", None, None, None)
        })
    );
}

#[test]
fn a_non_string_operation_is_unknown_and_a_wrong_schema_is_refused() {
    let query =
        json!({"kind": "plan", "operation": 5, "harness": null, "surface": null, "managers": null});
    let bytes =
        evaluate_command_job_plan_request(&request(COMMAND_JOB_PLAN_REQUEST_SCHEMA, query.clone()))
            .expect("answer");
    let result: CommandJobPlanResultV1 = serde_json::from_slice(&bytes).expect("result");
    let Some(CommandJobPlanPayloadV1::Plan { plan }) = result.payload else {
        panic!("no plan");
    };
    assert_eq!(
        failure(&plan),
        (
            "unsupported_operation",
            "Unsupported Guard command operation: unknown"
        )
    );
    let bytes = evaluate_command_job_plan_request(&request("other.v1", query)).expect("answer");
    let result: CommandJobPlanResultV1 = serde_json::from_slice(&bytes).expect("result");
    assert_eq!(
        (result.status.as_str(), result.code.as_str()),
        ("error", "native_command_job_plan_schema_mismatch")
    );
    assert!(result.payload.is_none());
}

#[test]
fn an_oversized_request_is_refused() {
    let query = json!({
        "kind": "plan",
        "operation": "guard.packageShims.install",
        "harness": null,
        "surface": null,
        "managers": ["x".repeat(COMMAND_JOB_PLAN_MAX_BYTES)],
    });
    assert_eq!(
        evaluate_command_job_plan_request(&request(COMMAND_JOB_PLAN_REQUEST_SCHEMA, query)),
        Err("native_command_job_plan_too_large".to_owned())
    );
}
