use super::{
    workspace::{candidate_with_agent, data},
    Fixture,
};
use serde_json::{json, Value};

fn result(answer: Value) -> Value {
    assert_eq!(answer["status"], "ok", "native agent operation failed");
    assert_eq!(
        answer["payload"]["data"]["schema"],
        "guard-cigar-agent-data.v1"
    );
    assert_eq!(answer["payload"]["data"]["data_role"], true);
    answer["payload"]["data"]["result"].clone()
}

#[test]
fn off_agent_discovery_and_cached_calls_never_create_an_optional_runtime() {
    let fixture = Fixture::new();
    assert_eq!(
        result(fixture.agent(json!({"action":"discover"})))["available"],
        false
    );
    for input in [
        json!({"action":"begin"}),
        json!({"action":"compile","credential":"0".repeat(64),"arguments":{"query":"x"}}),
    ] {
        assert_eq!(
            fixture.agent(input)["code"],
            "native_context_assistance_disabled"
        );
    }
    assert!(!fixture.home.join("context-assistance").exists());
}

#[test]
#[ignore = "requires the explicitly approved installed CIGAR 0.14.1 candidate"]
fn installed_human_paired_agent_context_binds_scope_and_refuses_cached_revoked_calls() {
    let fixture = Fixture::new();
    candidate_with_agent(&fixture, true);
    assert_eq!(
        result(fixture.agent(json!({"action":"discover"})))["available"],
        true
    );
    let private = result(fixture.agent(json!({"action":"begin"})));
    let id = &private["session_id"];
    let credential = &private["credential"];
    let status =
        || fixture.agent(json!({"action":"status","credential":credential,"arguments":{}}));
    assert_eq!(result(status())["phase"], "pending");
    let compile = || {
        fixture.agent(json!({"action":"compile","credential":credential,"arguments":{"query":"approved deployment procedure"}}))
    };
    assert_eq!(
        compile()["code"],
        "native_context_assistance_context_scope_denied"
    );
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().canonicalize().unwrap();
    std::fs::write(
        root.join("README.md"),
        "This app uses a reviewed and approved deployment procedure.\n",
    )
    .unwrap();
    let grant = |app| {
        data(fixture.ask_input(
            "workspace_grant",
            json!({"action":"grant","workspace":root,"app":app,"sources":["README.md"]}),
        ))
    };
    let dashboard = grant("dashboard");
    let authorize = |kind, scope: &Value| {
        fixture.ask_input(
            kind,
            json!({"action":"authorize_agent","session_id":id,"scope_id":scope["scope_id"]}),
        )
    };
    assert_eq!(
        authorize("workspace", &dashboard)["code"],
        "native_context_assistance_workspace_input_invalid"
    );
    assert_eq!(
        authorize("workspace_access", &dashboard)["code"],
        "native_context_assistance_workspace_input_invalid"
    );
    assert_eq!(
        authorize("workspace_grant", &dashboard)["code"],
        "native_context_assistance_context_scope_denied"
    );
    let app = grant("codex");
    data(authorize("workspace_grant", &app));
    assert_eq!(result(status())["app"], "codex");
    let public = data(fixture.ask_input("workspace", json!({"action":"list"})));
    assert!(public.to_string().contains(id.as_str().unwrap()));
    assert!(!public.to_string().contains(credential.as_str().unwrap()));
    let context = result(compile());
    let brief = &context["result"]["brief"];
    assert!(brief["rendered"]
        .as_str()
        .unwrap()
        .contains("This app uses"));
    assert!(!brief.to_string().contains(credential.as_str().unwrap()));
    let snapshot = &brief["snapshot_id"];
    result(fixture.agent(
        json!({"action":"explain","credential":credential,"arguments":{"snapshot_id":snapshot}}),
    ));
    let other = result(fixture.agent(json!({"action":"begin"})));
    assert_eq!(fixture.agent(json!({"action":"explain","credential":other["credential"],"arguments":{"snapshot_id":snapshot}}))["code"], "native_context_assistance_context_scope_denied");
    data(fixture.ask_input(
        "workspace_access",
        json!({"action":"revoke_agent","session_id":id}),
    ));
    assert_eq!(
        compile()["code"],
        "native_context_assistance_context_scope_denied"
    );
    data(fixture.ask_input("workspace_grant",json!({"action":"authorize_agent","session_id":other["session_id"],"scope_id":app["scope_id"]})));
    assert_eq!(fixture.agent(json!({"action":"explain","credential":other["credential"],"arguments":{"snapshot_id":snapshot}}))["code"], "native_context_assistance_context_scope_denied", "a newly authorized session cannot use a previous session's retained snapshot");
    fixture.ask("stop");
    assert_eq!(
        result(fixture.agent(json!({"action":"discover"})))["available"],
        false
    );
    assert_eq!(compile()["code"], "native_context_assistance_disabled");
    println!(
        "GUARD_CIGAR_AGENT_VERIFICATION={}",
        json!({"schema":"guard-cigar-agent-verification.v1","status":"passed",
        "qualification":"native-library-and-actual-sdk-only", "checks":["native_private_session_issuance","human_pairing_required","read_route_cannot_authorize",
        "access_reduction_route_cannot_authorize","dashboard_scope_not_agent_authority","host_bound_app_scope","credential_excluded_from_operator_metadata_and_sdk_context",
        "actual_cited_agent_context","actual_selection_explanation","foreign_unapproved_connection_refused","session_snapshot_isolation","revoked_cached_call_refused","disabled_cached_call_refused"]})
    );
}
