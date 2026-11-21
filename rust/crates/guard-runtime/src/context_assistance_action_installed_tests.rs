use super::{
    workspace::{candidate_with_agent, data},
    Fixture,
};
use guard_contracts::{GuardHookEdgeResultV2, GuardHookEnvelopeV2};
use serde_json::{json, Value};

fn evaluate(
    fixture: &Fixture,
    workspace: &std::path::Path,
    generation: u64,
) -> GuardHookEdgeResultV2 {
    let snapshot = match fixture.store.current_snapshot() {
        Ok(snapshot) if snapshot.generation == generation => snapshot,
        _ => {
            let snapshot = crate::policy_store::tests::signed_snapshot(
                generation,
                &[29_u8; 32],
                &fixture.home,
            );
            fixture
                .store
                .push(&json!({"schema":"guard-policy-snapshot-push.v1", "snapshot":snapshot}))
                .unwrap();
            snapshot
        }
    };
    let envelope: GuardHookEnvelopeV2 = serde_json::from_value(json!({
        "schema":"guard-hook-envelope.v2", "request_id":"native-action-context", "harness":"codex",
        "event":"PreToolUse", "raw_payload":{"tool_name":"exec_command", "tool_input":{"cmd":"printf private-action-command"}},
        "deadline_budget_ms":100, "policy_generation":generation, "policy_snapshot":snapshot,
        "source":{"cwd":workspace,"home_dir":workspace,"guard_home":fixture.home,"source_ref_external_allowed":false},
        "recording_only":false
    })).unwrap();
    serde_json::from_slice(
        &crate::edge::evaluate_envelope_with_store(envelope, &fixture.store).unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires the explicitly approved installed CIGAR 0.14.1 candidate"]
fn installed_native_action_context_has_mandatory_provenance_and_private_scope_fences() {
    let fixture = Fixture::new();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let before_activation = evaluate(&fixture, &root, 1);
    candidate_with_agent(&fixture, true);
    std::fs::write(root.join("README.md"), "Project guidance for command execute review policy: deployment always follows the approved project procedure.\n").unwrap();
    let grant = |workspace: &std::path::Path, app| {
        data(fixture.ask_input(
            "workspace_grant",
            json!({"action":"grant","workspace":workspace,"app":app,"sources":["README.md"]}),
        ))
    };
    let scope = grant(&root, "dashboard");
    let ask = |id: &Value, snapshot: Option<&Value>| {
        fixture.ask_input("workspace",
        json!({"action":"action","scope_id":scope["scope_id"],"decision_id":id,"snapshot_id":snapshot}))
    };
    assert_eq!(
        ask(&json!(before_activation.receipt.decision_id), None)["code"],
        "native_context_assistance_context_stale"
    );
    let evaluated = evaluate(&fixture, &root, 1);
    crate::policy_store::native_review_origin::verify(&fixture.store, &evaluated.receipt).unwrap();
    let decision = json!(evaluated.receipt.decision_id);
    let context = data(ask(&decision, None));
    let brief = &context["brief"];
    assert!(brief["citations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["source"] == "guard:action"));
    assert!(brief["rendered"]
        .as_str()
        .unwrap()
        .contains("Authenticated native Guard decision"));
    assert_eq!(context["association"]["decision_id"], decision);
    assert_eq!(
        context["association"]["binding"],
        "authenticated_native_decision"
    );
    assert_eq!(context["association"]["execution_binding"], "unqualified");
    assert_eq!(context["association"]["approval_grant"], false);
    for private in [
        "private-action-command",
        root.to_str().unwrap(),
        fixture.home.to_str().unwrap(),
        evaluated.receipt.origin_authentication.as_deref().unwrap(),
        evaluated
            .receipt
            .execution_intent_digest
            .as_deref()
            .unwrap(),
    ] {
        assert!(
            !brief.to_string().contains(private),
            "unexpected private field"
        );
    }
    let explained = data(ask(&decision, Some(&brief["snapshot_id"])));
    assert!(explained["explanation"].is_object());
    assert_eq!(fixture.ask_input("workspace", json!({"action":"explain", "scope_id":scope["scope_id"], "snapshot_id":brief["snapshot_id"]}))["code"], "native_context_assistance_context_stale", "generic explanations cannot bypass native action currentness");
    assert_eq!(fixture.ask_input("workspace", json!({"action":"action", "scope_id":scope["scope_id"],"decision_id":decision,"query":"caller facts must not enter"}))["code"], "native_context_assistance_workspace_input_invalid");
    let agent_scope = grant(&root, "codex");
    let session = fixture.agent(json!({"action":"begin"}));
    let session = &session["payload"]["data"]["result"];
    data(fixture.ask_input("workspace_grant", json!({"action":"authorize_agent","session_id":session["session_id"],"scope_id":agent_scope["scope_id"]})));
    let agent = |snapshot: Option<&Value>| {
        fixture.agent(json!({"action":"review_action","credential":session["credential"],"arguments":{"decision_id":decision,"snapshot_id":snapshot}}))
    };
    assert_eq!(
        agent(Some(&brief["snapshot_id"]))["code"],
        "native_context_assistance_context_scope_denied"
    );
    let agent_context = agent(None);
    assert_eq!(agent_context["status"], "ok", "{agent_context}");
    let agent_context = &agent_context["payload"]["data"]["result"]["result"];
    assert_eq!(agent_context["association"]["decision_id"], decision);
    assert_eq!(
        agent(Some(&agent_context["brief"]["snapshot_id"]))["status"],
        "ok"
    );
    std::fs::write(root.join("README.md"), "Changed project guidance.\n").unwrap();
    assert_eq!(
        ask(&decision, Some(&brief["snapshot_id"]))["code"],
        "native_context_assistance_context_stale"
    );
    assert_eq!(
        agent(None)["code"],
        "native_context_assistance_context_stale"
    );
    data(fixture.ask_input(
        "workspace_access",
        json!({"action":"refresh","scope_id":scope["scope_id"]}),
    ));
    data(ask(&decision, None));
    let newer = evaluate(&fixture, &root, 2);
    assert_eq!(
        ask(&decision, None)["code"],
        "native_context_assistance_context_scope_denied",
        "older native policy cannot explain a decision as current"
    );
    data(fixture.ask_input("workspace_access", json!({"action":"clear"})));
    let fresh_grant = grant(&root, "dashboard");
    assert_eq!(fixture.ask_input("workspace", json!({"action":"action","scope_id":fresh_grant["scope_id"],"decision_id":newer.receipt.decision_id}))["code"],
        "native_context_assistance_context_stale", "clear must forget native decision origins before a new explicit grant");
    assert_eq!(
        agent(None)["code"],
        "native_context_assistance_context_scope_denied"
    );
    fixture.ask("stop");
    assert_eq!(
        ask(&decision, None)["code"],
        "native_context_assistance_disabled"
    );
    assert_eq!(agent(None)["code"], "native_context_assistance_disabled");
    println!(
        "GUARD_CIGAR_ACTION_VERIFICATION={}",
        json!({"schema":"guard-cigar-native-action-verification.v1", "status":"passed",
        "qualification":"native-library-and-actual-sdk-only", "brief":brief, "association":context["association"],
        "checks":["authenticated_native_origin", "no_origin_before_opt_in", "mandatory_native_decision_citation", "native_only_private_bindings",
            "actual_action_selection_explanation", "generic_explain_isolation", "caller_facts_rejected", "paired_agent_action_context", "agent_snapshot_isolation",
            "changed_source_refused", "refreshed_source_accepted", "native_policy_generation_fence", "clear_forgets_native_decision_origins", "disabled_cached_calls_refused", "no_execution_binding_claim"]})
    );
}
