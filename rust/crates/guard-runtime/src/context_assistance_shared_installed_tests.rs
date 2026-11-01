use super::{
    workspace::{candidate_features, data},
    Fixture,
};
use serde_json::{json, Value};

#[test]
#[ignore = "requires the explicitly approved installed CIGAR 0.14.1 candidate"]
fn installed_shared_pairing_reserves_capacity_before_first_agent_compile() {
    let fixture = Fixture::new();
    candidate_features(&fixture, true, true);
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::write(root.join("README.md"), "Reviewed deployment checklist.\n").unwrap();
    let scope = data(fixture.ask_input(
        "workspace_grant",
        json!({"action":"grant","workspace":root,"app":"codex","sources":["README.md"]}),
    ));
    data(fixture.ask_input(
        "workspace",
        json!({"action":"compile","scope_id":scope["scope_id"],"query":"deployment"}),
    ));
    let clients = (0..7).map(|_| pair(&fixture, &scope)).collect::<Vec<_>>();
    // No agent has compiled. Pairing itself must consume the seven remaining
    // SDK slots, and an unsuccessful human pairing must leave no authority.
    let refused = result(fixture.agent(json!({"action":"begin"})));
    let denied = fixture.ask_input(
        "workspace_grant",
        json!({"action":"authorize_agent","scope_id":scope["scope_id"],
            "session_id":refused["session_id"]}),
    );
    assert_eq!(
        denied["code"],
        "native_context_assistance_context_resource_limit"
    );
    let sessions = data(fixture.ask_input("workspace", json!({"action":"list_agents"})));
    assert_eq!(sessions["agent_sessions"].as_array().unwrap().len(), 7);
    assert_eq!(
        agent(&fixture, &refused, "compile", json!({"query":"deployment"}))["code"],
        "native_context_assistance_context_scope_denied"
    );
    for private in &clients {
        let compiled = result(agent(
            &fixture,
            private,
            "compile",
            json!({"query":"deployment"}),
        ));
        assert_eq!(compiled["result"]["current"], true);
        assert!(compiled["result"]["brief"]["rendered"]
            .as_str()
            .unwrap()
            .contains("Reviewed deployment"));
    }
    data(fixture.ask_input(
        "workspace_access",
        json!({"action":"revoke_agent","session_id":clients[0]["session_id"]}),
    ));
    let replacement = pair(&fixture, &scope);
    assert_ne!(replacement["session_id"], clients[0]["session_id"]);
    assert_eq!(
        result(agent(
            &fixture,
            &replacement,
            "compile",
            json!({"query":"deployment"})
        ))["result"]["current"],
        true
    );
    assert_eq!(fixture.ask("stop")["status"], "ok");
}

fn result(answer: Value) -> Value {
    assert_eq!(
        answer["status"], "ok",
        "native shared agent operation failed: {}",
        answer["code"]
    );
    answer["payload"]["data"]["result"].clone()
}
fn agent(fixture: &Fixture, private: &Value, action: &str, arguments: Value) -> Value {
    fixture.agent(json!({"action":action,"credential":private["credential"],"arguments":arguments}))
}
fn pair(fixture: &Fixture, scope: &Value) -> Value {
    let private = result(fixture.agent(json!({"action":"begin"})));
    let authorized = data(fixture.ask_input(
        "workspace_grant",
        json!({"action":"authorize_agent",
        "scope_id":scope["scope_id"],"session_id":private["session_id"]}),
    ));
    assert_eq!(authorized["lease_seconds"], 300);
    private
}

#[test]
#[ignore = "requires the explicitly approved installed CIGAR 0.14.1 candidate"]
fn installed_shared_connections_quarantine_cas_dependencies_withdrawal_and_off() {
    let fixture = Fixture::new();
    candidate_features(&fixture, true, true);
    assert_eq!(
        fixture.ask("status")["payload"]["state"]["runtime"]["shared_compile_verified"],
        true
    );
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let original = "Project deployment uses the reviewed deployment checklist.\n";
    std::fs::write(root.join("README.md"), original).unwrap();
    let scope = data(fixture.ask_input(
        "workspace_grant",
        json!({"action":"grant","workspace":root,
        "app":"codex","sources":["README.md"],"shared_notes":{"read":true,"propose":true}}),
    ));
    assert_eq!(scope["sharing"]["mode"], "shared_broker");
    let id = scope["scope_id"].clone();
    let host = |kind: &str, action: &str, extra: Value| {
        let mut input = json!({"action":action,"scope_id":id});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        fixture.ask_input(kind, input)
    };
    let a = pair(&fixture, &scope);
    let b = pair(&fixture, &scope);
    for private in [&a, &b] {
        let status = result(agent(&fixture, private, "status", json!({})));
        assert!(status["tools"]
            .as_array()
            .unwrap()
            .contains(&json!("propose_guard_context_note")));
    }
    let first = result(agent(
        &fixture,
        &a,
        "compile",
        json!({"query":"reviewed deployment checklist"}),
    ));
    let snapshot = first["result"]["brief"]["snapshot_id"].clone();
    assert!(first["result"]["brief"]["citations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["source"] == scope["sources"][0]["source_id"]));
    assert_eq!(
        agent(&fixture, &b, "explain", json!({"snapshot_id":snapshot}))["code"],
        "native_context_assistance_context_scope_denied"
    );
    let proposed_text = "Shared deployment checklist: require the team's release review.";
    let proposal = |text: &str| {
        agent(
            &fixture,
            &a,
            "propose_note",
            json!({"snapshot_id":snapshot,"request_key":"deployment:one","text":text}),
        )
    };
    let pending = result(proposal(proposed_text));
    assert_eq!(pending["outcome"]["status"], "pending");
    assert_eq!(result(proposal(proposed_text)), pending);
    assert_eq!(
        proposal("Changed text under the same request key.")["code"],
        "native_context_assistance_context_conflict"
    );
    let second = result(agent(
        &fixture,
        &b,
        "compile",
        json!({"query":"shared deployment checklist"}),
    ));
    assert!(
        !second.to_string().contains(proposed_text),
        "pending text must stay quarantined"
    );
    let competing = result(agent(
        &fixture,
        &b,
        "propose_note",
        json!({"snapshot_id":second["result"]["brief"]["snapshot_id"],
        "request_key":"deployment:competing","text":"Different shared deployment guidance."}),
    ));
    let pid = pending["proposal_id"].clone();
    let list = data(host("workspace", "proposals", json!({})));
    assert_eq!(list["proposals"].as_array().unwrap().len(), 2);
    assert!(!list.to_string().contains(proposed_text));
    assert!(!list.to_string().contains(a["credential"].as_str().unwrap()));
    let detail = data(host("workspace", "proposal", json!({"proposal_id":pid})));
    assert_eq!(detail["proposal"]["source_access"], "available");
    assert_eq!(detail["proposal"]["approval_grant"], false);
    assert!(detail["proposal"].to_string().contains(proposed_text));
    #[cfg(unix)]
    {
        std::fs::remove_file(root.join("README.md")).unwrap();
        std::os::unix::fs::symlink(root.join("missing.md"), root.join("README.md")).unwrap();
        let withheld = data(host("workspace", "proposal", json!({"proposal_id":pid})));
        assert_eq!(withheld["proposal"]["source_access"], "unavailable");
        assert!(withheld["proposal"]["documents"].is_null());
        assert!(withheld["proposal"]["current_documents"].is_null());
        std::fs::remove_file(root.join("README.md")).unwrap();
        std::fs::write(root.join("README.md"), original).unwrap();
    }
    for route in ["workspace", "workspace_access"] {
        assert_eq!(
            host(route, "admit_proposal", json!({"proposal_id":pid}))["code"],
            "native_context_assistance_workspace_input_invalid"
        );
    }
    let admitted = data(host(
        "workspace_grant",
        "admit_proposal",
        json!({"proposal_id":pid}),
    ));
    assert_eq!(admitted["state"], "admitted");
    assert_eq!(admitted["approval_grant"], false);
    assert_eq!(
        result(agent(
            &fixture,
            &a,
            "proposal_status",
            json!({"request_key":"deployment:one"})
        ))["outcome"]["status"],
        "admitted"
    );
    assert_eq!(
        host(
            "workspace_grant",
            "admit_proposal",
            json!({"proposal_id":competing["proposal_id"]})
        )["code"],
        "native_context_assistance_context_conflict"
    );
    data(host(
        "workspace_access",
        "reject_proposal",
        json!({"proposal_id":competing["proposal_id"]}),
    ));
    assert_eq!(
        result(agent(
            &fixture,
            &b,
            "proposal_status",
            json!({"request_key":"deployment:competing"})
        ))["outcome"]["status"],
        "rejected"
    );
    assert_eq!(
        agent(
            &fixture,
            &b,
            "proposal_status",
            json!({"request_key":"deployment:one"})
        )["code"],
        "native_context_assistance_context_scope_denied"
    );
    let shared = result(agent(
        &fixture,
        &b,
        "compile",
        json!({"query":"shared deployment checklist team release review"}),
    ));
    let brief = &shared["result"]["brief"];
    assert!(brief["rendered"].as_str().unwrap().contains(proposed_text));
    assert!(brief["citations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["source"] == "guard:notes"));
    let history = data(host("workspace", "history", json!({})));
    let entry = history["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["snapshot_id"] == brief["snapshot_id"])
        .unwrap();
    assert!(
        entry["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["source_id"] == scope["sources"][0]["source_id"]),
        "shared notes must retain upstream file dependencies"
    );
    let history_id = entry["history_id"].clone();
    #[cfg(unix)]
    {
        std::fs::remove_file(root.join("README.md")).unwrap();
        std::os::unix::fs::symlink(root.join("missing.md"), root.join("README.md")).unwrap();
        let unsafe_detail = data(host(
            "workspace",
            "history_detail",
            json!({"history_id":history_id}),
        ));
        assert!(unsafe_detail["brief"].is_null());
        assert_eq!(unsafe_detail["source_access"], "unavailable");
        std::fs::remove_file(root.join("README.md")).unwrap();
    }
    std::fs::write(
        root.join("README.md"),
        "Changed deployment now uses a revised checklist.\n",
    )
    .unwrap();
    assert_eq!(
        agent(&fixture, &b, "compile", json!({"query":"deployment"}))["code"],
        "native_context_assistance_context_stale"
    );
    data(host("workspace_access", "refresh", json!({})));
    let refreshed = result(agent(
        &fixture,
        &b,
        "compile",
        json!({"query":"shared deployment checklist team release review"}),
    ));
    assert!(!refreshed.to_string().contains(proposed_text));
    assert_eq!(
        refreshed["result"]["scope"]["sharing"]["notes"]["documents"],
        0
    );
    let declined_arguments = json!({"snapshot_id":refreshed["result"]["brief"]["snapshot_id"],
        "request_key":"deployment:declined","text":"A note rejected before source mutation."});
    let declined = result(agent(
        &fixture,
        &b,
        "propose_note",
        declined_arguments.clone(),
    ));
    data(host(
        "workspace_access",
        "reject_proposal",
        json!({"proposal_id":declined["proposal_id"]}),
    ));
    assert_eq!(
        result(agent(&fixture, &b, "propose_note", declined_arguments))["outcome"]["status"],
        "rejected",
        "replaying an unchanged rejected proposal must not report it pending"
    );
    assert_eq!(
        agent(&fixture, &a, "explain", json!({"snapshot_id":snapshot}))["code"],
        "native_context_assistance_context_stale"
    );
    // A distinct grant without note permissions cannot use a cached proposal tool.
    let other = tempfile::tempdir().unwrap();
    let readonly = data(fixture.ask_input(
        "workspace_grant",
        json!({"action":"grant","workspace":other.path().canonicalize().unwrap(),
        "app":"codex","sources":[]}),
    ));
    let c = pair(&fixture, &readonly);
    assert!(!result(agent(&fixture, &c, "status", json!({})))["tools"]
        .as_array()
        .unwrap()
        .contains(&json!("propose_guard_context_note")));
    let read_context = result(agent(
        &fixture,
        &c,
        "compile",
        json!({"query":"native policy"}),
    ));
    assert_eq!(
        agent(
            &fixture,
            &c,
            "propose_note",
            json!({"snapshot_id":read_context["result"]["brief"]["snapshot_id"],"request_key":"refused","text":"No note permission."})
        )["code"],
        "native_context_assistance_context_scope_denied"
    );
    data(host("workspace_access", "clear_notes", json!({})));
    assert_eq!(
        data(host("workspace", "history", json!({})))["entries"],
        json!([])
    );
    data(fixture.ask_input(
        "workspace_access",
        json!({"action":"revoke_agent","session_id":b["session_id"]}),
    ));
    assert_eq!(
        agent(&fixture, &b, "compile", json!({"query":"deployment"}))["code"],
        "native_context_assistance_context_scope_denied"
    );
    data(host(
        "workspace_access",
        "withdraw",
        json!({"source_id":scope["sources"][0]["source_id"]}),
    ));
    assert!(!result(agent(
        &fixture,
        &a,
        "compile",
        json!({"query":"deployment"})
    ))
    .to_string()
    .contains("Changed deployment"));
    assert_eq!(fixture.ask("stop")["status"], "ok");
    for action in [
        "compile",
        "propose_note",
        "proposal_status",
        "forget_proposal",
    ] {
        assert_eq!(
            agent(
                &fixture,
                &a,
                action,
                match action {
                    "compile" => json!({"query":"deployment"}),
                    "propose_note" =>
                        json!({"snapshot_id":snapshot,"request_key":"cached","text":"Refused after off."}),
                    _ => json!({"request_key":"deployment:one"}),
                }
            )["code"],
            "native_context_assistance_disabled"
        );
    }
    assert_eq!(fixture.ask("recheck")["status"], "ok");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let state = fixture.ask("status")["payload"]["state"].clone();
        if state["job"].is_null() {
            assert_eq!(state["last_check"]["shared_compile_verified"], true);
            assert_eq!(state["last_check"]["active"], false);
            assert_eq!(state["effective_enabled"], false);
            assert!(state["runtime"].is_null());
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    println!(
        "GUARD_CIGAR_SHARED_PRODUCT_VERIFICATION={}",
        json!({"schema":"guard-cigar-shared-product-verification.v1","status":"passed",
        "qualification":"native_library_actual_sdk_and_paired_sessions","checks":["actual_broker_activation_doctor","two_paired_connections_one_scope","snapshot_isolation",
        "conditional_proposal_tools","quarantine_and_idempotency","host_metadata_excludes_text_and_credentials","operator_detail","admission_route_requires_grant_authority",
        "admission_is_data_not_command_approval","competing_cas_conflict","private_proposal_status","shared_note_citation","inherited_history_dependencies",
        "unsafe_dependency_withholds_history","source_refresh_clears_dependent_notes","read_only_cached_tool_refusal","separate_notes_clear_purges_history",
        "connection_revoke","source_withdrawal","off_cached_mutation_refusal","unsafe_basis_withholds_both_proposal_collections",
        "rejected_replay_keeps_rejected_outcome","explicit_off_recheck_restores_no_authority"]})
    );
}
