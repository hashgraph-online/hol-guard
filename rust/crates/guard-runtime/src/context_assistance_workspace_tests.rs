use super::*;
use std::fs;
use std::time::{Duration, Instant};

#[test]
fn read_operations_cannot_create_grants_and_disabled_content_never_reads_sources() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.ask_input(
            "workspace",
            json!({"action":"grant", "workspace":"/not-read", "app":"dashboard", "sources":[]})
        )["code"],
        "native_context_assistance_workspace_input_invalid"
    );
    assert_eq!(
        fixture.ask_input(
            "workspace",
            json!({"action":"compile", "scope_id":"forged", "query":"x"})
        )["code"],
        "native_context_assistance_disabled"
    );
    assert_eq!(
        fixture.ask_input(
            "workspace_grant",
            json!({"action":"grant", "workspace":"/not-read", "app":"dashboard", "sources":[]})
        )["code"],
        "native_context_assistance_disabled"
    );
    assert!(!fixture.home.join("context-assistance").exists());
}

pub(super) fn candidate(fixture: &Fixture) {
    candidate_with_agent(fixture, false);
}

pub(super) fn candidate_with_agent(fixture: &Fixture, agent_context: bool) {
    candidate_features(fixture, agent_context, false);
}

pub(super) fn candidate_features(fixture: &Fixture, agent_context: bool, shared_agents: bool) {
    candidate_with_storage(fixture, agent_context, shared_agents, false);
}

pub(super) fn candidate_with_storage(
    fixture: &Fixture,
    agent_context: bool,
    shared_agents: bool,
    persistent: bool,
) {
    let selection: serde_json::Value = serde_json::from_slice(
        &fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit candidate selection"),
        )
        .unwrap(),
    )
    .unwrap();
    let approval: serde_json::Value = serde_json::from_slice(
        &fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_APPROVAL")
                .expect("independently approved candidate"),
        )
        .unwrap(),
    )
    .unwrap();
    let enrolled: serde_json::Value = serde_json::from_slice(&crate::policy_store::context_assistance_registry::run_enroll_command(
        json!({"schema":"guard-cigar-enroll-local.v1", "guard_home":fixture.home, "runtime_id":"source-candidate",
        "local_candidate_approved":true, "source_revision":"b47380e5a5cbeaaad5a61cab3372e9e67368732f", "selection":selection, "approval":approval}).to_string().as_bytes()).unwrap()).unwrap();
    assert_eq!(enrolled["ok"], true);
    let updated: serde_json::Value = serde_json::from_slice(&crate::guard_config_update::run_command(
        json!({"schema":"guard-config-update.v1", "guard_home":fixture.home, "kind":"settings", "value_text":json!({
            "context_assistance":{"enabled":true, "runtime_id":"source-candidate", "features":{"agent_context":agent_context,"shared_agents":shared_agents},
                "storage":{"mode":if persistent {"sqlite"}else{"memory"}},
                "sources":{"workspace_documents":true, "source_set_id":"selected-files"}}
        }).to_string()}).to_string().as_bytes()).unwrap()).unwrap();
    assert_eq!(updated["ok"], true, "{updated}");
    assert_eq!(fixture.ask("activate")["status"], "ok");
    let deadline = Instant::now() + Duration::from_secs(if persistent { 60 } else { 30 });
    loop {
        let observed = fixture.ask("status");
        if observed["payload"]["state"]["job"].is_null() {
            assert_eq!(
                observed["payload"]["state"]["effective_enabled"], true,
                "{observed}"
            );
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(super) fn data(answer: serde_json::Value) -> serde_json::Value {
    assert_eq!(answer["status"], "ok", "{answer}");
    assert_eq!(answer["payload"]["data"]["data_role"], true);
    answer["payload"]["data"]["result"].clone()
}

#[test]
#[ignore = "requires the explicitly approved installed CIGAR 0.14.1 candidate"]
fn installed_native_sources_currentness_withdrawal_workspace_policy_and_opt_out() {
    let fixture = Fixture::new();
    candidate(&fixture);
    let temporary = tempfile::tempdir().unwrap();
    let workspace = temporary.path().canonicalize().unwrap();
    fs::write(
        workspace.join("README.md"),
        "Project alpha uses a reviewed deployment procedure.\n",
    )
    .unwrap();
    let grant = |app: &str, paths: serde_json::Value| {
        fixture.ask_input(
            "workspace_grant",
            json!({"action":"grant", "workspace":workspace, "app":app, "sources":paths}),
        )
    };
    assert_eq!(
        grant("codex", json!(["README.md"]))["code"],
        "native_context_assistance_context_scope_denied"
    );
    assert_eq!(
        grant("dashboard", json!([".env"]))["code"],
        "native_context_assistance_context_scope_denied"
    );
    let admitted = data(grant("dashboard", json!(["README.md"])));
    let id = admitted["scope_id"].as_str().unwrap();
    let source_id = admitted["sources"][0]["source_id"].as_str().unwrap();
    let ask = |action: &str, extras: serde_json::Value| {
        let mut input = json!({"action":action,"scope_id":id});
        input
            .as_object_mut()
            .unwrap()
            .extend(extras.as_object().unwrap().clone());
        fixture.ask_input(
            if ["refresh", "withdraw", "revoke"].contains(&action) {
                "workspace_access"
            } else {
                "workspace"
            },
            input,
        )
    };
    let first = data(ask("compile", json!({"query":"deployment procedure"})));
    let brief = first["brief"].clone();
    assert!(brief["rendered"]
        .as_str()
        .unwrap()
        .contains("Project alpha"));
    assert!(brief["citations"].as_array().unwrap().len() >= 2);
    let snapshot = brief["snapshot_id"].as_str().unwrap();
    data(ask("explain", json!({"snapshot_id":snapshot})));
    fs::write(
        workspace.join("README.md"),
        "Project beta now uses a different deployment procedure.\n",
    )
    .unwrap();
    assert_eq!(
        ask("explain", json!({"snapshot_id":snapshot}))["code"],
        "native_context_assistance_context_stale"
    );
    assert_eq!(
        ask("compile", json!({"query":"deployment"}))["code"],
        "native_context_assistance_context_stale"
    );
    data(ask("refresh", json!({})));
    assert_eq!(
        ask("explain", json!({"snapshot_id":snapshot}))["code"],
        "native_context_assistance_context_stale"
    );
    let updated = data(ask("compile", json!({"query":"deployment procedure"})));
    assert!(updated["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains("Project beta"));
    assert_ne!(updated["brief"]["snapshot_id"], brief["snapshot_id"]);
    data(ask("withdraw", json!({"source_id":source_id})));
    assert_eq!(
        ask(
            "explain",
            json!({"snapshot_id":updated["brief"]["snapshot_id"]})
        )["code"],
        "native_context_assistance_context_stale"
    );
    let withdrawn = data(ask("compile", json!({"query":"deployment"})));
    assert!(!withdrawn["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains("Project beta"));
    fs::write(
        workspace.join(".hol-guard.toml"),
        "[context_assistance]\nenabled=false\n",
    )
    .unwrap();
    assert_eq!(
        ask("compile", json!({"query":"deployment"}))["code"],
        "native_context_assistance_context_scope_denied"
    );
    assert_eq!(
        fixture.ask("status")["payload"]["state"]["requested_enabled"],
        true
    );
    fs::remove_file(workspace.join(".hol-guard.toml")).unwrap();
    assert_eq!(
        ask("compile", json!({"query":"deployment"}))["code"],
        "native_context_assistance_context_scope_denied",
        "policy recovery cannot resurrect an earlier grant"
    );
    data(ask("revoke", json!({})));
    assert_eq!(
        ask("compile", json!({"query":"deployment"}))["code"],
        "native_context_assistance_context_scope_denied"
    );
    assert_eq!(
        fixture.ask("stop")["payload"]["state"]["effective_enabled"],
        false
    );
    assert_eq!(
        ask("compile", json!({"query":"deployment"}))["code"],
        "native_context_assistance_disabled"
    );
    println!(
        "GUARD_CIGAR_SOURCE_VERIFICATION={}",
        json!({"schema":"guard-cigar-source-verification.v1", "status":"passed",
        "qualification":"local-development-darwin-arm64-only", "brief_observation":brief,
        "checks":["real_native_activation","explicit_app_workspace_source_consent","agent_feature_gate","secret_path_refusal",
            "native_policy_and_document_citations","source_change_stale_refusal","explicit_refresh","workspace_policy_refusal",
            "source_withdrawal","scope_revocation","persisted_global_opt_out"]})
    );
}
