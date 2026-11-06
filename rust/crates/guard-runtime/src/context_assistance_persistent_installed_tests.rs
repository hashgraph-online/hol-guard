//! Actual qualified persistence through native service/permission routes.
use super::workspace::{candidate_with_storage, data};
use super::*;
use std::time::{Duration, Instant};

fn ready(fixture: &Fixture) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = fixture.ask("status");
        assert_eq!(status["status"], "ok");
        let state = status["payload"]["state"].clone();
        if state["job"].is_null() {
            assert_eq!(state["effective_enabled"], true, "{}", state["diagnostic"]);
            assert_eq!(state["runtime"]["persistence_compile_verified"], true);
            return state;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
#[ignore = "requires the explicitly approved final CPython 3.14 and actual CIGAR 0.14.1 worker"]
fn installed_native_persistence_doctor_stop_fresh_grants_and_off_state_removal() {
    let fixture = Fixture::new();
    candidate_with_storage(&fixture, false, false, true);
    let state = ready(&fixture);
    assert_eq!(state["capabilities"]["private_persistence"], true);
    assert_eq!(state["runtime"]["shared_compile_verified"], false);
    let project = tempfile::tempdir().unwrap();
    let workspace = project.path().canonicalize().unwrap();
    std::fs::write(
        workspace.join("README.md"),
        "Private persistent evidence needs a fresh source grant after restart.\n",
    )
    .unwrap();
    let grant =
        json!({"action":"grant","workspace":workspace,"app":"dashboard","sources":["README.md"]});
    let scope = data(fixture.ask_input("workspace_grant", grant.clone()));
    assert_eq!(scope["sharing"]["mode"], "private_broker");
    let brief = data(fixture.ask_input(
        "workspace",
        json!({"action":"compile","scope_id":scope["scope_id"],"query":"persistent evidence"}),
    ));
    assert!(brief["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains("fresh source grant"));
    assert_eq!(
        fixture.ask("stop")["payload"]["state"]["effective_enabled"],
        false
    );
    let saved = data(fixture.ask_input("workspace", json!({"action":"data"})));
    assert_eq!(saved["saved_evidence"]["status"], "saved");
    assert_eq!(saved["saved_evidence"]["slots"], 1);
    assert_eq!(saved["current_contexts"], 0);
    assert_eq!(saved["saved_evidence"]["authority_restored"], false);
    assert!(fixture.ask("status")["payload"]["state"]["runtime"].is_null());
    let mut preferences = state["preferences"].clone();
    preferences["enabled"] = json!(true);
    let response: serde_json::Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(
            json!({"schema":"guard-config-update.v1","guard_home":fixture.home,"kind":"settings",
            "value_text":json!({"context_assistance":preferences}).to_string()})
            .to_string()
            .as_bytes(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(fixture.ask("activate")["status"], "ok");
    ready(&fixture);
    assert_eq!(
        data(fixture.ask_input("workspace", json!({"action":"list"})))["scopes"],
        json!([])
    );
    assert_eq!(
        fixture.ask_input(
            "workspace",
            json!({"action":"compile","scope_id":scope["scope_id"],"query":"persistent evidence"})
        )["code"],
        "native_context_assistance_context_scope_denied"
    );
    let fresh = data(fixture.ask_input("workspace_grant", grant));
    assert_ne!(fresh["scope_id"], scope["scope_id"]);
    let current = data(fixture.ask_input(
        "workspace",
        json!({"action":"compile","scope_id":fresh["scope_id"],"query":"persistent evidence"}),
    ));
    assert!(current["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains("fresh source grant"));
    assert_eq!(
        fixture.ask_input("workspace", json!({"action":"forget_saved"}))["code"],
        "native_context_assistance_workspace_input_invalid"
    );
    let removed = data(fixture.ask_input("workspace_access", json!({"action":"forget_saved"})));
    assert_eq!(removed["cleared_saved"], true);
    assert_eq!(removed["saved_evidence"]["status"], "empty");
    let stopped = fixture.ask("status");
    assert_eq!(stopped["payload"]["state"]["effective_enabled"], false);
    assert!(stopped["payload"]["state"]["runtime"].is_null());
    fixture.ask("stop");
    println!("GUARD_CIGAR_PERSISTENCE_SERVICE_VERIFICATION actual_doctor=true private_without_sharing=true saved_evidence_after_stop=true fresh_grants_after_restart=true old_scope_refused=true protected_removal=true no_restored_authority=true");
}
