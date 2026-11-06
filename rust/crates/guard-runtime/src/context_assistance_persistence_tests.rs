//! Native engine qualification; the public persistence activation gate remains
//! closed until its doctor, controls and installed lifecycle are qualified.
use super::*;
use guard_context_assistance::{BundleApproval, RuntimeSelection, StorageMode};
use std::os::unix::fs::PermissionsExt;

fn runtime() -> VerifiedRuntime {
    let selection: RuntimeSelection = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit candidate selection"),
        )
        .unwrap(),
    )
    .unwrap();
    let approval: BundleApproval = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_APPROVAL").expect("explicit candidate approval"),
        )
        .unwrap(),
    )
    .unwrap();
    VerifiedRuntime::start(selection, &approval).unwrap()
}
fn settings(home: &std::path::Path, shared: bool) -> ContextAssistanceConfig {
    let selection: Value = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit candidate selection"),
        )
        .unwrap(),
    )
    .unwrap();
    let approval: Value = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_APPROVAL").expect("explicit candidate approval"),
        )
        .unwrap(),
    )
    .unwrap();
    let enrolled: Value = serde_json::from_slice(
        &crate::policy_store::context_assistance_registry::run_enroll_command(
            json!({"schema":"guard-cigar-enroll-local.v1","guard_home":home,"runtime_id":"candidate",
                "local_candidate_approved":true,"source_revision":"b47380e5a5cbeaaad5a61cab3372e9e67368732f",
                "selection":selection,"approval":approval}).to_string().as_bytes()).unwrap()).unwrap();
    assert_eq!(enrolled["ok"], true);
    let mut config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "candidate".into(),
        ..Default::default()
    };
    config.storage.mode = StorageMode::Sqlite;
    config.storage.retention_hours = 1;
    config.sources.workspace_documents = true;
    config.sources.source_set_id = "selected".into();
    config.features.agent_context = shared;
    config.features.shared_agents = shared;
    config.sources.sanitized_receipt_facts = !shared;
    let response: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(
            json!({"schema":"guard-config-update.v1","guard_home":home,"kind":"settings",
            "value_text":json!({"context_assistance":config}).to_string()})
            .to_string()
            .as_bytes(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(response["ok"], true);
    config
}
fn ask(
    engine: &mut Engine,
    runtime: &mut VerifiedRuntime,
    value: Value,
) -> Result<Value, RuntimeError> {
    engine
        .execute(runtime, serde_json::from_value(value).unwrap())
        .map(|v| v["result"].clone())
}

#[test]
#[ignore = "requires the explicitly approved final CPython 3.14 and actual CIGAR 0.14.1 worker"]
fn actual_native_private_storage_requires_fresh_grants_and_deletes_on_revocation() {
    let home_owner = tempfile::tempdir().unwrap();
    let home = home_owner.path().canonicalize().unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let workspace_owner = tempfile::tempdir().unwrap();
    let workspace = workspace_owner.path().canonicalize().unwrap();
    std::fs::write(
        workspace.join("README.md"),
        "Project persistence evidence requires fresh source permission.\n",
    )
    .unwrap();
    let config = settings(&home, false);
    let mut first = runtime();
    let mut engine = Engine::new(home.clone(), &config, None);
    let grant =
        json!({"action":"grant","workspace":workspace,"app":"dashboard","sources":["README.md"]});
    let mut old_config = config.clone();
    old_config.storage.mode = StorageMode::Memory;
    let mut old_generation = Engine::new(home.clone(), &old_config, None);
    assert!(matches!(
        ask(&mut old_generation, &mut first, grant.clone()),
        Err(RuntimeError::ScopeDenied)
    ));
    old_config.storage.mode = StorageMode::Sqlite;
    old_config.runtime_id = "previously-selected".into();
    let mut old_generation = Engine::new(home.clone(), &old_config, None);
    assert!(matches!(
        ask(&mut old_generation, &mut first, grant.clone()),
        Err(RuntimeError::ScopeDenied)
    ));
    assert!(!home.join("context-assistance/saved-evidence").exists());
    assert!(matches!(
        ask(&mut engine, &mut first, grant.clone()),
        Err(RuntimeError::HandshakeFailed)
    ));
    assert!(
        !home.join("context-assistance/saved-evidence").exists(),
        "unqualified private persistence cannot create a user store"
    );
    first.verify_persistence_compile(&home, &config).unwrap();
    let scope = ask(&mut engine, &mut first, grant.clone()).unwrap();
    let old_id = scope["scope_id"].clone();
    assert_eq!(scope["sharing"]["mode"], "private_broker");
    assert_eq!(scope["sharing"]["notes"]["read"], false);
    let old_revision = scope["sharing"]["notes"]["revision"].clone();
    let old = ask(
        &mut engine,
        &mut first,
        json!({"action":"compile","scope_id":old_id,"query":"persistence evidence"}),
    )
    .unwrap();
    assert!(old["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains("fresh source permission"));
    first.close();
    drop(engine);
    let cache = guard_context_assistance::EvidenceCache::existing(&home)
        .unwrap()
        .unwrap();
    assert_eq!(cache.summary().unwrap().slots, 1);
    drop(cache);
    let mut second = runtime();
    second.verify_persistence_compile(&home, &config).unwrap();
    let mut engine = Engine::new(home.clone(), &config, None);
    assert_eq!(
        ask(&mut engine, &mut second, json!({"action":"list"})).unwrap()["scopes"],
        json!([])
    );
    assert!(matches!(
        ask(
            &mut engine,
            &mut second,
            json!({"action":"compile","scope_id":old_id,"query":"persistence"})
        ),
        Err(RuntimeError::ScopeDenied)
    ));
    let fresh = ask(&mut engine, &mut second, grant).unwrap();
    assert_ne!(fresh["scope_id"], old_id);
    let new_revision = &fresh["sharing"]["notes"]["revision"];
    assert_ne!(new_revision["epoch"], old_revision["epoch"]);
    assert_eq!(new_revision["version"], old_revision["version"]);
    assert!(matches!(
        ask(
            &mut engine,
            &mut second,
            json!({"action":"explain","scope_id":fresh["scope_id"],"snapshot_id":old["brief"]["snapshot_id"]})
        ),
        Err(RuntimeError::ContextStale)
    ));
    let current = ask(
        &mut engine,
        &mut second,
        json!({"action":"compile","scope_id":fresh["scope_id"],"query":"persistence"}),
    )
    .unwrap();
    assert!(current["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains("fresh source permission"));
    let withdrawn = ask(&mut engine, &mut second, json!({"action":"withdraw","scope_id":fresh["scope_id"],"source_id":fresh["sources"][0]["source_id"]})).unwrap();
    assert_eq!(withdrawn["sources"], json!([]));
    assert_ne!(
        withdrawn["sharing"]["notes"]["revision"]["epoch"],
        new_revision["epoch"]
    );
    let after = ask(
        &mut engine,
        &mut second,
        json!({"action":"compile","scope_id":fresh["scope_id"],"query":"persistence"}),
    )
    .unwrap();
    assert!(!after["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains("fresh source permission"));
    ask(
        &mut engine,
        &mut second,
        json!({"action":"revoke","scope_id":fresh["scope_id"]}),
    )
    .unwrap();
    assert_eq!(engine.cache.as_ref().unwrap().summary().unwrap().slots, 0);
    second.close();
    println!("GUARD_CIGAR_NATIVE_PRIVATE_ENGINE_VERIFICATION private_broker=true sharing=false fresh_scope_required=true old_context_refused=true revoke_removes_store=true");
}

fn shared_runtime(home: &std::path::Path, config: &ContextAssistanceConfig) -> VerifiedRuntime {
    let mut runtime = runtime();
    runtime.verify_shared_compile(config).unwrap();
    runtime.verify_persistence_compile(home, config).unwrap();
    runtime
}
fn propose(
    engine: &mut Engine,
    runtime: &mut VerifiedRuntime,
    id: &str,
    key: &str,
    text: &str,
) -> String {
    let scope = engine.scopes.get_mut(id).unwrap();
    // This exercises the native backend, not an MCP delivery/approval claim.
    scope
        .graph
        .create_view(
            runtime,
            "app",
            allowed(&scope.sources, &scope.policy),
            &scope.revision,
            true,
        )
        .unwrap();
    let context = scope
        .graph
        .compile(runtime, "app", "reviewed evidence", Vec::new(), None)
        .unwrap();
    scope
        .graph
        .propose(runtime, &context, "native-fixture", key, text)
        .unwrap()["proposal_id"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
#[ignore = "requires the explicitly approved final CPython 3.14 and actual CIGAR 0.14.1 worker"]
fn actual_native_reviewed_notes_recover_then_clear_replaces_saved_store() {
    let home_owner = tempfile::tempdir().unwrap();
    let home = home_owner.path().canonicalize().unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let workspace_owner = tempfile::tempdir().unwrap();
    let workspace = workspace_owner.path().canonicalize().unwrap();
    std::fs::write(
        workspace.join("README.md"),
        "Reviewed project evidence uses a documented release procedure.\n",
    )
    .unwrap();
    let config = settings(&home, true);
    let mut first = shared_runtime(&home, &config);
    let mut engine = Engine::new(home.clone(), &config, None);
    let grant = json!({"action":"grant","workspace":workspace,"app":"codex","sources":["README.md"],"shared_notes":{"read":true,"propose":true}});
    let scope = ask(&mut engine, &mut first, grant.clone()).unwrap();
    let id = scope["scope_id"].as_str().unwrap();
    let text = "Native durability marker: reviewed evidence needs the team's release inspection.";
    let proposal = propose(&mut engine, &mut first, id, "durable:reviewed", text);
    ask(
        &mut engine,
        &mut first,
        json!({"action":"admit_proposal","scope_id":id,"proposal_id":proposal}),
    )
    .unwrap();
    let old = ask(
        &mut engine,
        &mut first,
        json!({"action":"compile","scope_id":id,"query":"durability marker reviewed evidence"}),
    )
    .unwrap();
    assert!(old["brief"]["rendered"].as_str().unwrap().contains(text));
    first.close();
    drop(engine);
    let mut second = shared_runtime(&home, &config);
    let key = guard_context_assistance::EvidenceCache::key(
        "codex",
        &workspace,
        &second.status().worker_fingerprint,
    )
    .unwrap();
    let database = home
        .join("context-assistance/saved-evidence")
        .join(key)
        .join("sdk/broker.sqlite3");
    let before_identity = std::fs::metadata(&database).unwrap();
    let mut engine = Engine::new(home.clone(), &config, None);
    let scope = ask(&mut engine, &mut second, grant.clone()).unwrap();
    let id = scope["scope_id"].as_str().unwrap();
    assert_eq!(scope["sharing"]["notes"]["documents"], 1);
    let recovered = ask(
        &mut engine,
        &mut second,
        json!({"action":"compile","scope_id":id,"query":"durability marker reviewed evidence"}),
    )
    .unwrap();
    assert!(recovered["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains(text));
    assert!(recovered["brief"]["citations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["source"] == "guard:notes"));
    let cleared = ask(
        &mut engine,
        &mut second,
        json!({"action":"clear_notes","scope_id":id}),
    )
    .unwrap();
    assert_eq!(cleared["cleared_notes"], true);
    let after_identity = std::fs::metadata(&database).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_ne!(
        (before_identity.dev(), before_identity.ino()),
        (after_identity.dev(), after_identity.ino())
    );
    assert!(!std::fs::read(&database)
        .unwrap()
        .windows(text.len())
        .any(|w| w == text.as_bytes()));
    let after = ask(
        &mut engine,
        &mut second,
        json!({"action":"compile","scope_id":id,"query":"durability marker reviewed evidence"}),
    )
    .unwrap();
    assert!(!after["brief"]["rendered"].as_str().unwrap().contains(text));
    let dependent_text =
        "Dependency recovery marker: this reviewed note depends on the original source.";
    let pending = propose(
        &mut engine,
        &mut second,
        id,
        "after-clear:dependency",
        dependent_text,
    );
    ask(
        &mut engine,
        &mut second,
        json!({"action":"admit_proposal","scope_id":id,"proposal_id":pending}),
    )
    .unwrap();
    second.close();
    drop(engine);
    let mut third = shared_runtime(&home, &config);
    let mut engine = Engine::new(home.clone(), &config, None);
    let saved_bytes = std::fs::read(&database).unwrap();
    std::fs::remove_file(workspace.join("README.md")).unwrap();
    std::os::unix::fs::symlink(
        workspace.join("missing-dependency.md"),
        workspace.join("README.md"),
    )
    .unwrap();
    assert!(matches!(
        ask(&mut engine, &mut third, grant.clone()),
        Err(RuntimeError::ScopeDenied)
    ));
    assert_eq!(
        std::fs::read(&database).unwrap(),
        saved_bytes,
        "unsafe file admission must fail before restoring the saved SDK store"
    );
    std::fs::remove_file(workspace.join("README.md")).unwrap();
    std::fs::write(
        workspace.join("README.md"),
        "Changed source evidence now requires a different release procedure.\n",
    )
    .unwrap();
    let changed = ask(&mut engine, &mut third, grant).unwrap();
    assert_eq!(
        changed["sharing"]["notes"]["documents"], 0,
        "changed recovery dependencies must withhold old reviewed notes"
    );
    let current = ask(&mut engine, &mut third, json!({"action":"compile","scope_id":changed["scope_id"],"query":"dependency recovery release procedure"})).unwrap();
    assert!(current["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains("Changed source evidence"));
    assert!(!current["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains(dependent_text));
    third.close();
    drop(engine);
    let mut empty_authority = Engine::new(home, &config, None);
    ask(&mut empty_authority, &mut third, json!({"action":"clear"})).unwrap();
    assert_eq!(
        empty_authority
            .cache
            .as_ref()
            .unwrap()
            .summary()
            .unwrap()
            .slots,
        0
    );
    third.close();
    println!("GUARD_CIGAR_NATIVE_NOTES_ENGINE_VERIFICATION reviewed_notes_recovered=true fresh_grant_required=true clear_replaced_store=true unsafe_source_before_restore_refused=true changed_recovery_basis_withholds_notes=true inactive_clear=true");
}
