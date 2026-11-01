//! The ordinary persisted settings route must enable only an existing verified
//! installation, without recursive catalog writer locks or SDK activation.
use super::*;
#[test]
#[ignore = "requires task-private exact final0.14.1 wheel/dependency and external CPython3.14.10 inputs"]
fn actual_managed_settings_enable_resolves_authenticated_catalog_without_recursive_lock() {
    let f = UpgradeFixture::new();
    let mut off = f.target.clone();
    off.enabled = false;
    f.write_settings(&off);
    let (_, runtime, _) = f.installed_target();
    drop(runtime);
    let mut key =
        crate::resident_state::private_file(&f.home.join("policy-verifier.key"), true, &f.home)
            .unwrap();
    key.write_all(&[91_u8; 32]).unwrap();
    drop(key);
    let store = crate::policy_store::PolicySnapshotStore::new(
        &f.home,
        &crate::resident_state::runtime_digest().unwrap(),
    )
    .unwrap();
    catalog_fixture::install(&store, &f.home);
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let request = json!({"schema":"guard-config-update.v1","guard_home":f.home,"kind":"settings","value_text":json!({"context_assistance":f.target}).to_string()});
    let result: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(request.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    println!("CIGAR_SETTINGS_OPT_IN_RESULT={result}");
    assert_eq!(
        result["ok"], true,
        "a verified installed SDK must be selectable after signed catalog import: {result}"
    );
    let after = std::fs::read(f.home.join("config.toml")).unwrap();
    assert_ne!(before, after);
    let settings = crate::guard_config_load::context_assistance_config(&f.home).unwrap();
    assert_eq!(settings.requested, f.target);
    assert_eq!(settings.effective, f.target);
    let state = ask(&store, &f.home, "status", json!({}));
    assert_eq!(state["status"], "ok", "{state}");
    let service = store.context_assistance();
    let status = service.status().unwrap();
    assert_eq!(status["requested_enabled"], true);
    assert_eq!(status["runtime"], Value::Null);
    assert_eq!(status["job"], Value::Null);
    crate::guard_config_update::disable_context_assistance(&f.home).unwrap();
    let disabled = std::fs::read(f.home.join("config.toml")).unwrap();
    let owner =
        crate::policy_store::context_assistance_registry::switching::Owner::acquire(&f.home)
            .unwrap();
    let busy: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(request.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(busy["ok"], false);
    assert!(
        busy["error"].as_str().unwrap().ends_with("install_busy"),
        "{busy}"
    );
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), disabled);
    drop(owner);
    let writer = crate::guard_config_update::io::WriteLock::acquire(&f.home).unwrap();
    let contention: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(request.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(contention["ok"], false);
    assert!(
        contention["error"]
            .as_str()
            .unwrap()
            .ends_with("cigar_catalog_busy"),
        "{contention}"
    );
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), disabled);
    drop(writer);
    let installation =
        crate::policy_store::context_assistance_registry::load(&f.home, &f.target.runtime_id)
            .unwrap();
    let injected = installation
        .selection
        .site_packages
        .join("__guard_settings_untrusted_probe__.py");
    std::fs::write(&injected, b"# untrusted injected bytes; never executed\n").unwrap();
    let rejected: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(request.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(rejected["ok"], false);
    assert!(rejected["invalid"]
        .as_str()
        .unwrap()
        .contains("CPython 3.14"));
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), disabled);
    std::fs::remove_file(injected).unwrap();
    crate::policy_store::context_assistance_registry::validate_selection(
        &f.home,
        &f.target.runtime_id,
    )
    .unwrap();
    let home = f.home.clone();
    let stale: Value = crate::guard_config_update::with_publication_hook(
        move || {
            crate::guard_config_update::disable_context_assistance(&home).unwrap();
        },
        || {
            serde_json::from_slice(
                &crate::guard_config_update::run_command(request.to_string().as_bytes()).unwrap(),
            )
            .unwrap()
        },
    );
    assert_eq!(stale["ok"], false);
    assert_eq!(stale["error"], "config_file_changed");
    assert!(
        !crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested
            .enabled
    );
    assert_ne!(std::fs::read(f.home.join("config.toml")).unwrap(), disabled);
    service.shutdown();
    println!(
        "CIGAR_SETTINGS_OPT_IN_PROOF={}",
        json!({"schema":"guard-cigar-settings-opt-in-proof.v1","scope":"local-macos-arm64-final0141-external31410-test-qualified-cached-catalog-not-newer-sdk","ordinary_settings_writer":true,"authenticated_catalog":true,"installed_exact_bundle_verified":true,"stored_opt_in_without_sdk_activation":true,"preferences_preserved":true,"lifecycle_conflict_preserved_opt_out":true,"writer_contention_reported_busy_instead_of_unverified":true,"tampered_bundle_refused_without_activation":true,"stop_while_already_off_won_prepared_enable_race":true})
    );
}
