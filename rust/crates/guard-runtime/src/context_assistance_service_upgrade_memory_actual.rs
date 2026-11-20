//! Memory-only cases reuse the live Service flow and require actual SDK proof.
use super::*;

pub(super) fn no_saved_evidence(f: &UpgradeFixture) {
    assert!(!f.home.join("context-assistance/saved-evidence").exists());
    assert!(!f
        .home
        .join("context-assistance/evidence-generations")
        .exists());
}
pub(super) fn second_app(
    service: &Service,
    f: &UpgradeFixture,
    store: &crate::policy_store::PolicySnapshotStore,
) -> String {
    let scope = workspace(
        service,
        f,
        store,
        json!({"action":"grant","workspace":f.workspace,
        "app":"dashboard","sources":["README.md"],"shared_notes":{"read":true,"propose":true}}),
    )["scope_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let id = scope.clone();
    old_actor(service)
        .call(move |runtime, engine| {
            upgrade_admit(
                engine,
                runtime,
                &id,
                "secondary-reviewed",
                "Secondary app marker must stay scoped to dashboard.",
            )
        })
        .unwrap();
    no_saved_evidence(f);
    scope
}
pub(super) fn invalidate_ready(
    service: &Service,
    f: &UpgradeFixture,
    scope: &str,
    generation: u64,
) {
    service
        .prepare_switch(
            &f.home,
            SwitchRequest {
                job_id: "memory-stale".into(),
                target_runtime_id: f.target.runtime_id.clone(),
                expected_generation: generation,
                rollback: false,
            },
        )
        .unwrap();
    wait_job(service, &f.home, "memory-stale", "ready");
    let scope = scope.to_owned();
    old_actor(service)
        .call(move |runtime, engine| {
            upgrade_admit(
                engine,
                runtime,
                &scope,
                "after-ready-reviewed",
                "Latest reviewed memory edit must survive the fresh preparation.",
            )
        })
        .unwrap();
    service
        .commit_switch(&f.home, "memory-stale", generation, true)
        .unwrap();
    let failed = wait_job(service, &f.home, "memory-stale", "failed");
    assert_eq!(failed["code"], "switch_source_changed");
    assert_eq!(service.configuration_generation().unwrap(), generation);
    assert_eq!(service.status().unwrap()["availability"], "ready");
    assert!(old_actor(service).is_active());
    no_saved_evidence(f);
}
pub(super) fn summary(service: &Service, scope: &str) -> Value {
    let scope = scope.to_owned();
    old_actor(service)
        .call(move |runtime, engine| {
            crate::context_assistance_engine::upgrade_memory_summary(engine, runtime, &scope)
        })
        .unwrap()
}
pub(super) fn summaries(service: &Service, primary: &str, secondary: &str) -> Value {
    json!({"primary":summary(service,primary),"secondary":summary(service,secondary)})
}
pub(super) fn verify_target(
    service: &Service,
    f: &UpgradeFixture,
    store: &crate::policy_store::PolicySnapshotStore,
    primary: &str,
    secondary: &str,
    original: &Value,
) {
    for (scope, kind) in [(primary, "primary"), (secondary, "secondary")] {
        let current = summary(service, scope);
        for field in [
            "scope_sha256",
            "notes",
            "observed_at_ms",
            "valid_until_ms",
            "documents_sha256",
        ] {
            assert_eq!(current[field], original[kind][field], "{kind} {field}");
        }
    }
    let primary = workspace(
        service,
        f,
        store,
        json!({"action":"compile","scope_id":primary,"query":"Latest reviewed memory edit"}),
    )
    .to_string();
    assert!(primary.contains("Latest reviewed memory edit"));
    assert!(!primary.contains("Secondary app marker"));
    let secondary = workspace(
        service,
        f,
        store,
        json!({"action":"compile","scope_id":secondary,"query":"Secondary app marker dashboard"}),
    )
    .to_string();
    assert!(secondary.contains("Secondary app marker"));
    assert!(!secondary.contains("A reviewed note survives"));
    assert!(!secondary.contains("Latest reviewed memory edit"));
    no_saved_evidence(f);
}
