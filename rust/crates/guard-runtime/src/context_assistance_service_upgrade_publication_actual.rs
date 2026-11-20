//! Actual readonly journal failure after attachment. Recovery must retain the
//! same serving actor and epoch and must never replay installation or switching.
use super::*;
use guard_cigar_release::SelectionPhase;
use std::os::unix::fs::PermissionsExt;

pub(super) fn fail_completion(service: &Service, f: &UpgradeFixture) {
    let signal = lock(&service.state).unwrap().upgrade.clone().unwrap();
    let record = f.home.join("cigar-lifecycle.json");
    *signal.completion_hook.lock().unwrap() = Some(Box::new(move || {
        std::fs::set_permissions(record, std::fs::Permissions::from_mode(0o400)).unwrap();
    }));
}
pub(super) fn reconcile(
    service: &Service,
    f: &UpgradeFixture,
    store: &crate::policy_store::PolicySnapshotStore,
    scope: &str,
    generation: u64,
    latest: &[Value],
) -> Value {
    let pending = wait_job(service, &f.home, "live-commit", "recovery_required");
    assert_eq!(
        pending["code"],
        "switch_publication_acknowledgement_pending"
    );
    assert_eq!(service.status().unwrap()["availability"], "ready");
    let actor = old_actor(service);
    let fence = lock(&service.state).unwrap().epoch.fence();
    let config = std::fs::read(f.home.join("config.toml")).unwrap();
    let owner = switching::Owner::acquire(&f.home).unwrap();
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::Healthy
    );
    assert!(owner.record().unwrap().last_good.is_none());
    drop(owner);
    // Verify the full transferred readonly window before a new target query
    // legitimately evicts its oldest entry under the existing history quota.
    let history = workspace(
        service,
        f,
        store,
        json!({"action":"history","scope_id":scope}),
    );
    super::assert_history_entries(&history, latest);
    let response = workspace(
        service,
        f,
        store,
        json!({"action":"compile","scope_id":scope,"query":"release evidence reviewed note"}),
    );
    assert!(response.to_string().contains("A reviewed note survives"));
    service.cancel_switch(&f.home, "live-commit").unwrap();
    assert!(actor.is_active());
    assert!(fence.is_current());
    assert!(service
        .reconcile_switch(&f.home, "live-commit", generation + 1)
        .is_err());
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), config);
    std::fs::set_permissions(
        f.home.join("cigar-lifecycle.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let done = service
        .reconcile_switch(&f.home, "live-commit", generation)
        .unwrap();
    assert_eq!(done["phase"], "completed");
    assert!(Arc::ptr_eq(&actor, &old_actor(service)));
    assert!(fence.is_current());
    assert_eq!(service.configuration_generation().unwrap(), generation);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), config);
    assert_eq!(
        service
            .reconcile_switch(&f.home, "live-commit", generation)
            .unwrap()["phase"],
        "completed"
    );
    done
}
