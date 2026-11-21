use super::*;

fn job(f: &Fixture) -> jobs::SwitchJob {
    let mut job = jobs::SwitchJob::new(
        jobs::SwitchRequest {
            job_id: "switch-test".into(),
            target_runtime_id: "new".into(),
            expected_generation: 4,
            rollback: false,
        },
        "old".into(),
    )
    .unwrap();
    jobs::save(
        &f.home,
        &mut job,
        jobs::JobPhase::RecoveryRequired,
        "switch_publication_acknowledgement_pending",
    )
    .unwrap();
    job
}
#[test]
fn health_does_not_promote_last_good_before_publication_completion() {
    let f = Fixture::new(false);
    let (mut owner, settings) = f.begin();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    owner.commit(&settings).unwrap();
    owner.mark_healthy("switch-test").unwrap();
    assert_eq!(owner.record().unwrap().current, pointer("new"));
    assert!(owner.record().unwrap().last_good.is_none());
    let job = job(&f);
    assert!(owner.reconcile_job(&job).is_err());
    assert_eq!(
        jobs::get(&f.home, "switch-test").unwrap().unwrap().phase,
        jobs::JobPhase::RecoveryRequired
    );
    owner.complete_publication("switch-test").unwrap();
    owner.complete_publication("switch-test").unwrap();
    assert_eq!(
        owner.record().unwrap().last_good.as_ref(),
        Some(&pointer("old"))
    );
    owner.reconcile_job(&job).unwrap();
    assert_eq!(
        jobs::get(&f.home, "switch-test").unwrap().unwrap().phase,
        jobs::JobPhase::Completed
    );
    assert!(
        !crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested
            .enabled
    );
}
#[test]
fn progress_cannot_complete_a_prepared_selection_or_substitute_a_different_request() {
    let f = Fixture::new(false);
    let (mut owner, settings) = f.begin();
    let mut job = job(&f);
    let before = fs::read(f.home.join("config.toml")).unwrap();
    assert!(owner.reconcile_job(&job).is_err());
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), before);
    owner.advance(SelectionPhase::StopIntent).unwrap();
    owner.commit(&settings).unwrap();
    owner.mark_healthy("switch-test").unwrap();
    owner.complete_publication("switch-test").unwrap();
    job.request.expected_generation += 1;
    assert!(owner.reconcile_job(&job).is_err());
    job.request.expected_generation -= 1;
    job.prepared_data_generation = Some("d".repeat(64));
    assert!(owner.reconcile_job(&job).is_err());
    assert_eq!(
        jobs::get(&f.home, "switch-test").unwrap().unwrap().phase,
        jobs::JobPhase::RecoveryRequired
    );
    assert!(!f.home.join("context-assistance/installations").exists());
}
#[test]
fn recovery_metadata_never_reconstructs_an_inactive_service_or_its_grants() {
    let f = Fixture::new(true);
    let (mut owner, settings) = f.begin();
    let progress = job(&f);
    owner.advance(SelectionPhase::StopIntent).unwrap();
    owner.commit(&settings).unwrap();
    owner.mark_healthy("switch-test").unwrap();
    drop(owner);
    let service = crate::context_assistance_service::Service::default();
    service
        .configure(crate::guard_config_load::context_assistance_config(&f.home).unwrap())
        .unwrap();
    let generation = service.configuration_generation().unwrap();
    assert!(service
        .reconcile_switch(&f.home, "switch-test", generation)
        .unwrap_err()
        .ends_with("switch_recovery_required"));
    assert_eq!(service.status().unwrap()["runtime"], Value::Null);
    let mut owner = Owner::acquire(&f.home).unwrap();
    owner.complete_publication("switch-test").unwrap();
    drop(owner);
    assert_eq!(
        service
            .reconcile_switch(&f.home, "switch-test", generation)
            .unwrap()["phase"],
        "completed"
    );
    assert_eq!(service.status().unwrap()["runtime"], Value::Null);
    assert_eq!(
        jobs::get(&f.home, &progress.request.job_id)
            .unwrap()
            .unwrap()
            .phase,
        jobs::JobPhase::Completed
    );
    assert!(!f.home.join("context-assistance/installations").exists());
}
