//! Journal/settings admission only; actual private SDK verification is separate.
use super::*;
fn interrupted(intent: bool) -> (Fixture, Owner, jobs::SwitchJob) {
    let f = Fixture::new(false);
    let (mut owner, settings) = f.begin();
    let mut job = jobs::SwitchJob::new_disabled(
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
        "interrupted",
    )
    .unwrap();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    if intent {
        crate::guard_config_update::io::fail_next_config_write_after_rename();
        assert!(owner.commit(&settings).is_err());
        assert_eq!(
            owner.record().unwrap().transaction.as_ref().unwrap().phase,
            SelectionPhase::CommitIntent
        );
    } else {
        owner.commit(&settings).unwrap();
    }
    (f, owner, job)
}
#[test]
fn committed_disabled_recovery_renews_only_progress_and_repairs_records_after_measurement() {
    for intent in [false, true] {
        let (f, mut owner, original) = interrupted(intent);
        let before = fs::read(f.home.join("config.toml")).unwrap();
        let (target, recovery) = owner.begin_disabled_recovery(&original, 9).unwrap();
        assert_eq!(recovery.operation(), "recover");
        assert_eq!(recovery.request, original.request);
        assert_eq!(recovery.request_sha256, original.request_sha256);
        assert_eq!(recovery.deadline_at_ms, original.deadline_at_ms);
        let attempt = recovery.recovery.as_ref().unwrap();
        assert_eq!(attempt.expected_generation, 9);
        assert_eq!(attempt.deadline_at_ms - attempt.started_at_ms, 120_000);
        assert!(!target.settings().requested.enabled);
        assert!(!target.settings().effective.enabled);
        assert_eq!(target.pointer(), &pointer("new"));
        assert!(owner
            .recover_disabled_target(&recovery, &target, &pointer("wrong"))
            .is_err());
        owner
            .recover_disabled_target(&recovery, &target, &pointer("new"))
            .unwrap();
        assert!(owner.record().unwrap().last_good.is_none());
        owner.mark_healthy("switch-test").unwrap();
        owner.complete_publication("switch-test").unwrap();
        owner.reconcile_job(&recovery).unwrap();
        assert_eq!(
            owner.record().unwrap().last_good.as_ref(),
            Some(&pointer("old"))
        );
        assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), before);
        assert_eq!(
            jobs::get(&f.home, "switch-test").unwrap().unwrap().phase,
            jobs::JobPhase::Completed
        );
        assert!(!f.home.join("cigar-scopes.json").exists());
        assert!(!f.home.join("context-assistance/installations").exists());
    }
}
#[test]
fn a_stale_job_or_an_enabled_transaction_cannot_enter_disabled_recovery() {
    let (f, mut owner, job) = interrupted(false);
    let mut wrong = job.clone();
    wrong.request.target_runtime_id = "other".into();
    assert!(owner.begin_disabled_recovery(&wrong, 9).is_err());
    let mut wrong = job.clone();
    wrong.source_runtime_id = "other".into();
    assert!(owner.begin_disabled_recovery(&wrong, 9).is_err());
    assert!(jobs::get(&f.home, "switch-test")
        .unwrap()
        .unwrap()
        .recovery
        .is_none());
    let live = Fixture::new(true);
    let (mut owner, settings) = live.begin();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    owner.commit(&settings).unwrap();
    let mut forged = jobs::SwitchJob::new_disabled(job.request.clone(), "old".into()).unwrap();
    jobs::save(
        &live.home,
        &mut forged,
        jobs::JobPhase::RecoveryRequired,
        "forged",
    )
    .unwrap();
    assert!(owner.begin_disabled_recovery(&forged, 9).is_err());
    assert!(jobs::get(&live.home, "switch-test")
        .unwrap()
        .unwrap()
        .recovery
        .is_none());
}
#[test]
fn cancelling_one_disabled_attempt_does_not_cancel_the_next_explicit_attempt() {
    let (f, mut owner, original) = interrupted(false);
    jobs::mark_cancel(&f.home, &original).unwrap();
    let (_, mut first) = owner.begin_disabled_recovery(&original, 9).unwrap();
    assert!(!jobs::cancelled(&f.home, &first).unwrap());
    jobs::mark_cancel(&f.home, &first).unwrap();
    jobs::save(
        &f.home,
        &mut first,
        jobs::JobPhase::RecoveryRequired,
        "cancelled_verification",
    )
    .unwrap();
    let (_, second) = owner.begin_disabled_recovery(&first, 10).unwrap();
    assert_ne!(
        first.recovery.as_ref().unwrap().id,
        second.recovery.as_ref().unwrap().id
    );
    assert!(!jobs::cancelled(&f.home, &second).unwrap());
    jobs::mark_cancel(&f.home, &first).unwrap();
    assert!(!jobs::cancelled(&f.home, &second).unwrap());
    assert!(owner.record().unwrap().last_good.is_none());
}

#[test]
fn committed_recovery_snapshots_new_disabled_settings_without_restoring_old_preferences() {
    for healthy in [false, true] {
        let (f, mut owner, job) = interrupted(false);
        if healthy {
            owner.mark_healthy("switch-test").unwrap();
        }
        crate::guard_config_update::disable_context_assistance(&f.home).unwrap();
        let path = f.home.join("config.toml");
        let mut text: toml_edit::DocumentMut = fs::read_to_string(&path).unwrap().parse().unwrap();
        text["context_assistance"]["sources"]["native_policy_facts"] = toml_edit::value(false);
        text["context_assistance"]["limits"]["max_active_workspaces"] = toml_edit::value(1);
        fs::write(
            &path,
            text.to_string() + "\n# newer unrelated preference edit\n",
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        let (target, recovery) = owner.begin_disabled_recovery(&job, 9).unwrap();
        assert!(!target.settings().requested.sources.native_policy_facts);
        assert_eq!(target.settings().requested.limits.max_active_workspaces, 1);
        assert!(!target.settings().requested.enabled);
        owner
            .recover_disabled_target(&recovery, &target, &pointer("new"))
            .unwrap();
        target.check().unwrap();
        owner.mark_healthy("switch-test").unwrap();
        owner.complete_publication("switch-test").unwrap();
        owner.reconcile_job(&recovery).unwrap();
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(owner.record().unwrap().current, pointer("new"));
        assert_eq!(
            owner.record().unwrap().last_good.as_ref(),
            Some(&pointer("old"))
        );
        assert!(!f.home.join("cigar-scopes.json").exists());
    }
}
#[test]
fn another_edit_after_recovery_admission_invalidates_the_captured_settings() {
    let (f, mut owner, job) = interrupted(false);
    let (target, recovery) = owner.begin_disabled_recovery(&job, 9).unwrap();
    let path = f.home.join("config.toml");
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"\n# edit after explicit recovery admission\n")
        .unwrap();
    let newer = fs::read(&path).unwrap();
    assert!(target.check().is_err());
    assert!(owner
        .recover_disabled_target(&recovery, &target, &pointer("new"))
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), newer);
    assert_eq!(
        owner.job_phase(&recovery).unwrap(),
        SelectionPhase::Committed
    );
    assert!(owner.record().unwrap().last_good.is_none());
}
#[test]
fn an_uncertain_commit_still_requires_exact_written_target_settings() {
    let (f, mut owner, job) = interrupted(true);
    fs::OpenOptions::new()
        .append(true)
        .open(f.home.join("config.toml"))
        .unwrap()
        .write_all(b"\n# unknown commit with later edit\n")
        .unwrap();
    let before = fs::read(f.home.join("config.toml")).unwrap();
    assert!(owner.begin_disabled_recovery(&job, 9).is_err());
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), before);
    assert!(jobs::get(&f.home, "switch-test")
        .unwrap()
        .unwrap()
        .recovery
        .is_none());
}
#[test]
fn a_current_opt_in_other_runtime_or_storage_change_cannot_reuse_disabled_recovery() {
    for change in ["enabled", "runtime", "storage"] {
        let (f, mut owner, job) = interrupted(false);
        let path = f.home.join("config.toml");
        let mut text: toml_edit::DocumentMut = fs::read_to_string(&path).unwrap().parse().unwrap();
        match change {
            "enabled" => text["context_assistance"]["enabled"] = toml_edit::value(true),
            "runtime" => text["context_assistance"]["runtime_id"] = toml_edit::value("other"),
            _ => text["context_assistance"]["storage"]["mode"] = toml_edit::value("sqlite"),
        }
        fs::write(&path, text.to_string()).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(owner.begin_disabled_recovery(&job, 9).is_err(), "{change}");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(jobs::get(&f.home, "switch-test")
            .unwrap()
            .unwrap()
            .recovery
            .is_none());
    }
}

#[test]
fn a_later_stop_allows_recovery_of_a_committed_live_switch_without_restoring_activation() {
    for healthy in [false, true] {
        let f = Fixture::new(true);
        let (mut owner, settings) = f.begin();
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
            "interrupted",
        )
        .unwrap();
        owner.advance(SelectionPhase::StopIntent).unwrap();
        owner.commit(&settings).unwrap();
        if healthy {
            owner.mark_healthy("switch-test").unwrap();
        }
        assert!(owner.begin_disabled_recovery(&job, 9).is_err());
        crate::guard_config_update::disable_context_assistance(&f.home).unwrap();
        let stopped = fs::read(f.home.join("config.toml")).unwrap();
        let (target, recovery) = owner.begin_disabled_recovery(&job, 10).unwrap();
        assert!(!recovery.source_disabled);
        assert_eq!(recovery.request, job.request);
        assert_eq!(recovery.request_sha256, job.request_sha256);
        assert!(!target.settings().requested.enabled);
        assert!(!target.settings().effective.enabled);
        owner
            .recover_disabled_target(&recovery, &target, &pointer("new"))
            .unwrap();
        owner.mark_healthy("switch-test").unwrap();
        owner.complete_publication("switch-test").unwrap();
        owner.reconcile_job(&recovery).unwrap();
        assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), stopped);
        assert_eq!(owner.record().unwrap().current, pointer("new"));
        assert_eq!(
            owner.record().unwrap().last_good.as_ref(),
            Some(&pointer("old"))
        );
        assert!(!f.home.join("cigar-scopes.json").exists());
    }
}

#[test]
fn a_transient_snapshot_lock_is_retried_but_other_errors_are_not() {
    let mut calls = 0;
    let value = super::super::disabled_recovery::snapshot(|| {
        calls += 1;
        if calls < 3 {
            Err(error("context_busy"))
        } else {
            Ok("snapshot")
        }
    })
    .unwrap();
    assert_eq!(value, "snapshot");
    assert_eq!(calls, 3);
    calls = 0;
    let result: Result<(), String> = super::super::disabled_recovery::snapshot(|| {
        calls += 1;
        Err(error("switch_settings_conflict"))
    });
    assert!(result.unwrap_err().ends_with("switch_settings_conflict"));
    assert_eq!(calls, 1);
}
