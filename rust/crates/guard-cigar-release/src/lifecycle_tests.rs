use super::*;
use serde_json::json;

fn journal() -> SwitchJournal {
    let catalog = TrustedCatalog::bundled().unwrap();
    let first = catalog.document().builds[0].identity.clone();
    let mut second = first.clone();
    second.build_id = "synthetic-next-build".into();
    second.manifest_sha256 = "8".repeat(64);
    SwitchJournal {
        schema: "guard-cigar-switch-journal.v1".into(),
        request_id: "fixture-switch".into(),
        expected_generation: 7,
        settings_sha256: "3".repeat(64),
        from_installation: "installed-a".into(),
        to_installation: "installed-b".into(),
        from_build: first,
        to_build: second,
        previous_enabled: false,
        activate_target: false,
        reconnect_acknowledged: false,
        data_transition: DataTransition::MemoryRebuild,
        previous_data_generation: None,
        prepared_data_generation: None,
        phase: SwitchPhase::Prepared,
        cancel_requested: false,
    }
}
#[test]
fn update_defaults_require_intent_and_retain_recovery_bytes() {
    let preferences = UpdatePreferences::default();
    assert_eq!(preferences.mode, UpdateMode::Manual);
    assert!(!preferences.allow_preview);
    assert!(preferences.retain_last_good);
    assert!(preferences.pinned_build.is_none());
}
#[test]
fn every_durable_boundary_has_an_explicit_crash_recovery_decision() {
    use RecoveryAction::*;
    use SwitchPhase::*;
    for (phase, selected, expected) in [
        (Prepared, "installed-a", PreservePrevious),
        (OldRuntimeStopped, "installed-a", RestorePrevious),
        (SelectionCommitted, "installed-b", VerifyTarget),
        (TargetHealthy, "installed-b", FinalizeTarget),
        (Completed, "installed-b", Complete),
        (RollbackSelected, "installed-a", VerifyPrevious),
        (RolledBack, "installed-a", Complete),
        (Cancelled, "installed-a", PreservePrevious),
        (RecoveryRequired, "installed-b", RequireOperatorRecovery),
    ] {
        let mut record = journal();
        record.phase = phase;
        assert_eq!(
            record.recovery(selected, true, true).unwrap(),
            expected,
            "{phase:?}"
        );
    }
}
#[test]
fn cancellation_after_commit_rolls_back_instead_of_claiming_nothing_changed() {
    let mut record = journal();
    record.phase = SwitchPhase::SelectionCommitted;
    record.cancel_requested = true;
    assert_eq!(
        record.recovery("installed-b", true, true).unwrap(),
        RecoveryAction::RestorePrevious
    );
    assert_eq!(
        record.recovery("installed-b", true, false).unwrap(),
        RecoveryAction::RequireOperatorRecovery
    );
    assert_eq!(
        record.advance(SwitchPhase::Cancelled),
        Err(SwitchError::InvalidTransition)
    );
}
#[test]
fn failed_or_withdrawn_target_uses_only_a_currently_eligible_previous_build() {
    let mut record = journal();
    record.phase = SwitchPhase::SelectionCommitted;
    assert_eq!(
        record.recovery("installed-b", false, true).unwrap(),
        RecoveryAction::RestorePrevious
    );
    assert_eq!(
        record.recovery("installed-b", false, false).unwrap(),
        RecoveryAction::RequireOperatorRecovery
    );
    record.phase = SwitchPhase::RollbackSelected;
    assert_eq!(
        record.recovery("installed-a", true, false).unwrap(),
        RecoveryAction::RequireOperatorRecovery
    );
}
#[test]
fn changed_selection_settings_or_generation_cannot_commit_a_prepared_switch() {
    let record = journal();
    assert!(record
        .check_precondition(7, &"3".repeat(64), "installed-a")
        .is_ok());
    assert_eq!(
        record.check_precondition(8, &"3".repeat(64), "installed-a"),
        Err(SwitchError::SelectionConflict)
    );
    assert_eq!(
        record.check_precondition(7, &"3".repeat(64), "installed-c"),
        Err(SwitchError::SelectionConflict)
    );
    assert_eq!(
        record.check_precondition(7, &"4".repeat(64), "installed-a"),
        Err(SwitchError::SettingsConflict)
    );
    assert_eq!(
        record.recovery("installed-c", true, true),
        Err(SwitchError::SelectionConflict)
    );
}
#[test]
fn preparation_and_cutover_do_not_change_the_off_intent_or_mint_authority() {
    let mut record = journal();
    for phase in [
        SwitchPhase::OldRuntimeStopped,
        SwitchPhase::SelectionCommitted,
        SwitchPhase::TargetHealthy,
        SwitchPhase::Completed,
    ] {
        record.advance(phase).unwrap();
        assert!(!record.previous_enabled);
        assert!(!record.activate_target);
    }
    let value = serde_json::to_value(record).unwrap();
    for forbidden in [
        "credential",
        "approval",
        "grant",
        "session_token",
        "execution_handoff",
    ] {
        assert!(value.get(forbidden).is_none());
    }
}
#[test]
fn persistent_data_cannot_claim_a_copy_migration_without_a_separate_prepared_generation() {
    let mut record = journal();
    record.data_transition = DataTransition::PreparedCopy;
    assert_eq!(record.validate(), Err(SwitchError::InvalidJournal));
    record.previous_data_generation = Some("old-data".into());
    record.prepared_data_generation = Some("new-data".into());
    assert!(record.validate().is_ok());
    record.prepared_data_generation = record.previous_data_generation.clone();
    assert_eq!(record.validate(), Err(SwitchError::InvalidJournal));
    record.data_transition = DataTransition::ReuseCompatible;
    assert!(record.validate().is_ok());
}
#[test]
fn terminals_do_not_resume_as_new_switches_and_unknown_journal_fields_are_refused() {
    let mut record = journal();
    record.phase = SwitchPhase::Completed;
    assert_eq!(
        record.advance(SwitchPhase::Prepared),
        Err(SwitchError::InvalidTransition)
    );
    let mut value = serde_json::to_value(record).unwrap();
    value["force_restore_credentials"] = json!(true);
    assert!(serde_json::from_value::<SwitchJournal>(value).is_err());
}
