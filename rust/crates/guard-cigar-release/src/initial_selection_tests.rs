use super::*;

fn intent() -> InitialSelection {
    InitialSelection {
        schema: "guard-cigar-initial-selection.v1".into(),
        revision: 1,
        request_id: "first-selection".into(),
        expected_service_generation: 3,
        before_settings_sha256: "4".repeat(64),
        after_settings_sha256: "5".repeat(64),
        empty_data_sha256: "6".repeat(64),
        phase: InitialPhase::Prepared,
        target: SelectionPointer {
            runtime: SelectionInstallation {
                installation_id: "verified-first".into(),
                installation_sha256: "1".repeat(64),
                approval_sha256: "2".repeat(64),
                producer_sha256: "3".repeat(64),
                origin: SelectionOrigin::Enrolled {
                    sdk_version: "0.14.1".into(),
                    core_version: "0.14.0".into(),
                    profile_id: "cigar-014".into(),
                    adapter_id: "guard-cigar-python-sdk-v1".into(),
                    adapter_revision: 1,
                },
            },
            data: SelectionData::LegacySaved,
        },
    }
}
#[test]
fn initial_intent_has_no_fabricated_previous_runtime_or_enable_authority() {
    let first = intent();
    first.validate().unwrap();
    let value = serde_json::to_value(&first).unwrap();
    for field in [
        "from",
        "previous",
        "was_enabled",
        "activate_target",
        "grants",
    ] {
        assert!(value.get(field).is_none());
        let mut unknown = value.clone();
        unknown[field] = serde_json::json!(false);
        assert!(serde_json::from_value::<InitialSelection>(unknown).is_err());
    }
    let decoded: InitialSelection = serde_json::from_value(value).unwrap();
    assert_eq!(first, decoded);
    let mut existing_data = first;
    existing_data.target.data = SelectionData::Generation {
        generation_id: "7".repeat(64),
    };
    assert_eq!(existing_data.validate(), Err(SwitchError::InvalidJournal));
}
#[test]
fn first_selection_uses_a_write_ahead_health_and_completion_sequence() {
    use InitialPhase::*;
    let mut current = intent();
    for phase in [CommitIntent, Committed, Healthy, Completed] {
        let before = current.revision;
        current = current.advance(phase).unwrap();
        assert_eq!(current.revision, before + 1);
        assert_eq!(current.target, intent().target);
    }
    assert!(current.phase.terminal());
    assert!(current.advance(Cancelled).is_err());
    assert!(intent().advance(Healthy).is_err());
    assert!(intent().advance(Completed).is_err());
    let mut exhausted = intent();
    exhausted.revision = u64::MAX;
    assert!(exhausted.advance(CommitIntent).is_err());
    let cancelled = intent().advance(Cancelled).unwrap();
    assert!(cancelled.phase.terminal());
    assert!(cancelled.advance(CommitIntent).is_err());
}
#[test]
fn initial_recovery_distinguishes_unpublished_intent_from_uncertain_commit() {
    use InitialPhase::*;
    use InitialRecovery::*;
    let mut current = intent();
    for (phase, before, after_no_record, after_record) in [
        (
            Prepared,
            CancelUnpublished,
            RequireOperatorRecovery,
            RequireOperatorRecovery,
        ),
        (CommitIntent, CancelUnpublished, VerifyTarget, VerifyTarget),
        (
            Committed,
            RequireOperatorRecovery,
            VerifyTarget,
            VerifyTarget,
        ),
        (
            Healthy,
            RequireOperatorRecovery,
            RequireOperatorRecovery,
            CompleteMetadata,
        ),
        (
            Completed,
            RequireOperatorRecovery,
            RequireOperatorRecovery,
            KeepDisabled,
        ),
    ] {
        if phase != Prepared {
            current = current.advance(phase).unwrap();
        }
        assert_eq!(
            current
                .recovery("", &current.before_settings_sha256, false, None, true)
                .unwrap(),
            before
        );
        assert_eq!(
            current
                .recovery(
                    "verified-first",
                    &current.after_settings_sha256,
                    false,
                    None,
                    true
                )
                .unwrap(),
            after_no_record
        );
        assert_eq!(
            current
                .recovery(
                    "verified-first",
                    &current.after_settings_sha256,
                    false,
                    Some(&current.target),
                    true
                )
                .unwrap(),
            after_record
        );
    }
    let uncertain = intent().advance(RecoveryRequired).unwrap();
    assert_eq!(
        uncertain
            .recovery(
                "verified-first",
                &uncertain.after_settings_sha256,
                false,
                None,
                false
            )
            .unwrap(),
        RequireOperatorRecovery
    );
    assert_eq!(
        uncertain
            .recovery(
                "verified-first",
                &uncertain.after_settings_sha256,
                false,
                None,
                true
            )
            .unwrap(),
        VerifyTarget
    );
}
#[test]
fn settings_edits_other_selections_and_enabled_intent_never_authorize_initial_recovery() {
    use InitialPhase::*;
    let mut current = intent();
    for phase in [Prepared, CommitIntent, Committed, Healthy, Completed] {
        if phase != Prepared {
            current = current.advance(phase).unwrap();
        }
        let mut other = current.target.clone();
        other.runtime.installation_id = "different".into();
        for (id, hash, enabled, selected) in [
            (
                "verified-first",
                current.after_settings_sha256.as_str(),
                true,
                Some(&current.target),
            ),
            (
                "verified-first",
                "unrelated-edited-settings",
                false,
                Some(&current.target),
            ),
            (
                "another-runtime",
                current.after_settings_sha256.as_str(),
                false,
                Some(&current.target),
            ),
            (
                "verified-first",
                current.after_settings_sha256.as_str(),
                false,
                Some(&other),
            ),
        ] {
            assert_eq!(
                current.recovery(id, hash, enabled, selected, true).unwrap(),
                InitialRecovery::RequireOperatorRecovery
            );
        }
    }
}
#[test]
fn malformed_initial_bindings_and_schema_are_rejected_without_affecting_v2_records() {
    let first = intent();
    for field in [
        "before_settings_sha256",
        "after_settings_sha256",
        "empty_data_sha256",
    ] {
        let mut value = serde_json::to_value(&first).unwrap();
        value[field] = serde_json::json!("BAD");
        assert!(serde_json::from_value::<InitialSelection>(value)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut invalid = first.clone();
    invalid.after_settings_sha256 = invalid.before_settings_sha256.clone();
    assert!(invalid.validate().is_err());
    let mut invalid = first.clone();
    invalid.expected_service_generation = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = first.clone();
    invalid.schema = "guard-cigar-selection.v2".into();
    assert!(invalid.validate().is_err());
    let existing = SelectionRecord {
        schema: "guard-cigar-selection.v2".into(),
        revision: 1,
        current: first.target,
        last_good: None,
        transaction: None,
    };
    let raw = serde_json::to_string(&existing).unwrap();
    let decoded: SelectionRecord = serde_json::from_str(&raw).unwrap();
    decoded.validate().unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), raw);
}

#[test]
fn observed_reconciliation_repairs_uncertain_metadata_without_inventing_a_previous_selection() {
    let uncertain = intent().advance(InitialPhase::RecoveryRequired).unwrap();
    assert!(uncertain
        .reconcile(
            "verified-first",
            &uncertain.after_settings_sha256,
            false,
            None,
            false
        )
        .is_err());
    let committed = uncertain
        .reconcile(
            "verified-first",
            &uncertain.after_settings_sha256,
            false,
            None,
            true,
        )
        .unwrap();
    assert_eq!(committed.phase, InitialPhase::Committed);
    assert_eq!(committed.revision, uncertain.revision + 1);
    assert_eq!(committed.target, uncertain.target);
    assert_eq!(
        committed
            .reconcile(
                "verified-first",
                &committed.after_settings_sha256,
                false,
                None,
                true
            )
            .unwrap(),
        committed
    );
    let healthy = committed.advance(InitialPhase::Healthy).unwrap();
    let completed = healthy
        .reconcile(
            "verified-first",
            &healthy.after_settings_sha256,
            false,
            Some(&healthy.target),
            false,
        )
        .unwrap();
    assert_eq!(completed.phase, InitialPhase::Completed);
    assert_eq!(
        completed
            .reconcile(
                "verified-first",
                &completed.after_settings_sha256,
                false,
                Some(&completed.target),
                false
            )
            .unwrap(),
        completed
    );
    let cancelled = uncertain
        .reconcile("", &uncertain.before_settings_sha256, false, None, false)
        .unwrap();
    assert_eq!(cancelled.phase, InitialPhase::Cancelled);
    assert!(uncertain
        .reconcile("", &uncertain.before_settings_sha256, true, None, false)
        .is_err());
}
