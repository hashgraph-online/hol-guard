use super::*;

fn pointer(id: &str, data: SelectionData) -> SelectionPointer {
    SelectionPointer {
        runtime: SelectionInstallation {
            installation_id: id.into(),
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
        data,
    }
}
fn record() -> SelectionRecord {
    SelectionRecord {
        schema: "guard-cigar-selection.v2".into(),
        revision: 1,
        current: pointer("old-enrollment", SelectionData::LegacySaved),
        last_good: None,
        transaction: None,
    }
}
fn transaction(r: &SelectionRecord) -> SelectionTransaction {
    SelectionTransaction {
        request_id: "native-switch-1".into(),
        expected_service_generation: 5,
        before_settings_sha256: "4".repeat(64),
        after_settings_sha256: "5".repeat(64),
        source_semantic_sha256: "6".repeat(64),
        from: r.current.clone(),
        to: pointer(
            "catalog-final",
            SelectionData::Generation {
                generation_id: "7".repeat(64),
            },
        ),
        was_enabled: true,
        activate_target: true,
        reconnect_acknowledged: true,
        cancel_requested: false,
        phase: SelectionPhase::Prepared,
    }
}
#[test]
fn enrolled_identity_has_no_fabricated_public_build_source_or_manifest() {
    let r = record();
    r.validate().unwrap();
    let value = serde_json::to_value(&r).unwrap();
    let origin = &value["current"]["runtime"]["origin"];
    assert_eq!(origin["kind"], "enrolled");
    for name in [
        "identity",
        "build_id",
        "source_revision",
        "manifest_sha256",
        "release",
    ] {
        assert!(origin.get(name).is_none());
    }
    let mut invalid = value;
    invalid["current"]["runtime"]["origin"]["manifest_sha256"] = serde_json::json!("9".repeat(64));
    assert!(serde_json::from_value::<SelectionRecord>(invalid).is_err());
}
#[test]
fn last_good_changes_only_after_target_health_and_completed_publication() {
    let r = record();
    let mut prepared = r.begin(transaction(&r)).unwrap();
    for phase in [
        SelectionPhase::StopIntent,
        SelectionPhase::CommitIntent,
        SelectionPhase::Committed,
        SelectionPhase::Healthy,
    ] {
        prepared = prepared.advance(phase).unwrap();
        assert!(prepared.last_good.is_none());
    }
    let completed = prepared.advance(SelectionPhase::Completed).unwrap();
    assert_eq!(completed.last_good.as_ref(), Some(&r.current));
    assert_eq!(completed.current.runtime.installation_id, "catalog-final");
    assert_eq!(
        completed.advance(SelectionPhase::Prepared),
        Err(SwitchError::InvalidTransition)
    );
}
#[test]
fn recovery_observes_both_sides_of_config_and_record_commit() {
    use SelectionPhase::*;
    use SelectionRecovery::*;
    let r = record();
    let mut r = r.begin(transaction(&r)).unwrap();
    for (phase, before, after) in [
        (Prepared, PreservePrevious, RequireOperatorRecovery),
        (StopIntent, PreservePrevious, RequireOperatorRecovery),
        (CommitIntent, PreservePrevious, VerifyTarget),
        (Committed, RequireOperatorRecovery, VerifyTarget),
        (Healthy, RequireOperatorRecovery, VerifyTarget),
        (Completed, RequireOperatorRecovery, KeepTarget),
    ] {
        if phase != Prepared {
            r = r.advance(phase).unwrap();
        }
        assert_eq!(
            r.recovery("old-enrollment", &"4".repeat(64), true, true, true)
                .unwrap(),
            before
        );
        assert_eq!(
            r.recovery("catalog-final", &"5".repeat(64), true, true, true)
                .unwrap(),
            after
        );
        assert_eq!(
            r.recovery("catalog-final", &"8".repeat(64), true, true, true)
                .unwrap(),
            if phase == Completed {
                KeepTarget
            } else {
                RequireOperatorRecovery
            }
        );
        assert_eq!(
            r.recovery("unrelated", &"5".repeat(64), true, true, true),
            Err(SwitchError::SelectionConflict)
        );
    }
}
#[test]
fn committed_cancellation_requires_eligible_previous_and_never_claims_cancelled() {
    let r = record();
    let mut r = r.begin(transaction(&r)).unwrap();
    for phase in [
        SelectionPhase::StopIntent,
        SelectionPhase::CommitIntent,
        SelectionPhase::Committed,
    ] {
        r = r.advance(phase).unwrap();
    }
    r.transaction.as_mut().unwrap().cancel_requested = true;
    assert_eq!(
        r.recovery("catalog-final", &"5".repeat(64), true, true, true)
            .unwrap(),
        SelectionRecovery::RestorePrevious
    );
    assert_eq!(
        r.recovery("catalog-final", &"5".repeat(64), true, true, false)
            .unwrap(),
        SelectionRecovery::RequireOperatorRecovery
    );
    assert_eq!(
        r.advance(SelectionPhase::Cancelled),
        Err(SwitchError::InvalidTransition)
    );
}
#[test]
fn a_later_disabled_preference_never_restores_enable_or_requires_old_settings_bytes() {
    let r = record();
    let r = r.begin(transaction(&r)).unwrap();
    for p in [
        &r.transaction.as_ref().unwrap().from,
        &r.transaction.as_ref().unwrap().to,
    ] {
        assert_eq!(
            r.recovery(
                &p.runtime.installation_id,
                &"9".repeat(64),
                false,
                false,
                false
            )
            .unwrap(),
            SelectionRecovery::PreserveDisabled(Box::new(p.clone()))
        );
    }
}
#[test]
fn preparing_cannot_reuse_persistent_data_or_opt_in_or_skip_reconnect_consent() {
    let r = record();
    let mut t = transaction(&r);
    t.to.data = t.from.data.clone();
    assert_eq!(t.validate(), Err(SwitchError::InvalidJournal));
    t = transaction(&r);
    t.was_enabled = false;
    assert_eq!(t.validate(), Err(SwitchError::InvalidJournal));
    t = transaction(&r);
    t.reconnect_acknowledged = false;
    let prepared = r.begin(t).unwrap();
    assert_eq!(
        prepared.advance(SelectionPhase::StopIntent),
        Err(SwitchError::InvalidJournal)
    );
}
#[test]
fn retention_references_are_derived_from_current_last_good_and_pending_pairs() {
    let mut r = record();
    r.current.data = SelectionData::Generation {
        generation_id: "0".repeat(64),
    };
    r.last_good = Some(pointer(
        "earlier",
        SelectionData::Generation {
            generation_id: "8".repeat(64),
        },
    ));
    let r = r.begin(transaction(&r)).unwrap();
    assert_eq!(
        r.retained_generations().unwrap(),
        vec!["0".repeat(64), "7".repeat(64), "8".repeat(64)]
    );
    let cancelled = r.advance(SelectionPhase::Cancelled).unwrap();
    assert_eq!(
        cancelled.retained_generations().unwrap(),
        vec!["0".repeat(64), "8".repeat(64)]
    );
}
#[test]
fn same_sdk_catalog_replacement_retains_full_independent_identity() {
    let catalog = TrustedCatalog::bundled().unwrap();
    let first = catalog
        .prepare(
            &catalog.document().builds[0].identity.build_id,
            "darwin-arm64",
            false,
        )
        .unwrap();
    let mut r = record();
    r.current.runtime.origin = SelectionOrigin::Catalog {
        release: Box::new(first.binding().unwrap()),
    };
    let mut t = transaction(&r);
    let mut final_binding = first.binding().unwrap();
    final_binding.identity.build_id = "fixture-final-same-version".into();
    final_binding.identity.manifest_sha256 = "9".repeat(64);
    t.to.runtime.origin = SelectionOrigin::Catalog {
        release: Box::new(final_binding),
    };
    assert!(r.begin(t.clone()).is_ok());
    if let SelectionOrigin::Catalog { release } = &mut t.to.runtime.origin {
        release.identity.build_id = first.build().identity.build_id.clone();
    }
    assert_eq!(t.validate(), Err(SwitchError::InvalidJournal));
}
