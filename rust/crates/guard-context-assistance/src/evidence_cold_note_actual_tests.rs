//! Actual SDK cold proof, deferred carry and unknown-write reconciliation.
//! Fixture ownership rows are trusted synthetic inputs; the native Service
//! companion case verifies real profile MAC attribution and disabled intent.
use super::*;
use crate::{
    EvidenceCacheLocation, EvidenceGenerationStore, EvidencePreparation, EvidenceScopeOwner,
};
fn seed(
    runtime: &mut VerifiedRuntime,
    cache: &EvidenceCache,
    scope: &EvidenceScope,
    home: &Path,
    config: &ContextAssistanceConfig,
) -> (String, crate::BrokerClientHandle, Vec<ContextDocument>) {
    let key = EvidenceCache::key("dashboard", home, &runtime.status().worker_fingerprint).unwrap();
    let mut slot = cache.open_slot(&key, 1, now()).unwrap();
    let domain = runtime
        .open_persistent_broker_domain(&slot.domain_name(), config, slot.broker_storage().unwrap())
        .unwrap();
    let docs = vec![doc(
        "source:cold",
        "Freshly admitted source content is required again.",
    )];
    let zero = runtime.broker_source_revision(&domain, "docs").unwrap();
    runtime
        .broker_replace_source(&domain, "docs", &zero, docs.clone())
        .unwrap();
    let zero = runtime
        .broker_source_revision(&domain, "guard:notes")
        .unwrap();
    slot.stage_notes("0", &[], now()).unwrap();
    let empty = runtime
        .broker_replace_source(&domain, "guard:notes", &zero, Vec::new())
        .unwrap();
    slot.commit_notes(&empty.version, None, now()).unwrap();
    let client = runtime
        .grant_broker_client(
            &domain,
            BTreeSet::from(["docs".into(), "guard:notes".into()]),
            BTreeSet::from(["guard:notes".into()]),
            "original-synthetic-scope",
            Duration::from_secs(180),
        )
        .unwrap();
    let context = runtime
        .compile_broker_context(&client, "source", vec!["source:cold".into()])
        .unwrap();
    let offered = runtime
        .propose_broker_evidence(
            &context,
            "human-reviewed",
            empty,
            vec![doc(
                "note:cold",
                "Reviewed data must never recreate an old grant.",
            )],
        )
        .unwrap();
    let proposal = runtime
        .inspect_broker_proposal(&domain, offered["proposal_id"].as_str().unwrap())
        .unwrap();
    slot.stage_notes(&proposal.expected.version, &proposal.documents, now())
        .unwrap();
    let admitted = runtime
        .admit_broker_proposal(&domain, &proposal.proposal_id)
        .unwrap();
    slot.commit_notes(
        &admitted.version,
        Some(SavedNotes {
            documents: proposal.documents,
            basis: proposal.basis.into_keys().collect(),
            version: admitted.version.clone(),
            valid_until_ms: slot.expires_at_ms(),
        }),
        now(),
    )
    .unwrap();
    runtime.close_broker_domain(&domain).unwrap();
    assert_eq!(scope.namespace_sha256().len(), 64);
    (key, client, docs)
}
#[test]
#[ignore = "requires exact final0141 bytes and task-private external CPython3.14.7/3.14.10"]
fn actual_cold_notes_keep_ancestral_provenance_and_recover_deferred_import_without_replay() {
    let input: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var_os("GUARD_CIGAR_NOTE_TRANSFER_TEST_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    let home = Fixture(std::env::temp_dir().canonicalize().unwrap().join(format!(
        "guard-cold-note-proof-{}-{}",
        std::process::id(),
        now()
    )));
    private(&home.0);
    let config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "cold-note-fixture".into(),
        storage: crate::Storage {
            mode: StorageMode::Sqlite,
            retention_hours: 1,
        },
        ..Default::default()
    };
    let (mut first, from) = start_kind(
        &input,
        &home.0,
        input["python"].as_str().unwrap(),
        "original",
        &config,
        true,
    );
    let scope = EvidenceScope::new("dashboard", &home.0).unwrap();
    let cache = EvidenceCache::open(&home.0).unwrap();
    let (key, old_client, docs) = seed(&mut first, &cache, &scope, &home.0, &config);
    first.close();
    drop(first);
    let before = std::fs::read(
        home.0
            .join("context-assistance/saved-evidence")
            .join(&key)
            .join("state.json"),
    )
    .unwrap();
    let (mut source, measured_from) = start_kind(
        &input,
        &home.0,
        input["python"].as_str().unwrap(),
        "cold-source",
        &config,
        true,
    );
    assert_eq!(from.identity_sha256(), measured_from.identity_sha256());
    let mut off = config.clone();
    off.enabled = false;
    std::fs::write(home.0.join("config.toml"),"[context_assistance]\nenabled=false\nruntime_id=\"cold-note-fixture\"\n[context_assistance.storage]\nmode=\"sqlite\"\nretention_hours=1\n").unwrap();
    let off_bytes = std::fs::read(home.0.join("config.toml")).unwrap();
    assert!(cache
        .export_cold_notes(&home.0, &[], &from, &mut source, &off, now())
        .is_err());
    let owners = [EvidenceScopeOwner {
        location: EvidenceCacheLocation::Legacy,
        slot_key: key.clone(),
        scope_sha256: scope.namespace_sha256().into(),
    }];
    let exports = cache
        .export_cold_notes(&home.0, &owners, &from, &mut source, &off, now())
        .unwrap();
    assert_eq!(exports.len(), 1);
    assert_eq!(
        std::fs::read(
            home.0
                .join("context-assistance/saved-evidence")
                .join(&key)
                .join("state.json")
        )
        .unwrap(),
        before
    );
    assert_eq!(
        std::fs::read(home.0.join("config.toml")).unwrap(),
        off_bytes
    );
    let (mut target, to) = start(
        &input,
        &home.0,
        input["target_python"].as_str().unwrap(),
        "target",
        &config,
    );
    assert!(matches!(
        target.compile_broker_context(&old_client, "must refuse old grant", Vec::new()),
        Err(RuntimeError::ScopeDenied)
    ));
    let store = EvidenceGenerationStore::open(&home.0).unwrap();
    let g1 = store
        .prepare_cold(
            EvidencePreparation {
                request_id: "cold-one",
                source: &cache,
                snapshot: &cache.upgrade_inventory(now()).unwrap(),
                from: &from,
                to: &to,
                notes: &exports,
            },
            now(),
        )
        .unwrap();
    let original = exports[0].semantic_sha256().unwrap();
    let original_docs = exports[0].documents_sha256().unwrap();
    let expiry = exports[0].describe()["expires_at_ms"].clone();
    let c1 = g1.open_cache().unwrap();
    let g2 = store
        .prepare_cold(
            EvidencePreparation {
                request_id: "cold-two",
                source: &c1,
                snapshot: &c1.upgrade_inventory(now()).unwrap(),
                from: &to,
                to: &from,
                notes: &[],
            },
            now(),
        )
        .unwrap();
    drop(c1);
    let ancestral = g2.transfer(&scope, &from, now()).unwrap();
    assert_eq!(ancestral.semantic_sha256().unwrap(), original);
    assert_eq!(
        g2.describe().unwrap()["source_producer_sha256"],
        to.identity_sha256()
    );
    assert_eq!(
        ancestral.describe()["source_producer_sha256"],
        from.identity_sha256()
    );
    assert_eq!(
        ancestral.describe()["source_release"]["qualification"],
        "verified_enrolled_candidate"
    );
    let c2 = g2.open_cache().unwrap();
    let g3 = store
        .prepare_cold(
            EvidencePreparation {
                request_id: "cold-three",
                source: &c2,
                snapshot: &c2.upgrade_inventory(now()).unwrap(),
                from: &from,
                to: &to,
                notes: &[],
            },
            now(),
        )
        .unwrap();
    drop(c2);
    drop(cache);
    source.close();
    drop(source);
    let target_cache = g3.open_cache().unwrap();
    let target_key = scope.key(&to).unwrap();
    let wrong_cache = EvidenceCache::existing(&home.0).unwrap().unwrap();
    let mut wrong_slot = wrong_cache.open_slot(&target_key, 1, now()).unwrap();
    let wrong_domain = target
        .open_persistent_broker_domain(
            &wrong_slot.domain_name(),
            &config,
            wrong_slot.broker_storage().unwrap(),
        )
        .unwrap();
    let zero = target
        .broker_source_revision(&wrong_domain, "docs")
        .unwrap();
    target
        .broker_replace_source(&wrong_domain, "docs", &zero, docs.clone())
        .unwrap();
    assert!(matches!(
        g3.admit_deferred_scope(
            &scope,
            &to,
            &mut wrong_slot,
            &mut target,
            &wrong_domain,
            now()
        ),
        Err(RuntimeError::ScopeDenied)
    ));
    assert_eq!(wrong_slot.notes_version(), "0");
    assert_eq!(
        target
            .broker_source_revision(&wrong_domain, "guard:notes")
            .unwrap()
            .version,
        "0"
    );
    target.close_broker_domain(&wrong_domain).unwrap();
    wrong_slot.remove().unwrap();
    drop(wrong_cache);
    let mut slot = target_cache.open_slot(&target_key, 1, now()).unwrap();
    let domain = target
        .open_persistent_broker_domain(&slot.domain_name(), &config, slot.broker_storage().unwrap())
        .unwrap();
    assert!(g3
        .admit_deferred_scope(&scope, &to, &mut slot, &mut target, &domain, now())
        .is_err());
    assert_eq!(slot.notes_version(), "0");
    let zero = target.broker_source_revision(&domain, "docs").unwrap();
    let wrong = target
        .broker_replace_source(
            &domain,
            "docs",
            &zero,
            vec![doc(
                "source:cold",
                "Different source bytes cannot inherit a review.",
            )],
        )
        .unwrap();
    assert!(matches!(
        g3.admit_deferred_scope(&scope, &to, &mut slot, &mut target, &domain, now()),
        Err(RuntimeError::ContextStale)
    ));
    target
        .broker_replace_source(&domain, "docs", &wrong, docs.clone())
        .unwrap();
    transfer::INTERRUPT_BEFORE_NOTE_COMMIT.with(|flag| flag.set(true));
    assert!(matches!(
        g3.admit_deferred_scope(&scope, &to, &mut slot, &mut target, &domain, now()),
        Err(RuntimeError::StorageOutcomeUnknown)
    ));
    assert!(slot.has_pending_write());
    assert_eq!(
        target
            .broker_source_revision(&domain, "guard:notes")
            .unwrap()
            .version,
        "1"
    );
    target.close_broker_domain(&domain).unwrap();
    drop(slot);
    let mut slot = target_cache.open_slot(&target_key, 1, now()).unwrap();
    let domain = target
        .open_persistent_broker_domain(&slot.domain_name(), &config, slot.broker_storage().unwrap())
        .unwrap();
    assert_eq!(
        target.broker_storage_status(&domain).unwrap()["restored"],
        true
    );
    target.resume_broker_source(&domain, "docs", docs).unwrap();
    g3.admit_deferred_scope(&scope, &to, &mut slot, &mut target, &domain, now())
        .unwrap();
    assert!(!slot.has_pending_write());
    assert_eq!(slot.notes_version(), "1");
    assert_eq!(
        target
            .broker_source_revision(&domain, "guard:notes")
            .unwrap()
            .version,
        "1"
    );
    assert_eq!(g3.describe().unwrap()["deferred_scopes"], 0);
    let transferred = slot
        .export_reviewed_notes(&scope, &to, &mut target, &domain, now())
        .unwrap();
    assert_eq!(transferred.documents_sha256().unwrap(), original_docs);
    assert!(transferred.describe()["expires_at_ms"].as_u64().unwrap() <= expiry.as_u64().unwrap());
    assert_eq!(
        std::fs::read(home.0.join("config.toml")).unwrap(),
        off_bytes
    );
    target.close_broker_domain(&domain).unwrap();
    drop(slot);
    drop(target_cache);
    target.close();
    println!(
        "CIGAR_COLD_NOTE_RECOVERY_PROOF={}",
        serde_json::json!({"schema":"guard-cigar-cold-note-recovery-proof.v1","scope":"local-macos-arm64-final0141-external3147-31410-test-only-qualified-source-and-target-synthetic-trusted-ownership-rows-not-native-operator-job-not-newer-sdk","closed_store_export_left_manifest_and_off_intent_unchanged":true,"missing_ownership_refused":true,"old_client_refused":true,"three_deferred_generations_kept_original_provenance_and_expiry":true,"wrong_generation_slot_refused_before_note_mutation":true,"missing_or_changed_fresh_source_refused":true,"interrupted_import_reconciled_sdk_version_one_without_replay":true,"complete_reviewed_data_preserved":true})
    );
}
