//! Actual semantic note transfer on exact final SDK bytes. Both runtimes and
//! every source/note are synthetic and confined to this disposable profile.
use super::*;
use crate::{inspect_release_bundle, EvidenceScope, EvidenceUpgradeProducer};
use guard_cigar_release::{CatalogTrust, Feature, Qualification, TrustedCatalog, TrustedKey};
use ring::signature::{Ed25519KeyPair, KeyPair};

#[path = "evidence_cold_note_actual_tests.rs"]
mod cold;
#[path = "evidence_note_transfer_recovery_actual.rs"]
mod recovery;
#[path = "evidence_note_roundtrip_actual.rs"]
mod roundtrip;

fn release() -> guard_cigar_release::ResolvedRelease {
    let mut document = TrustedCatalog::bundled().unwrap().document().clone();
    document.builds[0].platforms[0].qualification = Qualification::GuardQualified;
    document.builds[0].platforms[0].qualification_receipt_sha256 = Some("c".repeat(64));
    document.builds[0].platforms[0].features = vec![Feature::Graph, Feature::Persistence];
    let pair = Ed25519KeyPair::from_seed_unchecked(&[113; 32]).unwrap();
    let key = TrustedKey {
        key_id: "note-transfer-test-only".into(),
        public_key: pair.public_key().as_ref().try_into().unwrap(),
        not_before: 1,
        not_after: u64::MAX,
        revoked: false,
    };
    let payload = serde_json::to_string(&document).unwrap();
    let mut message = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
    message.extend_from_slice(payload.as_bytes());
    let signature: String = pair
        .sign(&message)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let envelope = serde_json::to_vec(
        &serde_json::json!({"schema":"guard-cigar-signed-catalog.v1","key_id":key.key_id,
        "payload":payload,"signature_hex":signature}),
    )
    .unwrap();
    TrustedCatalog::verify(
        &envelope,
        &CatalogTrust {
            keys: &[key],
            checkpoint: None,
            now: document.issued_at,
        },
    )
    .unwrap()
    .for_activation(
        &document.builds[0].identity.build_id,
        "darwin-arm64",
        false,
        &[Feature::Graph, Feature::Persistence],
    )
    .unwrap()
}
fn private(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn start(
    input: &serde_json::Value,
    home: &Path,
    python: &str,
    name: &str,
    config: &ContextAssistanceConfig,
) -> (VerifiedRuntime, EvidenceUpgradeProducer) {
    start_kind(input, home, python, name, config, false)
}
fn start_kind(
    input: &serde_json::Value,
    home: &Path,
    python: &str,
    name: &str,
    config: &ContextAssistanceConfig,
    enrolled: bool,
) -> (VerifiedRuntime, EvidenceUpgradeProducer) {
    let mut selection: RuntimeSelection = serde_json::from_slice(
        &std::fs::read(input["current_selection"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    selection.python = PathBuf::from(python);
    selection.python_bundle = None;
    selection.verified_python = None;
    selection.work_dir = home.join(name);
    private(&selection.work_dir);
    let release = release();
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (mut runtime, approval) = if enrolled {
        let approval = crate::inspect_bundle(&selection, "darwin-arm64").unwrap();
        let runtime = VerifiedRuntime::start_cancellable(selection, &approval, cancel).unwrap();
        (runtime, approval)
    } else {
        let approval = inspect_release_bundle(&selection, &release).unwrap();
        let runtime =
            VerifiedRuntime::start_release_cancellable(selection, &approval, &release, cancel)
                .unwrap();
        (runtime, approval)
    };
    let doctor = home.join(format!("{name}-doctor"));
    private(&doctor);
    runtime.verify_persistence_compile(&doctor, config).unwrap();
    let producer = if enrolled {
        assert!(runtime.status().release.is_none());
        EvidenceUpgradeProducer::from_enrolled_runtime(&runtime).unwrap()
    } else {
        assert!(EvidenceUpgradeProducer::from_enrolled_runtime(&runtime).is_err());
        EvidenceUpgradeProducer::new(&release, &approval).unwrap()
    };
    (runtime, producer)
}
#[test]
#[ignore = "requires exact final SDK selection plus CPython3.14.7/3.14.10 in GUARD_CIGAR_NOTE_TRANSFER_TEST_INPUT"]
fn actual_reviewed_notes_cross_python_producers_preserve_expiry_and_require_fresh_source_content() {
    reviewed_notes_round_trip(false);
}
#[test]
#[ignore = "requires exact final SDK bytes explicitly enrolled as a candidate; not original b47380"]
fn actual_enrolled_candidate_notes_migrate_without_public_relabeling_and_reverse_after_edits() {
    reviewed_notes_round_trip(true);
}
fn reviewed_notes_round_trip(enrolled_source: bool) {
    let input = std::env::var_os("GUARD_CIGAR_NOTE_TRANSFER_TEST_INPUT")
        .expect("explicit task-private artifact selection");
    let mut input: serde_json::Value =
        serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    // Test-fixture routing only. This never enters an SDK or runtime API.
    input["fixture_enrolled_source"] = enrolled_source.into();
    let home = Fixture(std::env::temp_dir().canonicalize().unwrap().join(format!(
        "guard-note-transfer-{}-{}",
        std::process::id(),
        now()
    )));
    private(&home.0);
    let config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "synthetic-note-transfer".into(),
        storage: crate::Storage {
            mode: StorageMode::Sqlite,
            retention_hours: 1,
        },
        ..Default::default()
    };
    let started = std::time::Instant::now();
    let (mut old, from) = start_kind(
        &input,
        &home.0,
        input["python"].as_str().unwrap(),
        "old",
        &config,
        enrolled_source,
    );
    let scope = EvidenceScope::new("dashboard", &home.0).unwrap();
    let cache = EvidenceCache::open(&home.0).unwrap();
    let legacy =
        EvidenceCache::key("dashboard", &home.0, &old.status().worker_fingerprint).unwrap();
    let mut slot = cache.open_slot(&legacy, 1, now()).unwrap();
    let old_domain = old
        .open_persistent_broker_domain(&slot.domain_name(), &config, slot.broker_storage().unwrap())
        .unwrap();
    let source = vec![doc(
        "source:example",
        "A fresh scope admits these exact synthetic release notes.",
    )];
    let zero = old.broker_source_revision(&old_domain, "docs").unwrap();
    old.broker_replace_source(&old_domain, "docs", &zero, source.clone())
        .unwrap();
    let zero = old
        .broker_source_revision(&old_domain, "guard:notes")
        .unwrap();
    slot.stage_notes("0", &[], now()).unwrap();
    let empty = old
        .broker_replace_source(&old_domain, "guard:notes", &zero, Vec::new())
        .unwrap();
    slot.commit_notes(&empty.version, None, now()).unwrap();
    let allowed = BTreeSet::from(["docs".into(), "guard:notes".into()]);
    let old_client = old
        .grant_broker_client(
            &old_domain,
            allowed.clone(),
            BTreeSet::from(["guard:notes".into()]),
            "old-current-permission",
            Duration::from_secs(180),
        )
        .unwrap();
    let before = old
        .compile_broker_context(&old_client, "release", vec!["source:example".into()])
        .unwrap();
    let notes = vec![doc(
        "note:reviewed",
        "Previously reviewed evidence is preserved without granting command approval.",
    )];
    let proposed = old
        .propose_broker_evidence(&before, "original-human-admission", empty, notes)
        .unwrap();
    let id = proposed["proposal_id"].as_str().unwrap();
    let proposal = old.inspect_broker_proposal(&old_domain, id).unwrap();
    slot.stage_notes(&proposal.expected.version, &proposal.documents, now())
        .unwrap();
    let admitted = old.admit_broker_proposal(&old_domain, id).unwrap();
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
    let prior_state = std::fs::read(slot.directory.path.join("state.json")).unwrap();
    let prior_db = std::fs::read(slot.directory.path.join("sdk/broker.sqlite3")).unwrap();
    let transfer = slot
        .export_reviewed_notes(&scope, &from, &mut old, &old_domain, now())
        .unwrap();
    let unrelated = EvidenceScope::new("another-app", &home.0).unwrap();
    assert!(matches!(
        slot.export_reviewed_notes(&unrelated, &from, &mut old, &old_domain, now()),
        Err(RuntimeError::ScopeDenied)
    ));
    let provenance = transfer.describe()["source_release"].clone();
    if enrolled_source {
        assert_eq!(provenance["qualification"], "verified_enrolled_candidate");
        assert!(provenance.get("identity").is_none());
        assert!(provenance.get("source_revision").is_none());
    } else {
        assert_eq!(
            provenance["identity"]["source_revision"],
            "10dd521dec8224d0957365a90111158e43c9d87f"
        );
    }
    let summary = transfer.describe().to_string();
    assert!(!summary.contains("Previously reviewed"));
    assert!(!summary.contains(home.0.to_str().unwrap()));
    let (mut target, to) = start(
        &input,
        &home.0,
        input["target_python"].as_str().unwrap(),
        "target",
        &config,
    );
    assert_ne!(from.identity_sha256(), to.identity_sha256());
    let store = crate::EvidenceGenerationStore::open(&home.0).unwrap();
    let snapshot = cache.upgrade_inventory(now()).unwrap();
    let prepared = store
        .prepare(
            crate::EvidencePreparation {
                request_id: "actual-prepared-notes",
                source: &cache,
                snapshot: &snapshot,
                from: &from,
                to: &to,
                notes: std::slice::from_ref(&transfer),
            },
            now(),
        )
        .unwrap();
    let id = prepared.id().to_owned();
    drop(prepared);
    drop(store);
    let store = crate::EvidenceGenerationStore::existing(&home.0)
        .unwrap()
        .unwrap();
    let prepared = store.load(&id).unwrap();
    let transfer = prepared.transfer(&scope, &to, now()).unwrap();
    let recovery_generation = store
        .prepare(
            crate::EvidencePreparation {
                request_id: "actual-recovery-notes",
                source: &cache,
                snapshot: &snapshot,
                from: &from,
                to: &to,
                notes: std::slice::from_ref(&transfer),
            },
            now(),
        )
        .unwrap();
    let target_cache = prepared.open_cache().unwrap();
    let target_key = transfer.target_key(&scope, &to).unwrap();
    let mut target_slot = target_cache.open_slot(&target_key, 1, now()).unwrap();
    let target_domain = target
        .open_persistent_broker_domain(
            &target_slot.domain_name(),
            &config,
            target_slot.broker_storage().unwrap(),
        )
        .unwrap();
    assert!(matches!(
        target_slot.import_reviewed_notes(
            &scope,
            &to,
            &mut target,
            &target_domain,
            &transfer,
            now()
        ),
        Err(RuntimeError::ScopeDenied)
    ));
    assert_eq!(
        target
            .broker_source_revision(&target_domain, "guard:notes")
            .unwrap()
            .version,
        "0"
    );
    let zero = target
        .broker_source_revision(&target_domain, "docs")
        .unwrap();
    let wrong = target
        .broker_replace_source(
            &target_domain,
            "docs",
            &zero,
            vec![doc(
                "source:example",
                "Changed content cannot inherit the old note.",
            )],
        )
        .unwrap();
    assert!(matches!(
        target_slot.import_reviewed_notes(
            &scope,
            &to,
            &mut target,
            &target_domain,
            &transfer,
            now()
        ),
        Err(RuntimeError::ContextStale)
    ));
    target
        .broker_replace_source(&target_domain, "docs", &wrong, source)
        .unwrap();
    target_slot
        .import_reviewed_notes(&scope, &to, &mut target, &target_domain, &transfer, now())
        .unwrap();
    assert!(target_slot.notes().unwrap().documents == slot.notes().unwrap().documents);
    assert!(target_slot.notes().unwrap().valid_until_ms <= slot.notes().unwrap().valid_until_ms);
    assert!(target_slot.expires_at_ms() <= slot.expires_at_ms());
    assert_eq!(target_slot.state.created_at_ms, slot.state.created_at_ms);
    let new_client = target
        .grant_broker_client(
            &target_domain,
            allowed,
            BTreeSet::new(),
            "fresh-target-permission",
            Duration::from_secs(60),
        )
        .unwrap();
    let current = target
        .compile_broker_context(
            &new_client,
            "reviewed release",
            vec!["source:example".into(), "note:reviewed".into()],
        )
        .unwrap();
    assert!(current.brief().rendered.contains("Previously reviewed"));
    assert!(target.explain_broker_context(&before).is_err());
    prepared
        .finish_scope(
            &scope,
            &to,
            &target_slot,
            &mut target,
            &target_domain,
            now(),
        )
        .unwrap();
    prepared
        .finish_scope(
            &scope,
            &to,
            &target_slot,
            &mut target,
            &target_domain,
            now(),
        )
        .unwrap();
    assert_eq!(prepared.describe().unwrap()["phase"], "ready");
    let sealed = std::fs::read_to_string(
        home.0
            .join("context-assistance/evidence-generations")
            .join(&id)
            .join("state.json"),
    )
    .unwrap();
    assert!(
        !sealed.contains("Previously reviewed"),
        "successful import removes prepared note copies"
    );
    assert!(matches!(
        store.discard_prepared(&id),
        Err(RuntimeError::ScopeDenied)
    ));
    assert!(matches!(
        crate::EvidenceGenerationStore::forget_existing(&home.0),
        Err(RuntimeError::Busy)
    ));
    target.close_broker_domain(&target_domain).unwrap();
    recovery::run(
        &home.0,
        &input,
        &scope,
        &to,
        &recovery_generation,
        &mut target,
        &config,
    );
    assert_eq!(old.status().interpreter.version, [3, 14, 7]);
    assert_eq!(target.status().interpreter.version, [3, 14, 10]);
    old.compile_broker_context(
        &old_client,
        "still responsive",
        vec!["note:reviewed".into()],
    )
    .unwrap();
    assert_eq!(
        prior_state,
        std::fs::read(slot.directory.path.join("state.json")).unwrap()
    );
    assert_eq!(
        prior_db,
        std::fs::read(slot.directory.path.join("sdk/broker.sqlite3")).unwrap()
    );
    target.close();
    old.close();
    assert!(EvidenceUpgradeProducer::from_enrolled_runtime(&old).is_err());
    drop(target_slot);
    drop(target_cache);
    assert_eq!(
        crate::EvidenceGenerationStore::forget_existing(&home.0).unwrap(),
        3
    );
    println!(
        "CIGAR_REVIEWED_NOTE_TRANSFER_PROOF={}",
        serde_json::json!({"schema":"guard-cigar-reviewed-note-transfer-proof.v1",
        "scope":if enrolled_source {"local-source-macos-arm64-final0141-bytes-enrolled-not-b47380"} else {"local-source-macos-arm64-final0141-test-catalog-only"},
        "enrolled_source":enrolled_source,"public_relabeling":false,"source_python":[3,14,7],"target_python":[3,14,10],
        "source_producer":from.identity_sha256(),"target_producer":to.identity_sha256(),"source_checkpoint_and_manifest_unchanged":true,
        "old_sdk_still_answered":true,"fresh_missing_or_changed_sources_refused":true,"old_context_refused_by_target":true,
        "notes_equal":true,"durable_generation_reloaded":true,"prepared_copies_removed_after_import":true,"explicit_forget_cleared_generations":true,"native_commit_recovered_after_sdk_restart":true,"sdk_mutation_not_replayed":true,"reverse_data_preparation_after_edit":true,"removed_note_not_resurrected":true,"expiry_not_extended":true,"source_creation_preserved":true,"raw_sdk_copy":false,"authority_restored":false,
        "elapsed_ms":started.elapsed().as_millis()})
    );
}
