//! Real SDK mutation followed by an interrupted native acknowledgement.
use super::*;

pub(super) fn run(
    home: &Path,
    input: &serde_json::Value,
    scope: &EvidenceScope,
    producer: &EvidenceUpgradeProducer,
    generation: &crate::PreparedEvidenceGeneration,
    target: &mut VerifiedRuntime,
    config: &ContextAssistanceConfig,
) {
    let transfer = generation.transfer(scope, producer, now()).unwrap();
    let cache = generation.open_cache().unwrap();
    let key = transfer.target_key(scope, producer).unwrap();
    let mut slot = cache.open_slot(&key, 1, now()).unwrap();
    let domain = target
        .open_persistent_broker_domain(&slot.domain_name(), config, slot.broker_storage().unwrap())
        .unwrap();
    let docs = vec![doc(
        "source:example",
        "A fresh scope admits these exact synthetic release notes.",
    )];
    let zero = target.broker_source_revision(&domain, "docs").unwrap();
    target
        .broker_replace_source(&domain, "docs", &zero, docs.clone())
        .unwrap();
    crate::evidence_cache::transfer::INTERRUPT_BEFORE_NOTE_COMMIT.with(|fault| fault.set(true));
    assert!(matches!(
        slot.import_reviewed_notes(scope, producer, target, &domain, &transfer, now()),
        Err(RuntimeError::StorageOutcomeUnknown)
    ));
    assert!(slot.has_pending_write());
    assert!(slot.notes().is_none());
    assert_eq!(
        target
            .broker_source_revision(&domain, "guard:notes")
            .unwrap()
            .version,
        "1"
    );
    target.close();
    drop(slot);
    drop(cache);
    let (restarted, observed) = start(
        input,
        home,
        input["target_python"].as_str().unwrap(),
        "target-restarted",
        config,
    );
    assert_eq!(observed.identity_sha256(), producer.identity_sha256());
    *target = restarted;
    drop(transfer);
    let store = crate::EvidenceGenerationStore::existing(home)
        .unwrap()
        .unwrap();
    let reloaded = store.load(generation.id()).unwrap();
    let transfer = reloaded.transfer(scope, producer, now()).unwrap();
    let cache = reloaded.open_cache().unwrap();
    let mut slot = cache.open_slot(&key, 1, now()).unwrap();
    let domain = target
        .open_persistent_broker_domain(&slot.domain_name(), config, slot.broker_storage().unwrap())
        .unwrap();
    assert!(matches!(
        slot.recover_reviewed_note_import(scope, producer, target, &domain, &transfer, now()),
        Err(RuntimeError::ScopeDenied)
    ));
    target.resume_broker_source(&domain, "docs", docs).unwrap();
    slot.recover_reviewed_note_import(scope, producer, target, &domain, &transfer, now())
        .unwrap();
    assert!(!slot.has_pending_write());
    assert_eq!(slot.notes_version(), "1");
    // Repeated acknowledgement recovery observes the same real SDK write.
    slot.recover_reviewed_note_import(scope, producer, target, &domain, &transfer, now())
        .unwrap();
    assert_eq!(
        target
            .broker_source_revision(&domain, "guard:notes")
            .unwrap()
            .version,
        "1"
    );
    let client = target
        .grant_broker_client(
            &domain,
            BTreeSet::from(["docs".into(), "guard:notes".into()]),
            BTreeSet::new(),
            "fresh-recovered-permission",
            Duration::from_secs(60),
        )
        .unwrap();
    let brief = target
        .compile_broker_context(&client, "recovered evidence", vec!["note:reviewed".into()])
        .unwrap();
    assert!(brief.brief().rendered.contains("Previously reviewed"));
    reloaded
        .finish_scope(scope, producer, &slot, target, &domain, now())
        .unwrap();
    assert_eq!(reloaded.describe().unwrap()["phase"], "ready");
    roundtrip::run(
        home,
        input,
        scope,
        roundtrip::Current {
            cache: &cache,
            slot: &mut slot,
            domain: &domain,
            runtime: target,
            producer,
        },
        config,
    );
}
