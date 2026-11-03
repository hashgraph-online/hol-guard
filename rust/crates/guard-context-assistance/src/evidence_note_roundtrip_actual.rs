//! Reverse semantic data preparation after a newly admitted edit/deletion.
use super::*;

pub(super) struct Current<'a> {
    pub cache: &'a EvidenceCache,
    pub slot: &'a mut EvidenceSlot,
    pub domain: &'a crate::BrokerDomainHandle,
    pub runtime: &'a mut VerifiedRuntime,
    pub producer: &'a EvidenceUpgradeProducer,
}
pub(super) fn run(
    home: &Path,
    input: &serde_json::Value,
    scope: &EvidenceScope,
    current: Current<'_>,
    config: &ContextAssistanceConfig,
) {
    let client = current
        .runtime
        .grant_broker_client(
            current.domain,
            BTreeSet::from(["docs".into(), "guard:notes".into()]),
            BTreeSet::from(["guard:notes".into()]),
            "explicit-new-human-review",
            Duration::from_secs(120),
        )
        .unwrap();
    let context = current
        .runtime
        .compile_broker_context(&client, "release", vec!["source:example".into()])
        .unwrap();
    let expected = current
        .runtime
        .broker_source_revision(current.domain, "guard:notes")
        .unwrap();
    let changed = vec![doc(
        "note:after-update",
        "An admitted edit after import survives reverse data preparation.",
    )];
    let proposal = current
        .runtime
        .propose_broker_evidence(&context, "reviewed-replacement", expected, changed)
        .unwrap();
    let id = proposal["proposal_id"].as_str().unwrap();
    let inspected = current
        .runtime
        .inspect_broker_proposal(current.domain, id)
        .unwrap();
    current
        .slot
        .stage_notes(&inspected.expected.version, &inspected.documents, now())
        .unwrap();
    let admitted = current
        .runtime
        .admit_broker_proposal(current.domain, id)
        .unwrap();
    current
        .slot
        .commit_notes(
            &admitted.version,
            Some(SavedNotes {
                documents: inspected.documents,
                basis: inspected.basis.into_keys().collect(),
                version: admitted.version.clone(),
                valid_until_ms: current.slot.expires_at_ms(),
            }),
            now(),
        )
        .unwrap();
    assert_eq!(current.slot.notes_version(), "2");
    let transfer = current
        .slot
        .export_reviewed_notes(
            scope,
            current.producer,
            current.runtime,
            current.domain,
            now(),
        )
        .unwrap();
    let enrolled = input["fixture_enrolled_source"] == true;
    let (mut previous_sdk, previous_producer) = start_kind(
        input,
        home,
        input["python"].as_str().unwrap(),
        "reverse",
        config,
        enrolled,
    );
    assert_eq!(previous_sdk.status().release.is_none(), enrolled);
    assert_eq!(previous_sdk.status().interpreter.version, [3, 14, 7]);
    assert_ne!(
        previous_producer.identity_sha256(),
        current.producer.identity_sha256()
    );
    let store = crate::EvidenceGenerationStore::existing(home)
        .unwrap()
        .unwrap();
    let generation = store
        .prepare(
            crate::EvidencePreparation {
                request_id: "reverse-after-admitted-edit",
                source: current.cache,
                snapshot: &current.cache.upgrade_inventory(now()).unwrap(),
                from: current.producer,
                to: &previous_producer,
                notes: std::slice::from_ref(&transfer),
            },
            now(),
        )
        .unwrap();
    let target_cache = generation.open_cache().unwrap();
    let mut target_slot = target_cache
        .open_slot(
            &transfer.target_key(scope, &previous_producer).unwrap(),
            1,
            now(),
        )
        .unwrap();
    let domain = previous_sdk
        .open_persistent_broker_domain(
            &target_slot.domain_name(),
            config,
            target_slot.broker_storage().unwrap(),
        )
        .unwrap();
    assert!(matches!(
        target_slot.import_reviewed_notes(
            scope,
            &previous_producer,
            &mut previous_sdk,
            &domain,
            &transfer,
            now()
        ),
        Err(RuntimeError::ScopeDenied)
    ));
    let zero = previous_sdk
        .broker_source_revision(&domain, "docs")
        .unwrap();
    previous_sdk
        .broker_replace_source(
            &domain,
            "docs",
            &zero,
            vec![doc(
                "source:example",
                "A fresh scope admits these exact synthetic release notes.",
            )],
        )
        .unwrap();
    target_slot
        .import_reviewed_notes(
            scope,
            &previous_producer,
            &mut previous_sdk,
            &domain,
            &transfer,
            now(),
        )
        .unwrap();
    assert!(target_slot
        .notes()
        .unwrap()
        .documents
        .iter()
        .all(|d| d.id != "note:reviewed"));
    assert_eq!(
        target_slot.notes().unwrap().documents[0].id,
        "note:after-update"
    );
    let view = previous_sdk
        .grant_broker_client(
            &domain,
            BTreeSet::from(["docs".into(), "guard:notes".into()]),
            BTreeSet::new(),
            "fresh-reverse-permission",
            Duration::from_secs(60),
        )
        .unwrap();
    let brief = previous_sdk
        .compile_broker_context(&view, "edited evidence", vec!["note:after-update".into()])
        .unwrap();
    assert!(brief.brief().rendered.contains("survives reverse"));
    assert!(!brief.brief().rendered.contains("Previously reviewed"));
    assert!(previous_sdk.explain_broker_context(&context).is_err());
    assert!(
        target_slot.notes().unwrap().valid_until_ms <= current.slot.notes().unwrap().valid_until_ms
    );
    generation
        .finish_scope(
            scope,
            &previous_producer,
            &target_slot,
            &mut previous_sdk,
            &domain,
            now(),
        )
        .unwrap();
    assert_eq!(generation.describe().unwrap()["phase"], "ready");
    previous_sdk.close();
}
