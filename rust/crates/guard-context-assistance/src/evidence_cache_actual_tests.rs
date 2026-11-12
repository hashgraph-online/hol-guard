//! Actual SDK durability with the native cache coordinator and fresh authority.
use super::*;
use crate::{
    BundleApproval, ContextAssistanceConfig, RuntimeSelection, StorageMode, VerifiedRuntime,
};
use std::os::unix::fs::DirBuilderExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn runtime() -> VerifiedRuntime {
    let selection: RuntimeSelection = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit candidate selection"),
        )
        .unwrap(),
    )
    .unwrap();
    let approval: BundleApproval = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_APPROVAL").expect("explicit candidate approval"),
        )
        .unwrap(),
    )
    .unwrap();
    VerifiedRuntime::start(selection, &approval).unwrap()
}
fn doc(id: &str, text: &str) -> ContextDocument {
    ContextDocument {
        id: id.into(),
        text: text.into(),
        start_line: 1,
    }
}

#[test]
#[ignore = "requires the explicitly approved final CPython 3.14 and actual CIGAR 0.14.1 worker"]
fn actual_private_cache_recovers_reviewed_notes_and_removes_only_after_worker_close() {
    let home = Fixture(std::env::temp_dir().canonicalize().unwrap().join(format!(
        "guard-cache-sdk-{}-{}",
        std::process::id(),
        now()
    )));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&home.0)
        .unwrap();
    let config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "candidate".into(),
        storage: crate::Storage {
            mode: StorageMode::Sqlite,
            retention_hours: 1,
        },
        ..Default::default()
    };
    let cache = EvidenceCache::open(&home.0).unwrap();
    let mut first = runtime();
    let key = EvidenceCache::key("dashboard", &home.0, &first.status().worker_fingerprint).unwrap();
    let mut slot = cache.open_slot(&key, 1, now()).unwrap();
    let domain = first
        .open_persistent_broker_domain(&slot.domain_name(), &config, slot.broker_storage().unwrap())
        .unwrap();
    let docs = vec![doc(
        "recovery-document",
        "Fresh source permission is required after recovery.",
    )];
    let zero = first.broker_source_revision(&domain, "docs").unwrap();
    first
        .broker_replace_source(&domain, "docs", &zero, docs.clone())
        .unwrap();
    let zero = first
        .broker_source_revision(&domain, "guard:notes")
        .unwrap();
    slot.stage_notes(&zero.version, &[], now()).unwrap();
    let empty = first
        .broker_replace_source(&domain, "guard:notes", &zero, Vec::new())
        .unwrap();
    slot.commit_notes(&empty.version, None, now()).unwrap();
    let sources = BTreeSet::from(["docs".into(), "guard:notes".into()]);
    let client = first
        .grant_broker_client(
            &domain,
            sources.clone(),
            BTreeSet::from(["guard:notes".into()]),
            "current-policy",
            Duration::from_secs(60),
        )
        .unwrap();
    let before = first
        .compile_broker_context(&client, "recovery", vec!["recovery-document".into()])
        .unwrap();
    let notes = vec![doc(
        "note:reviewed",
        "A reviewed note supplies evidence and grants no approval.",
    )];
    let proposal = first
        .propose_broker_evidence(&before, "reviewed", empty, notes.clone())
        .unwrap();
    let proposal_id = proposal["proposal_id"].as_str().unwrap();
    let inspected = first.inspect_broker_proposal(&domain, proposal_id).unwrap();
    slot.stage_notes(&inspected.expected.version, &inspected.documents, now())
        .unwrap();
    let admitted = first.admit_broker_proposal(&domain, proposal_id).unwrap();
    slot.commit_notes(
        &admitted.version,
        Some(SavedNotes {
            documents: notes,
            basis: inspected.basis.into_keys().collect(),
            version: admitted.version.clone(),
            valid_until_ms: slot.expires_at_ms(),
        }),
        now(),
    )
    .unwrap();
    assert!(matches!(cache.forget_all(), Err(RuntimeError::Busy)));
    first.close();
    drop(slot);
    drop(cache);
    let cache = EvidenceCache::existing(&home.0).unwrap().unwrap();
    let mut slot = cache.open_slot(&key, 1, now()).unwrap();
    let mut second = runtime();
    let fresh = second
        .open_persistent_broker_domain(&slot.domain_name(), &config, slot.broker_storage().unwrap())
        .unwrap();
    let (revision, digest) = second.broker_source_digest(&fresh, "guard:notes").unwrap();
    assert_ne!(revision.epoch, admitted.epoch);
    assert_eq!(revision.version, admitted.version);
    slot.reconcile_notes(&revision.version, digest.as_deref(), now())
        .unwrap();
    assert!(matches!(
        second.grant_broker_client(
            &fresh,
            sources.clone(),
            BTreeSet::new(),
            "current-policy",
            Duration::from_secs(60)
        ),
        Err(RuntimeError::ScopeDenied)
    ));
    second.resume_broker_source(&fresh, "docs", docs).unwrap();
    second
        .resume_broker_source(
            &fresh,
            "guard:notes",
            slot.notes().unwrap().documents.clone(),
        )
        .unwrap();
    let new_client = second
        .grant_broker_client(
            &fresh,
            sources,
            BTreeSet::new(),
            "current-policy",
            Duration::from_secs(60),
        )
        .unwrap();
    let brief = second
        .compile_broker_context(
            &new_client,
            "recovery evidence",
            vec!["recovery-document".into(), "note:reviewed".into()],
        )
        .unwrap();
    assert!(brief.brief().rendered.contains("grants no approval"));
    assert!(second.explain_broker_context(&before).is_err());
    assert!(second.inspect_broker_proposal(&fresh, proposal_id).is_err());
    second.close_broker_domain(&fresh).unwrap();
    let domain_name = slot.domain_name();
    drop(slot);
    // Model a surviving SDK owner with no native coordinator lease, as after
    // parent loss. Its actual SQLite lock must still prevent cache removal.
    let sdk = home
        .0
        .join("context-assistance/saved-evidence")
        .join(&key)
        .join("sdk");
    let surviving = second
        .open_persistent_broker_domain(&domain_name, &config, BrokerStorage::inspect(&sdk).unwrap())
        .unwrap();
    assert!(matches!(cache.forget(&key), Err(RuntimeError::Busy)));
    assert!(sdk.join("broker.sqlite3").exists());
    second.close_broker_domain(&surviving).unwrap();
    cache.forget(&key).unwrap();
    second.close();
    assert_eq!(cache.summary().unwrap().slots, 0);
    println!("GUARD_CIGAR_NATIVE_CACHE_VERIFICATION reviewed_notes=true fresh_epoch=true restored_authority=false bounded_removal=true");
}

#[test]
#[ignore = "requires the explicitly approved final CPython 3.14 and actual CIGAR 0.14.1 worker"]
fn actual_sdk_admission_interruption_reconciles_uncommitted_intent_and_preserves_lost_committed_text(
) {
    let home = Fixture(std::env::temp_dir().canonicalize().unwrap().join(format!(
        "guard-cache-uncertain-{}-{}",
        std::process::id(),
        now()
    )));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&home.0)
        .unwrap();
    let config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "candidate".into(),
        storage: crate::Storage {
            mode: StorageMode::Sqlite,
            retention_hours: 1,
        },
        ..Default::default()
    };
    let cache = EvidenceCache::open(&home.0).unwrap();
    let mut first = runtime();
    let key = EvidenceCache::key("dashboard", &home.0, &first.status().worker_fingerprint).unwrap();
    let mut slot = cache.open_slot(&key, 1, now()).unwrap();
    let domain = first
        .open_persistent_broker_domain(&slot.domain_name(), &config, slot.broker_storage().unwrap())
        .unwrap();
    let docs = vec![doc(
        "interruption-source",
        "Admitted source evidence survives an interrupted host.",
    )];
    let empty = first.broker_source_revision(&domain, "docs").unwrap();
    first
        .broker_replace_source(&domain, "docs", &empty, docs.clone())
        .unwrap();
    let empty = first
        .broker_source_revision(&domain, "guard:notes")
        .unwrap();
    slot.stage_notes(&empty.version, &[], now()).unwrap();
    let empty = first
        .broker_replace_source(&domain, "guard:notes", &empty, Vec::new())
        .unwrap();
    slot.commit_notes(&empty.version, None, now()).unwrap();
    let notes = vec![doc(
        "note:interrupted",
        "Reviewed admission crossed the SDK commit but lost the native text record.",
    )];
    slot.stage_notes(&empty.version, &notes, now()).unwrap();
    // The first interruption occurs before an SDK admission. Reconcile its
    // actual stored version/digest; do not replay any mutation.
    first.close_broker_domain(&domain).unwrap();
    drop(slot);
    let mut slot = cache.open_slot(&key, 1, now()).unwrap();
    let domain = first
        .open_persistent_broker_domain(&slot.domain_name(), &config, slot.broker_storage().unwrap())
        .unwrap();
    let (revision, digest) = first.broker_source_digest(&domain, "guard:notes").unwrap();
    slot.reconcile_notes(&revision.version, digest.as_deref(), now())
        .unwrap();
    assert!(!slot.has_pending_write());
    first.resume_broker_source(&domain, "docs", docs).unwrap();
    first
        .resume_broker_source(&domain, "guard:notes", Vec::new())
        .unwrap();
    let client = first
        .grant_broker_client(
            &domain,
            BTreeSet::from(["docs".into(), "guard:notes".into()]),
            BTreeSet::from(["guard:notes".into()]),
            "current-policy",
            Duration::from_secs(60),
        )
        .unwrap();
    let context = first
        .compile_broker_context(
            &client,
            "source evidence",
            vec!["interruption-source".into()],
        )
        .unwrap();
    let proposed = first
        .propose_broker_evidence(&context, "interrupted:admission", revision, notes.clone())
        .unwrap();
    let id = proposed["proposal_id"].as_str().unwrap();
    let inspected = first.inspect_broker_proposal(&domain, id).unwrap();
    slot.stage_notes(&inspected.expected.version, &inspected.documents, now())
        .unwrap();
    let admitted = first.admit_broker_proposal(&domain, id).unwrap();
    // Lose the host generation after the actual SQLite commit and before its
    // native metadata commit. No pending/admitted note text was written here.
    first.close();
    drop(slot);
    let record = home
        .0
        .join("context-assistance/saved-evidence")
        .join(&key)
        .join("state.json");
    assert!(!std::fs::read_to_string(&record)
        .unwrap()
        .contains(&notes[0].text));
    let mut second = runtime();
    let mut slot = cache.open_slot(&key, 1, now()).unwrap();
    let domain = second
        .open_persistent_broker_domain(&slot.domain_name(), &config, slot.broker_storage().unwrap())
        .unwrap();
    let (revision, digest) = second.broker_source_digest(&domain, "guard:notes").unwrap();
    assert_eq!(revision.version, admitted.version);
    assert_ne!(revision.epoch, admitted.epoch);
    assert!(matches!(
        slot.reconcile_notes(&revision.version, digest.as_deref(), now()),
        Err(RuntimeError::StorageRepairRequired)
    ));
    assert!(slot.has_pending_write());
    assert!(slot.notes().is_none());
    assert!(
        record.exists(),
        "uncertain evidence must remain available for explicit repair"
    );
    assert!(matches!(
        second.grant_broker_client(
            &domain,
            BTreeSet::from(["docs".into(), "guard:notes".into()]),
            BTreeSet::new(),
            "current-policy",
            Duration::from_secs(60)
        ),
        Err(RuntimeError::ScopeDenied)
    ));
    second.close();
    slot.remove().unwrap();
    assert_eq!(cache.summary().unwrap().slots, 0);
    println!("GUARD_CIGAR_ACTUAL_ADMISSION_INTERRUPTION_VERIFICATION uncommitted_intent_reconciled=true sdk_committed_text_loss_requires_repair=true restored_authority=false automatic_mutation_replay=false");
}

#[path = "evidence_note_transfer_actual_tests.rs"]
mod note_transfer;
