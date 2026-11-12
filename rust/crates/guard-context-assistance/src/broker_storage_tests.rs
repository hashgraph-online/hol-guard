use super::*;
use crate::{
    BundleApproval, ContextAssistanceConfig, ContextDocument, RuntimeSelection, StorageMode,
    VerifiedRuntime,
};
use std::collections::BTreeSet;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "guard-cigar-store-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn doc(id: &str, text: &str) -> ContextDocument {
    ContextDocument {
        id: id.into(),
        text: text.into(),
        start_line: 1,
    }
}
fn runtime() -> VerifiedRuntime {
    let selection: RuntimeSelection = serde_json::from_slice(
        &std::fs::read(std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit selection"))
            .unwrap(),
    )
    .unwrap();
    let approval: BundleApproval = serde_json::from_slice(
        &std::fs::read(std::env::var_os("GUARD_CIGAR_TEST_APPROVAL").expect("explicit approval"))
            .unwrap(),
    )
    .unwrap();
    VerifiedRuntime::start(selection, &approval).unwrap()
}

#[test]
fn private_storage_rejects_links_permissions_unknown_files_size_and_identity_changes() {
    let fixture = Fixture::new();
    let root = &fixture.0;
    let handle = BrokerStorage::inspect(root).unwrap();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(handle.revalidate().is_err());
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = root.join("broker.sqlite3");
    std::fs::write(&db, b"synthetic database bytes").unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(handle.revalidate().is_err());
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    let sealed = BrokerStorage::inspect(root).unwrap();
    std::fs::hard_link(&db, root.join("other")).unwrap();
    assert!(sealed.revalidate().is_err());
    std::fs::remove_file(root.join("other")).unwrap();
    std::fs::rename(&db, root.join("old")).unwrap();
    std::fs::write(&db, b"replacement").unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(sealed.revalidate().is_err());
    std::fs::remove_file(root.join("old")).unwrap();
    assert!(
        sealed.revalidate().is_err(),
        "replacing the database must invalidate the pinned file even after the old name is removed"
    );
    let opened = std::fs::OpenOptions::new().write(true).open(&db).unwrap();
    opened.set_len(DATABASE_BYTES + 1).unwrap();
    assert!(BrokerStorage::inspect(root).is_err());
    drop(opened);
    std::fs::remove_file(&db).unwrap();
    std::os::unix::fs::symlink("outside", &db).unwrap();
    assert!(BrokerStorage::inspect(root).is_err());
    std::fs::remove_file(&db).unwrap();
    let child = root.join("store");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&child)
        .unwrap();
    let pinned = BrokerStorage::inspect(&child).unwrap();
    std::fs::rename(&child, root.join("prior-store")).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&child)
        .unwrap();
    assert!(pinned.revalidate().is_err());
}

#[test]
#[ignore = "requires the explicitly approved final CPython 3.14 and actual CIGAR 0.14.1 worker"]
fn actual_persistent_sdk_recovery_needs_fresh_catalog_grants_and_contexts() {
    let fixture = Fixture::new();
    let mut config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "candidate".into(),
        ..Default::default()
    };
    config.storage.mode = StorageMode::Sqlite;
    let mut first = runtime();
    let domain = first
        .open_persistent_broker_domain(
            "durable:fixture",
            &config,
            BrokerStorage::inspect(&fixture.0).unwrap(),
        )
        .unwrap();
    assert_eq!(
        first.broker_storage_status(&domain).unwrap(),
        json!({"mode":"sqlite-checkpoint.v1","restored":false})
    );
    let initial = first.broker_source_revision(&domain, "docs").unwrap();
    let docs = vec![doc(
        "readme",
        "Reviewed recovery retains admitted project evidence.",
    )];
    let admitted = first
        .broker_replace_source(&domain, "docs", &initial, docs.clone())
        .unwrap();
    let empty = first
        .broker_source_revision(&domain, "guard:notes")
        .unwrap();
    let empty = first
        .broker_replace_source(&domain, "guard:notes", &empty, Vec::new())
        .unwrap();
    let sources = BTreeSet::from(["docs".into(), "guard:notes".into()]);
    let a = first
        .grant_broker_client(
            &domain,
            sources.clone(),
            BTreeSet::from(["guard:notes".into()]),
            "policy:one",
            Duration::from_secs(300),
        )
        .unwrap();
    let context = first
        .compile_broker_context(&a, "reviewed recovery", vec!["readme".into()])
        .unwrap();
    let notes = vec![doc(
        "note:reviewed",
        "Reviewed recovery note is supporting evidence.",
    )];
    let p = first
        .propose_broker_evidence(&context, "reviewed", empty, notes.clone())
        .unwrap();
    let notes_revision = first
        .admit_broker_proposal(&domain, p["proposal_id"].as_str().unwrap())
        .unwrap();
    let old = first
        .compile_broker_context(
            &a,
            "reviewed recovery",
            vec!["readme".into(), "note:reviewed".into()],
        )
        .unwrap();
    first
        .propose_broker_evidence(
            &old,
            "unadmitted",
            notes_revision,
            vec![doc(
                "note:pending",
                "Unadmitted content must not be restored.",
            )],
        )
        .unwrap();
    first.close();
    let mut restored = runtime();
    let fresh = restored
        .open_persistent_broker_domain(
            "durable:fixture",
            &config,
            BrokerStorage::inspect(&fixture.0).unwrap(),
        )
        .unwrap();
    assert_eq!(
        restored.broker_storage_status(&fresh).unwrap(),
        json!({"mode":"sqlite-checkpoint.v1","restored":true})
    );
    let current = restored.broker_source_revision(&fresh, "docs").unwrap();
    assert_ne!(current.epoch, admitted.epoch);
    assert_eq!(current.version, admitted.version);
    assert!(matches!(
        restored.grant_broker_client(
            &fresh,
            sources.clone(),
            BTreeSet::new(),
            "policy:one",
            Duration::from_secs(300)
        ),
        Err(RuntimeError::ScopeDenied)
    ));
    assert!(matches!(
        restored.resume_broker_source(
            &fresh,
            "docs",
            vec![doc("readme", "Forged recovered text.")]
        ),
        Err(RuntimeError::ContextStale)
    ));
    assert!(
        matches!(
            restored.resume_broker_source(&fresh, "guard:notes", notes.clone()),
            Err(RuntimeError::ContextStale)
        ),
        "omitting a required source cannot restore its derived notes"
    );
    restored.resume_broker_source(&fresh, "docs", docs).unwrap();
    restored
        .resume_broker_source(&fresh, "guard:notes", notes)
        .unwrap();
    let b = restored
        .grant_broker_client(
            &fresh,
            sources,
            BTreeSet::new(),
            "policy:one",
            Duration::from_secs(300),
        )
        .unwrap();
    let result = restored
        .compile_broker_context(
            &b,
            "reviewed recovery",
            vec!["readme".into(), "note:reviewed".into()],
        )
        .unwrap();
    assert!(result
        .brief()
        .rendered
        .contains("admitted project evidence"));
    assert!(result.brief().rendered.contains("Reviewed recovery note"));
    assert!(!result.brief().rendered.contains("Unadmitted content"));
    assert!(restored.explain_broker_context(&old).is_err());
    assert!(restored.broker_proposal_status(&b, "reviewed").is_err());
    assert!(restored.broker_proposal_status(&b, "unadmitted").is_err());
    assert!(restored.broker_source_revision(&domain, "docs").is_err());
    restored.close();
    std::fs::write(fixture.0.join("broker.sqlite3"), b"invalid database header").unwrap();
    let mut corrupted = runtime();
    assert!(corrupted
        .open_persistent_broker_domain(
            "durable:fixture",
            &config,
            BrokerStorage::inspect(&fixture.0).unwrap()
        )
        .is_err());
    corrupted.close();
    println!(
        "GUARD_CIGAR_PERSISTENT_CORE_VERIFICATION={}",
        json!({"schema":"guard-cigar-persistent-core-verification.v1","status":"passed",
        "qualification":"native_library_actual_sdk_only","checks":["explicit_private_directory","real_sqlite_storage_handshake","committed_evidence_survives_worker_group_loss",
        "fresh_sdk_epoch_preserves_versions","empty_native_catalog_cannot_grant_sources","forged_catalog_text_refused","fresh_source_readmission_matches_saved_provenance",
        "reviewed_notes_retain_upstream_versions","new_client_and_context_required","old_handles_and_proposals_refused","unadmitted_content_not_restored","corrupt_store_refuses_activation"]})
    );
}
