//! Actual immutable byte reuse; never changes the user's Guard profile.
use super::*;
use guard_cigar_release::{CatalogDocument, CatalogTrust, TrustedKey};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

fn catalog(features: Vec<Feature>) -> TrustedCatalog {
    let mut doc: CatalogDocument = super::super::actual::approved_catalog_requirement(None)
        .document()
        .clone();
    doc.revision += features.len() as u64;
    doc.builds[0].platforms[0].features = features;
    let pair = Ed25519KeyPair::from_seed_unchecked(&[109; 32]).unwrap();
    let key = TrustedKey {
        key_id: "reuse-real-sdk-test-only".into(),
        public_key: pair.public_key().as_ref().try_into().unwrap(),
        not_before: 500,
        not_after: 3000,
        revoked: false,
    };
    let payload = serde_json::to_string(&doc).unwrap();
    let mut message = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
    message.extend_from_slice(payload.as_bytes());
    let signature: String = pair
        .sign(&message)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let envelope = serde_json::to_vec(
        &json!({"schema":"guard-cigar-signed-catalog.v1", "key_id":key.key_id,
        "payload":payload,"signature_hex":signature}),
    )
    .unwrap();
    TrustedCatalog::verify(
        &envelope,
        &CatalogTrust {
            keys: &[key],
            checkpoint: None,
            now: 1000,
        },
    )
    .unwrap()
}
fn wait(jobs: &Jobs, home: &Path, id: &str) -> Value {
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(125));
        match jobs.get(home, id) {
            Ok(value) if value["worker_live"] == false => return value,
            Ok(_) => {}
            Err(code) if code == error("install_metadata_changed") => {}
            Err(code) => panic!("{code}"),
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn inventory(root: &Path) -> BTreeMap<PathBuf, (u64, i64, i64, u32)> {
    use std::os::unix::fs::MetadataExt;
    fn visit(path: &Path, result: &mut BTreeMap<PathBuf, (u64, i64, i64, u32)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                visit(&path, result);
            } else {
                result.insert(
                    path,
                    (meta.ino(), meta.mtime(), meta.mtime_nsec(), meta.mode()),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, &mut result);
    result
}
#[test]
#[ignore = "requires exact final CIGAR0.14.1 wheels and CPython3.14.7 in GUARD_CIGAR_INSTALL_TEST_INPUT"]
fn actual_receipt_refresh_reuses_historical_slot_and_keeps_existing_sdk_responsive() {
    let input =
        std::env::var_os("GUARD_CIGAR_INSTALL_TEST_INPUT").expect("explicit task-private inputs");
    let input: Value = serde_json::from_slice(&fs::read(input).unwrap()).unwrap();
    let fixture = Fixture::new();
    let interpreter = interpreters::register_interpreter(
        &fixture.home,
        Path::new(input["python"].as_str().unwrap()),
    )
    .unwrap();
    let first = catalog(vec![Feature::Graph]);
    let all = catalog(vec![
        Feature::Graph,
        Feature::Sharing,
        Feature::Persistence,
        Feature::ExecutionContext,
    ]);
    let build_id = first.document().builds[0].identity.build_id.clone();
    let first_release = first
        .for_activation(&build_id, "darwin-arm64", false, &[Feature::Graph])
        .unwrap();
    let wheels: BTreeMap<String, PathBuf> =
        serde_json::from_value(input["wheels"].clone()).unwrap();
    cache::import(&fixture.home, &first_release, &wheels).unwrap();
    let jobs = Jobs::default();
    let request = InstallRequest {
        job_id: "install-for-refresh".into(),
        build_id: build_id.clone(),
        interpreter_id: interpreter.interpreter_id.clone(),
    };
    jobs.install_catalog(&fixture.home, request.clone(), &first)
        .unwrap();
    let installed = wait(&jobs, &fixture.home, &request.job_id);
    assert_eq!(installed["phase"], "ready", "{installed}");
    let mut old = load(&fixture.home, installed["runtime_id"].as_str().unwrap()).unwrap();
    let original_slot = old.managed_slot.clone().unwrap();
    let original_id = old.runtime_id.clone();
    let key = owner_key::read(&fixture.home).unwrap();
    let prior = guard_cigar_release::verify_installation_receipt(
        old.receipt.as_ref().unwrap(),
        &key,
        &versioned::context(&old, &fixture.home).unwrap(),
    )
    .unwrap();
    // Emulate a previously shipped slot derivation and opaque installation ID.
    // Only fixture directories move; SDK/package bytes are never rewritten.
    let historical = "c".repeat(64);
    for parent in ["bundles", "work"] {
        let parent = fixture.home.join("context-assistance").join(parent);
        fs::rename(parent.join(&original_slot), parent.join(&historical)).unwrap();
    }
    old.runtime_id = "historical-runtime-id".into();
    old.managed_slot = Some(historical.clone());
    old.selection.site_packages = fixture
        .home
        .join("context-assistance/bundles")
        .join(&historical)
        .join("site-packages");
    old.selection.work_dir = fixture
        .home
        .join("context-assistance/work")
        .join(&historical);
    let mut metadata = prior.metadata().clone();
    metadata.context_sha256 = versioned::context(&old, &fixture.home).unwrap();
    old.receipt = Some(guard_cigar_release::seal_installation_receipt(&metadata, &key).unwrap());
    write_record(&fixture, &old);
    fs::remove_file(
        root(&fixture.home, false)
            .unwrap()
            .join(record_name(&original_id)),
    )
    .unwrap();
    let before_record = reuse::record_sha(&old).unwrap();
    let before_tree = inventory(&old.selection.site_packages);
    let config = guard_context_assistance::ContextAssistanceConfig {
        runtime_id: old.runtime_id.clone(),
        ..Default::default()
    };
    let mut current = old
        .start_cancellable(&fixture.home, &config, Arc::new(AtomicBool::new(false)))
        .unwrap();
    let mut qualification = config.clone();
    qualification.features.agent_context = true;
    qualification.features.shared_agents = true;
    let mut request = InstallRequest {
        job_id: "cancel-refresh".into(),
        ..request
    };
    let (entered, pending) = mpsc::sync_channel(1);
    let (_resume, proceed) = mpsc::sync_channel(1);
    let started = Instant::now();
    let initial = jobs
        .install_test_catalog(
            &fixture.home,
            request.clone(),
            &all,
            InstallPause { entered, proceed },
        )
        .unwrap();
    assert_eq!(initial["operation"], "verify");
    assert_eq!(initial["runtime_id"], old.runtime_id);
    pending.recv_timeout(Duration::from_secs(115)).unwrap();
    current.verify_shared_compile(&qualification).unwrap();
    assert_eq!(
        reuse::record_sha(&load(&fixture.home, &old.runtime_id).unwrap()).unwrap(),
        before_record
    );
    jobs.cancel(&fixture.home, &request.job_id).unwrap();
    assert_eq!(
        wait(&jobs, &fixture.home, &request.job_id)["phase"],
        "cancelled"
    );
    assert_eq!(
        reuse::record_sha(&load(&fixture.home, &old.runtime_id).unwrap()).unwrap(),
        before_record
    );
    current.verify_shared_compile(&qualification).unwrap();
    request.job_id = "complete-refresh".into();
    jobs.install_catalog(&fixture.home, request.clone(), &all)
        .unwrap();
    let completed = wait(&jobs, &fixture.home, &request.job_id);
    assert_eq!(completed["phase"], "ready", "{completed}");
    let refreshed = load(&fixture.home, &old.runtime_id).unwrap();
    assert_eq!(
        refreshed.verification_job_id.as_deref(),
        Some(request.job_id.as_str())
    );
    assert_eq!(refreshed.managed_slot, old.managed_slot);
    assert_eq!(
        refreshed.selection.site_packages,
        old.selection.site_packages
    );
    assert_eq!(refreshed.selection.work_dir, old.selection.work_dir);
    assert_eq!(before_tree, inventory(&refreshed.selection.site_packages));
    assert_eq!(
        super::super::super::super::list(&fixture.home)
            .unwrap()
            .len(),
        1
    );
    versioned::resolve(
        &fixture.home,
        &refreshed,
        &all.document().builds[0].platforms[0].features,
    )
    .unwrap();
    current.verify_shared_compile(&qualification).unwrap();
    assert!(current.status().active);
    let mut lost = store::get(&fixture.home, &request.job_id).unwrap().unwrap();
    store::save(&fixture.home, &mut lost, Phase::Publishing, "publishing").unwrap();
    assert_eq!(
        jobs.recover(&fixture.home, &request.job_id).unwrap()["phase"],
        "ready"
    );
    assert_eq!(
        jobs.install_catalog(&fixture.home, request.clone(), &all)
            .unwrap()["phase"],
        "ready"
    );
    current.close();
    let preferences = crate::guard_config_load::context_assistance_config(&fixture.home).unwrap();
    assert!(!preferences.requested.enabled);
    assert!(preferences.requested.runtime_id.is_empty());
    let id = record_name(&request.job_id);
    assert!(!fixture
        .home
        .join("context-assistance/verification")
        .join(id.trim_end_matches(".json"))
        .exists());
    println!(
        "CIGAR_RECEIPT_REFRESH_PROOF={}",
        json!({"schema":"guard-cigar-receipt-refresh-proof.v1",
        "scope":"local-source-macos-arm64-test-catalog-only", "guard_binary_sha256":crate::resident_state::runtime_digest().unwrap(),
        "build_id":build_id,"historical_slot_reused":true,"opaque_runtime_id_preserved":true,
        "qualified_features":all.document().builds[0].platforms[0].features,"bundle_inodes_modes_mtimes_unchanged":true,
        "old_sdk_answered_before_and_after_cancel_and_commit":true,"lost_reply_reconciled_without_probe":true,
        "off_preserved":true,"selection_unchanged":true,"elapsed_ms":started.elapsed().as_millis()})
    );
}
