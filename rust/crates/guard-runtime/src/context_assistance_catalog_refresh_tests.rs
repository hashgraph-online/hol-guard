//! Synthetic transport payloads, real native trust/storage/worker lifecycle.
//! No production feed, root, SDK qualification or network request is invented.
use super::*;
use crate::policy_store::context_assistance_registry::catalog::{self, feed, Authority, PublicKey};
use guard_cigar_release::{CatalogDocument, Qualification};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
struct Fixture {
    home: PathBuf,
    key: Ed25519KeyPair,
    now: u64,
}
impl Fixture {
    fn new() -> Self {
        let home = crate::resident_state::ensure_private_directory(
            &std::env::temp_dir().join(format!(
                "guard-cigar-refresh-{}-{}",
                std::process::id(),
                crate::unique_nanos::unique_nanos()
            )),
            true,
        )
        .unwrap();
        fs::write(
            home.join("config.toml"),
            "mode='enforce'\n[context_assistance]\nenabled=false\nruntime_id='preserved'\n",
        )
        .unwrap();
        Self {
            home,
            key: Ed25519KeyPair::from_seed_unchecked(&[68; 32]).unwrap(),
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    fn authority(&self) -> Authority {
        Authority {
            schema: "guard-cigar-catalog-authority.v1".into(),
            keys: vec![PublicKey {
                key_id: "refresh-test-only".into(),
                public_key_hex: hex::encode(self.key.public_key().as_ref()),
                not_before: 1,
                not_after: u64::MAX,
                revoked: false,
            }],
        }
    }
    fn feed(&self) -> feed::Feed {
        feed::Feed {
            schema: "guard-cigar-catalog-feed.v1".into(),
            url: Some("https://catalog.example.com/cigar.json".into()),
        }
    }
    fn configure(&self) {
        catalog::configure(&self.home, self.authority()).unwrap();
        feed::configure(&self.home, self.feed()).unwrap();
    }
    fn document(&self) -> CatalogDocument {
        let mut d = TrustedCatalog::bundled().unwrap().document().clone();
        d.revision += 1;
        d.issued_at = self.now - 1;
        d.expires_at = self.now + 3600;
        d.builds[0].platforms[0].features = vec![guard_cigar_release::Feature::Graph];
        d.builds[0].platforms[0].qualification = Qualification::GuardQualified;
        d.builds[0].platforms[0].qualification_receipt_sha256 = Some("6".repeat(64));
        d
    }
    fn sign(&self, d: &CatalogDocument) -> Vec<u8> {
        let payload = serde_json::to_string(d).unwrap();
        let mut message = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
        message.extend_from_slice(payload.as_bytes());
        serde_json::to_vec(&json!({"schema":"guard-cigar-signed-catalog.v1","key_id":"refresh-test-only","payload":payload,"signature_hex":hex::encode(self.key.sign(&message).as_ref())})).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.home).unwrap();
    }
}
fn wait(jobs: &Jobs, home: &Path, id: &str) -> Value {
    let start = Instant::now();
    loop {
        let job = jobs.get(home, id).unwrap();
        if job["worker_live"] == false {
            return job;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "{job}");
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn progress(f: &Fixture, id: &str) -> catalog_store::Job {
    let now = store::now().unwrap();
    catalog_store::Job {
        schema: "guard-cigar-catalog-refresh-job.v1".into(),
        job_id: id.into(),
        request_sha256: catalog_store::request_sha(id).unwrap(),
        feed_sha256: f.feed().fingerprint().unwrap(),
        target: None,
        phase: store::Phase::Queued,
        code: "queued".into(),
        created_at_ms: now,
        updated_at_ms: now,
        deadline_at_ms: now + 30_000,
    }
}
#[test]
fn refresh_requires_separate_feed_roots_and_opaque_resident_input() {
    let f = Fixture::new();
    let jobs = Jobs::default();
    let before = fs::read(f.home.join("config.toml")).unwrap();
    assert!(jobs
        .refresh_catalog(&f.home, "no-feed")
        .unwrap_err()
        .ends_with("cigar_catalog_feed_unavailable"));
    for url in [
        "http://catalog.example.com/feed",
        "https://catalog.example.com:8443/feed",
        "https://user:pass@catalog.example.com/feed",
        "https://catalog.example.com/feed?token=value",
        "https://catalog.example.com/feed#x",
        "https://127.0.0.1/feed",
        "https://[::1]/feed",
        "https://localhost/feed",
    ] {
        let mut feed = f.feed();
        feed.url = Some(url.into());
        assert!(feed::configure(&f.home, feed)
            .unwrap_err()
            .ends_with("cigar_catalog_feed_invalid"));
    }
    feed::configure(&f.home, f.feed()).unwrap();
    assert_eq!(
        catalog::status(&f.home).unwrap()["remote_feed_configured"],
        true
    );
    assert!(jobs
        .refresh_catalog(&f.home, "no-roots")
        .unwrap_err()
        .ends_with("cigar_catalog_trust_unavailable"));
    let service = crate::context_assistance_service::Service::default();
    assert!(service.versions(&f.home,json!({"action":"refresh_catalog","job_id":"injected","url":"https://other.example.com/feed"})).unwrap_err().ends_with("versions_request_invalid"));
    assert!(jobs.list(&f.home).unwrap().is_empty());
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), before);
    assert!(!f.home.join("cigar-catalog-state/key").exists());
}
#[test]
fn refresh_publishes_signed_data_without_selecting_starting_or_changing_preferences() {
    let f = Fixture::new();
    f.configure();
    let jobs = Jobs::default();
    let before = fs::read(f.home.join("config.toml")).unwrap();
    let bytes = f.sign(&f.document());
    let queued = jobs
        .refresh_catalog_inner(&f.home, "check", Some(Box::new(move |_, _| Ok(bytes))))
        .unwrap();
    assert_eq!(queued["operation"], "refresh_catalog");
    assert_eq!(queued["activation_granted"], false);
    let ready = wait(&jobs, &f.home, "check");
    assert_eq!(ready["phase"], "ready", "{ready}");
    assert_eq!(
        ready["catalog_checkpoint"],
        catalog::status(&f.home).unwrap()["checkpoint"]
    );
    assert_eq!(
        jobs.refresh_catalog(&f.home, "check").unwrap()["catalog_checkpoint"],
        ready["catalog_checkpoint"]
    );
    assert_eq!(jobs.list(&f.home).unwrap().len(), 1);
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), before);
    for name in ["installations", "bundles", "python", "work"] {
        assert!(
            !f.home.join("context-assistance").join(name).exists(),
            "{name}"
        );
    }
    let text = ready.to_string();
    assert!(!text.contains("example.com"));
    assert!(!text.contains("public_key_hex"));
}
#[test]
fn cancellation_keeps_the_profile_owner_until_worker_acknowledges_and_never_imports() {
    let f = Fixture::new();
    f.configure();
    let jobs = Jobs::default();
    let bytes = f.sign(&f.document());
    let (entered, seen) = mpsc::sync_channel(1);
    let (proceed, pending) = mpsc::sync_channel(1);
    jobs.refresh_catalog_inner(
        &f.home,
        "cancel",
        Some(Box::new(move |control, _| {
            entered.send(()).unwrap();
            pending.recv_timeout(Duration::from_secs(10)).unwrap();
            control.checkpoint().map_err(|e| error(e.code()))?;
            Ok(bytes)
        })),
    )
    .unwrap();
    seen.recv_timeout(Duration::from_secs(5)).unwrap();
    let other = Jobs::default();
    other.cancel(&f.home, "cancel").unwrap();
    assert!(catalog::configure(&f.home, f.authority())
        .unwrap_err()
        .ends_with("install_busy"));
    assert!(feed::configure(&f.home, f.feed())
        .unwrap_err()
        .ends_with("install_busy"));
    assert!(other
        .recover(&f.home, "cancel")
        .unwrap_err()
        .ends_with("install_busy"));
    assert!(!f.home.join("cigar-catalog-state/key").exists());
    std::thread::sleep(Duration::from_millis(300));
    proceed.send(()).unwrap();
    let cancelled = wait(&jobs, &f.home, "cancel");
    assert_eq!(cancelled["phase"], "cancelled", "{cancelled}");
    assert!(!f.home.join("cigar-catalog-state/catalog.json").exists());
    assert!(!f.home.join("cigar-catalog-state/key").exists());
    feed::configure(&f.home, f.feed()).unwrap();
}
#[test]
fn rejected_signature_or_replay_keeps_the_authenticated_cache_and_worker_recovers() {
    let f = Fixture::new();
    f.configure();
    let jobs = Jobs::default();
    let d = f.document();
    let signed = f.sign(&d);
    catalog::import(&f.home, &signed).unwrap();
    let before = fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap();
    let mut broken: Value = serde_json::from_slice(&signed).unwrap();
    broken["signature_hex"] = json!("0".repeat(128));
    let raw = serde_json::to_vec(&broken).unwrap();
    jobs.refresh_catalog_inner(&f.home, "bad", Some(Box::new(move |_, _| Ok(raw))))
        .unwrap();
    let failed = wait(&jobs, &f.home, "bad");
    assert_eq!(failed["phase"], "failed", "{failed}");
    assert!(failed["code"].as_str().unwrap().contains("signature"));
    assert_eq!(
        fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap(),
        before
    );
    let mut next = d.clone();
    next.revision += 1;
    catalog::import(&f.home, &f.sign(&next)).unwrap();
    let newer = fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap();
    jobs.refresh_catalog_inner(&f.home, "replay", Some(Box::new(move |_, _| Ok(signed))))
        .unwrap();
    let failed = wait(&jobs, &f.home, "replay");
    assert_eq!(failed["phase"], "failed", "{failed}");
    assert!(failed["code"]
        .as_str()
        .unwrap()
        .ends_with("cigar_catalog_replayed"));
    assert_eq!(
        fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap(),
        newer
    );
}
#[test]
fn interrupted_progress_can_only_confirm_the_identical_authenticated_current_cache() {
    let f = Fixture::new();
    f.configure();
    let jobs = Jobs::default();
    let raw = f.sign(&f.document());
    catalog::import(&f.home, &raw).unwrap();
    let cache = fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap();
    let checkpoint = catalog::installed(&f.home)
        .unwrap()
        .catalog
        .checkpoint()
        .clone();
    let mut forged = progress(&f, "forged");
    let mut different = checkpoint.clone();
    different.revision += 1;
    forged.target = Some(different);
    catalog_store::save(&f.home, &mut forged, store::Phase::Publishing, "publishing").unwrap();
    let failed = jobs.recover(&f.home, "forged").unwrap();
    assert_eq!(failed["phase"], "failed");
    assert_eq!(
        fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap(),
        cache
    );
    let mut committed = progress(&f, "committed");
    committed.target = Some(checkpoint);
    catalog_store::save(
        &f.home,
        &mut committed,
        store::Phase::Publishing,
        "publishing",
    )
    .unwrap();
    let ready = jobs.recover(&f.home, "committed").unwrap();
    assert_eq!(ready["phase"], "ready");
    assert_eq!(
        fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap(),
        cache
    );
    let mut unsigned: Value = serde_json::from_slice(&cache).unwrap();
    unsigned["mac"] = json!("0".repeat(64));
    fs::write(
        f.home.join("cigar-catalog-state/catalog.json"),
        serde_json::to_vec(&unsigned).unwrap(),
    )
    .unwrap();
    let mut invalid = progress(&f, "invalid");
    invalid.target = committed.target;
    catalog_store::save(
        &f.home,
        &mut invalid,
        store::Phase::Publishing,
        "publishing",
    )
    .unwrap();
    assert!(jobs
        .recover(&f.home, "invalid")
        .unwrap_err()
        .ends_with("cigar_catalog_state_unauthenticated"));
}
#[test]
fn refresh_job_ids_and_capacity_are_shared_with_install_python_and_switch_jobs() {
    let f = Fixture::new();
    f.configure();
    let jobs = Jobs::default();
    for i in 0..store::MAX_JOBS {
        let mut job = progress(&f, &format!("saved-{i}"));
        catalog_store::save(&f.home, &mut job, store::Phase::Failed, "interrupted").unwrap();
    }
    assert_eq!(jobs.list(&f.home).unwrap().len(), store::MAX_JOBS);
    assert!(jobs
        .refresh_catalog(&f.home, "overflow")
        .unwrap_err()
        .ends_with("install_job_limit"));
    assert!(jobs
        .install(
            &f.home,
            InstallRequest {
                job_id: "saved-0".into(),
                build_id: "opaque".into(),
                interpreter_id: "opaque".into()
            }
        )
        .unwrap_err()
        .ends_with("install_idempotency_conflict"));
    assert!(jobs
        .setup_interpreter(
            &f.home,
            SetupInterpreterRequest {
                job_id: "saved-0".into(),
                build_id: "opaque".into()
            }
        )
        .unwrap_err()
        .ends_with("install_idempotency_conflict"));
    assert!(native_job_id_exists(&f.home, "saved-0").unwrap());
    assert_eq!(total_job_count(&f.home).unwrap(), store::MAX_JOBS);
}

#[test]
fn refresh_deadline_prevents_publication_and_owned_cleanup_preserves_foreign_links() {
    let f = Fixture::new();
    f.configure();
    let owner = feed::begin(&f.home).unwrap();
    let mut job = progress(&f, "deadline");
    job.deadline_at_ms = store::now().unwrap() + 40;
    catalog_store::save(&f.home, &mut job, store::Phase::Queued, "queued").unwrap();
    let code = catalog_worker::run(
        &f.home,
        &mut job,
        &owner,
        Arc::new(AtomicBool::new(false)),
        Some(Box::new(|control, _| loop {
            control.checkpoint().map_err(|e| error(e.code()))?;
            std::thread::sleep(Duration::from_millis(5));
        })),
    )
    .unwrap_err();
    assert!(code.ends_with("deadline_exceeded"), "{code}");
    catalog_worker::fail(&f.home, &mut job, &code).unwrap();
    assert_eq!(
        Jobs::default().get(&f.home, "deadline").unwrap()["phase"],
        "failed"
    );
    assert!(!f.home.join("cigar-catalog-state/catalog.json").exists());
    drop(owner);
    let mut job = progress(&f, "cleanup");
    catalog_store::save(
        &f.home,
        &mut job,
        store::Phase::RecoveryRequired,
        "cigar_catalog_cleanup_pending",
    )
    .unwrap();
    let parent = store::directory(&f.home, "catalog-downloads", true).unwrap();
    let path = parent.join(record_name(&job.job_id).trim_end_matches(".json"));
    crate::resident_state::ensure_private_directory_under(&path, &f.home, true).unwrap();
    let marker = json!({"schema":"guard-cigar-catalog-download-owner.v1","job_id":job.job_id,"request_sha256":job.request_sha256});
    persist_private_bytes(
        &path.join("installation-owner.json"),
        &serde_json::to_vec(&marker).unwrap(),
        4096,
        "cigar_catalog_job",
        &f.home,
    )
    .unwrap();
    let outside = f.home.join("unrelated.txt");
    fs::write(&outside, b"kept").unwrap();
    std::os::unix::fs::symlink(&outside, path.join("unexpected-link")).unwrap();
    assert!(Jobs::default()
        .recover(&f.home, "cleanup")
        .unwrap_err()
        .ends_with("install_cleanup_unsafe"));
    assert_eq!(fs::read(&outside).unwrap(), b"kept");
    assert!(path.exists());
    fs::remove_file(path.join("unexpected-link")).unwrap();
    let recovered = Jobs::default().recover(&f.home, "cleanup").unwrap();
    assert_eq!(recovered["phase"], "failed");
    assert!(!path.exists());
    assert_eq!(fs::read(outside).unwrap(), b"kept");
}

#[test]
fn a_finished_worker_cannot_pair_its_final_liveness_with_an_older_progress_phase() {
    let f = Fixture::new();
    f.configure();
    let jobs = Jobs::default();
    let bytes = f.sign(&f.document());
    let (entered, seen) = mpsc::sync_channel(1);
    let (release, wait_for_release) = mpsc::sync_channel(1);
    jobs.refresh_catalog_inner(
        &f.home,
        "snapshot",
        Some(Box::new(move |_, _| {
            entered.send(()).unwrap();
            wait_for_release
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            Ok(bytes)
        })),
    )
    .unwrap();
    seen.recv_timeout(Duration::from_secs(10)).unwrap();
    let stale = catalog_store::get(&f.home, "snapshot").unwrap().unwrap();
    assert_eq!(stale.phase, store::Phase::Acquiring);
    release.send(()).unwrap();
    let ready = wait(&jobs, &f.home, "snapshot");
    assert_eq!(ready["phase"], "ready");
    let observed = jobs.catalog_view(&f.home, &stale).unwrap();
    assert_eq!(observed["worker_live"], false);
    assert_eq!(observed["phase"], "ready");
    assert_eq!(observed["recovery_available"], false);
    assert_eq!(observed["catalog_checkpoint"], ready["catalog_checkpoint"]);
    assert_eq!(observed["activation_granted"], false);
}
