//! Synthetic signed-catalog tests. Fixture keys/qualification labels are not
//! production authority and no SDK/interpreter is executed by these cases.
use super::*;
#[path = "context_assistance_catalog_atomic_tests.rs"]
mod atomic;
use guard_cigar_release::{CatalogDocument, Feature, Qualification};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::time::{SystemTime, UNIX_EPOCH};
struct Fixture {
    home: PathBuf,
    key: Ed25519KeyPair,
    time: u64,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "guard-cigar-catalog-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        Self {
            home: crate::resident_state::ensure_private_directory(&path, true).unwrap(),
            key: Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap(),
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    fn authority(&self) -> Authority {
        Authority {
            schema: "guard-cigar-catalog-authority.v1".into(),
            keys: vec![PublicKey {
                key_id: "synthetic-catalog-key".into(),
                public_key_hex: hex::encode(self.key.public_key().as_ref()),
                not_before: 1,
                not_after: u64::MAX,
                revoked: false,
            }],
        }
    }
    fn configure(&self) {
        configure(&self.home, self.authority()).unwrap();
    }
    fn doc(&self) -> CatalogDocument {
        let mut d = TrustedCatalog::bundled().unwrap().document().clone();
        d.revision += 1;
        d.issued_at = self.time - 1;
        d.expires_at = self.time + 3600;
        d.builds[0].platforms[0].qualification = Qualification::GuardQualified;
        d.builds[0].platforms[0].features = vec![Feature::Graph];
        d.builds[0].platforms[0].qualification_receipt_sha256 = Some("7".repeat(64));
        d
    }
    fn sign(&self, d: &CatalogDocument) -> Vec<u8> {
        let payload = serde_json::to_string(d).unwrap();
        let mut message = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
        message.extend_from_slice(payload.as_bytes());
        serde_json::to_vec(&json!({"schema":"guard-cigar-signed-catalog.v1","key_id":"synthetic-catalog-key","payload":payload,"signature_hex":hex::encode(self.key.sign(&message).as_ref())})).unwrap()
    }
    fn import(&self, d: &CatalogDocument) -> Value {
        native::import_at(&self.home, &self.sign(d), self.time).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.home).unwrap();
    }
}
fn receipt(
    d: &CatalogDocument,
    checkpoint: &guard_cigar_release::CatalogCheckpoint,
) -> guard_cigar_release::VerifiedInstallationReceipt {
    let mut release = d.builds[0].clone();
    let platform = release.platforms[0].clone();
    release.platforms = vec![platform.clone()];
    let metadata = guard_cigar_release::InstalledReleaseReceipt {
        schema: "guard-cigar-installed-release.v1".into(),
        release: release.clone(),
        profile: d
            .profiles
            .iter()
            .find(|p| p.profile_id == release.profile_id)
            .unwrap()
            .clone(),
        platform: platform.platform,
        catalog_checkpoint: checkpoint.clone(),
        guard_binary_sha256: "a".repeat(64),
        context_sha256: "b".repeat(64),
        verified_features: vec![Feature::Graph],
    };
    let sealed = guard_cigar_release::seal_installation_receipt(&metadata, &[31; 32]).unwrap();
    guard_cigar_release::verify_installation_receipt(&sealed, &[31; 32], &"b".repeat(64)).unwrap()
}
#[test]
fn passive_bundled_resolution_creates_no_stores_and_import_requires_separate_authority() {
    let f = Fixture::new();
    let s = status(&f.home).unwrap();
    assert_eq!(s["source"], "bundled");
    assert_eq!(s["trust_configured"], false);
    let listing = releases(&f.home).unwrap();
    assert_eq!(listing["schema"], "guard-cigar-releases.v1");
    assert_eq!(listing["catalog"]["activation_granted"], false);
    assert_eq!(
        listing["host_platform"],
        json!(preparation::setup_platform())
    );
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    assert_eq!(listing["host_platform"], "darwin-arm64");
    assert_eq!(
        fs::read_dir(&f.home).unwrap().count(),
        0,
        "host/catalog metadata must not provision any profile store"
    );
    assert!(!f.home.join("context-assistance").exists());
    assert!(!f.home.join("cigar-catalog-state/key").exists());
    assert!(import(&f.home, &f.sign(&f.doc()))
        .unwrap_err()
        .ends_with("cigar_catalog_trust_unavailable"));
    assert!(!f.home.join("cigar-catalog-state/key").exists());
    assert!(!f.home.join("config.toml").exists());
}
#[test]
fn signed_future_entry_is_data_only_preserves_settings_and_cannot_supply_trust_keys() {
    let f = Fixture::new();
    f.configure();
    let before = "mode='enforce'\n[context_assistance]\nenabled=false\nruntime_id='kept'\n";
    fs::write(f.home.join("config.toml"), before).unwrap();
    let mut d = f.doc();
    let mut next = d.builds[0].clone();
    next.identity.build_id = "synthetic-next-build".into();
    next.identity.sdk_version = "0.14.2".into();
    next.identity.manifest_sha256 = "c".repeat(64);
    for p in &mut next.platforms {
        if let Some(w) = &mut p.wheel {
            w.version = "0.14.2".into();
            w.filename = w.filename.replace("0.14.1", "0.14.2");
        }
    }
    d.builds.push(next);
    let installed = f.import(&d);
    assert_eq!(installed["source"], "cached");
    assert_eq!(installed["activation_granted"], false);
    let s = fresh(&f.home).unwrap();
    assert!(s
        .catalog
        .prepare("synthetic-next-build", "darwin-arm64", false)
        .is_ok());
    assert_eq!(
        fs::read_to_string(f.home.join("config.toml")).unwrap(),
        before
    );
    assert!(!f.home.join("context-assistance/installations").exists());
    let text = releases(&f.home).unwrap().to_string();
    assert!(!text.contains("public_key_hex"));
    let service = crate::context_assistance_service::Service::default();
    assert!(service.versions(&f.home,json!({"action":"import_catalog","signed_catalog":String::from_utf8(f.sign(&d)).unwrap(),"keys":[]})).unwrap_err().ends_with("versions_request_invalid"));
}
#[test]
fn replay_equivocation_and_identity_reuse_after_omission_never_replace_cache() {
    let f = Fixture::new();
    f.configure();
    let d = f.doc();
    f.import(&d);
    let path = f.home.join("cigar-catalog-state/catalog.json");
    let original = fs::read(&path).unwrap();
    let mut conflict = d.clone();
    conflict.expires_at += 1;
    assert!(native::import_at(&f.home, &f.sign(&conflict), f.time)
        .unwrap_err()
        .ends_with("cigar_catalog_revision_conflict"));
    assert_eq!(fs::read(&path).unwrap(), original);
    let mut missing = d.clone();
    missing.revision += 1;
    missing.builds.clear();
    f.import(&missing);
    let after_missing = fs::read(&path).unwrap();
    assert!(native::import_at(&f.home, &f.sign(&d), f.time)
        .unwrap_err()
        .ends_with("cigar_catalog_replayed"));
    conflict = d.clone();
    conflict.revision += 2;
    conflict.builds[0].identity.manifest_sha256 = "8".repeat(64);
    assert!(native::import_at(&f.home, &f.sign(&conflict), f.time)
        .unwrap_err()
        .ends_with("cigar_catalog_identity_conflict"));
    conflict = d.clone();
    conflict.revision += 2;
    conflict.builds[0].platforms[0].worker_sha256 = "8".repeat(64);
    assert!(native::import_at(&f.home, &f.sign(&conflict), f.time)
        .unwrap_err()
        .ends_with("cigar_catalog_identity_conflict"));
    assert_eq!(fs::read(&path).unwrap(), after_missing);
}
#[test]
fn expiration_or_root_revocation_blocks_new_work_but_preserves_verified_receipt_resolution() {
    let f = Fixture::new();
    f.configure();
    let mut d = f.doc();
    d.expires_at = f.time + 600;
    f.import(&d);
    let s = installed(&f.home).unwrap();
    let verified = receipt(&d, s.catalog.checkpoint());
    let expired = native::load_at(&f.home, f.time + 601).unwrap();
    assert!(expired
        .diagnostic
        .as_ref()
        .unwrap()
        .ends_with("cigar_catalog_expired"));
    assert!(verified
        .resolve(&expired.catalog, &[Feature::Graph])
        .is_ok());
    let mut authority = f.authority();
    authority.keys[0].revoked = true;
    configure(&f.home, authority).unwrap();
    let s = installed(&f.home).unwrap();
    assert!(s
        .diagnostic
        .as_ref()
        .unwrap()
        .ends_with("cigar_catalog_key_unavailable"));
    assert!(verified.resolve(&s.catalog, &[Feature::Graph]).is_ok());
    assert!(fresh(&f.home)
        .err()
        .unwrap()
        .ends_with("cigar_catalog_key_unavailable"));
    assert!(native::import_at(&f.home, &f.sign(&d), f.time)
        .unwrap_err()
        .ends_with("cigar_catalog_key_unavailable"));
}
#[test]
fn explicit_withdrawals_survive_omission_and_cannot_be_silently_reenabled() {
    let f = Fixture::new();
    f.configure();
    let mut d = f.doc();
    let sdk = d.builds[0].identity.build_id.clone();
    let python = d.interpreters[0].build_id.clone();
    let original = d.clone();
    d.builds[0].withdrawn = true;
    d.builds[0].platforms[0].qualification = Qualification::UpstreamOnly;
    d.builds[0].platforms[0].wheel = None;
    d.interpreters[0].withdrawn = true;
    f.import(&d);
    let mut next = d.clone();
    next.revision += 1;
    next.builds.clear();
    next.interpreters.clear();
    f.import(&next);
    let s = installed(&f.home).unwrap();
    assert!(s.check_sdk(&sdk).is_err());
    assert!(s.check_python(&python).is_err());
    d = original;
    d.revision += 2;
    d.builds[0].withdrawn = false;
    d.interpreters[0].withdrawn = false;
    f.import(&d);
    let s = fresh(&f.home).unwrap();
    assert!(s.check_sdk(&sdk).is_err());
    assert!(s.check_python(&python).is_err());
}
#[test]
fn copied_tampered_or_missing_state_refuses_without_recreating_a_key() {
    let f = Fixture::new();
    f.configure();
    let d = f.doc();
    f.import(&d);
    let other = Fixture::new();
    crate::resident_state::ensure_private_directory_under(
        &other.home.join("cigar-catalog-state"),
        &other.home,
        true,
    )
    .unwrap();
    for name in [
        "cigar-catalog-state/catalog.json",
        "cigar-catalog-state/key",
        "cigar-catalog-trust.json",
    ] {
        fs::copy(f.home.join(name), other.home.join(name)).unwrap();
    }
    assert!(installed(&other.home)
        .err()
        .unwrap()
        .ends_with("cigar_catalog_state_unauthenticated"));
    let key = f.home.join("cigar-catalog-state/key");
    let backup = f.home.join("key.fixture-backup");
    fs::rename(&key, &backup).unwrap();
    assert!(installed(&f.home)
        .err()
        .unwrap()
        .ends_with("cigar_catalog_state_incomplete"));
    assert!(import(&f.home, &f.sign(&d))
        .unwrap_err()
        .ends_with("cigar_catalog_state_incomplete"));
    assert!(!key.exists());
    fs::rename(backup, key).unwrap();
    let path = f.home.join("cigar-catalog-state/catalog.json");
    let mut raw: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    raw["payload"] = json!(raw["payload"]
        .as_str()
        .unwrap()
        .replace("accepted_at", "changed_time"));
    fs::write(path, serde_json::to_vec(&raw).unwrap()).unwrap();
    assert!(installed(&f.home)
        .err()
        .unwrap()
        .ends_with("cigar_catalog_state_unauthenticated"));
}
#[test]
fn publication_shares_the_lifecycle_lease_and_a_new_key_can_rotate_in_explicitly() {
    let f = Fixture::new();
    f.configure();
    let d = f.doc();
    let owner = super::super::switching::Owner::acquire(&f.home).unwrap();
    assert!(import(&f.home, &f.sign(&d))
        .unwrap_err()
        .ends_with("install_busy"));
    assert!(configure(&f.home, f.authority())
        .unwrap_err()
        .ends_with("install_busy"));
    assert_eq!(status(&f.home).unwrap()["source"], "bundled");
    drop(owner);
    f.import(&d);
    let mut next = f.doc();
    next.revision += 1;
    let key = Ed25519KeyPair::from_seed_unchecked(&[43; 32]).unwrap();
    let mut authority = f.authority();
    authority.keys.push(PublicKey {
        key_id: "synthetic-rotation".into(),
        public_key_hex: hex::encode(key.public_key().as_ref()),
        not_before: 1,
        not_after: u64::MAX,
        revoked: false,
    });
    configure(&f.home, authority).unwrap();
    let payload = serde_json::to_string(&next).unwrap();
    let mut message = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
    message.extend_from_slice(payload.as_bytes());
    let raw=serde_json::to_vec(&json!({"schema":"guard-cigar-signed-catalog.v1","key_id":"synthetic-rotation","payload":payload,"signature_hex":hex::encode(key.sign(&message).as_ref())})).unwrap();
    import(&f.home, &raw).unwrap();
    assert_eq!(
        fresh(&f.home).unwrap().catalog.signer(),
        Some("synthetic-rotation")
    );
}

#[test]
fn import_request_budget_is_bounded_separately_and_the_reply_stays_request_bound() {
    use std::io::Write;
    let f = Fixture::new();
    crate::resident_state::private_file(&f.home.join("policy-verifier.key"), true, &f.home)
        .unwrap()
        .write_all(&[91; 32])
        .unwrap();
    let store = crate::policy_store::PolicySnapshotStore::new(&f.home, &"a".repeat(64)).unwrap();
    for (action, expected) in [
        (
            "import_catalog",
            "native_context_assistance_cigar_catalog_trust_unavailable",
        ),
        ("jobs", "native_context_assistance_request_too_large"),
    ] {
        let request:crate::context_assistance_op::Request=serde_json::from_value(json!({"schema":"guard-context-assistance-request.v1","request_id":"catalog-bounded",
            "query":{"kind":"versions","guard_home":f.home,"input":{"action":action,"signed_catalog":"x".repeat(128*1024)}}})).unwrap();
        let answer = crate::context_assistance_op::evaluate(&request, &store);
        if action == "jobs" {
            assert_eq!(answer.unwrap_err(), expected);
        } else {
            let answer: Value = serde_json::from_slice(&answer.unwrap()).unwrap();
            assert_eq!(answer["code"], expected);
            assert!(answer["request_sha256"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"));
        }
    }
    assert!(!f.home.join("cigar-catalog-state/key").exists());
    assert!(!f.home.join("config.toml").exists());
    let service = store.context_assistance();
    assert_eq!(service.status().unwrap()["requested_enabled"], false);
    service.shutdown();
}

#[test]
fn malformed_current_roots_can_be_repaired_without_losing_authenticated_installed_metadata() {
    let f = Fixture::new();
    f.configure();
    let d = f.doc();
    f.import(&d);
    let s = installed(&f.home).unwrap();
    let verified = receipt(&d, s.catalog.checkpoint());
    fs::write(
        f.home.join("cigar-catalog-trust.json"),
        b"{broken-authority}",
    )
    .unwrap();
    let s = installed(&f.home).unwrap();
    assert!(s.diagnostic.is_some());
    assert!(s.trust_diagnostic.is_some());
    assert!(verified.resolve(&s.catalog, &[Feature::Graph]).is_ok());
    assert!(fresh(&f.home).is_err());
    configure(&f.home, f.authority()).unwrap();
    assert!(fresh(&f.home).is_ok());
    let cache = fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap();
    let key = fs::read(f.home.join("cigar-catalog-state/key")).unwrap();
    let lock = crate::guard_config_update::io::WriteLock::acquire(&f.home).unwrap();
    lock.forget_lifecycle_selection().unwrap();
    drop(lock);
    assert_eq!(
        fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap(),
        cache
    );
    assert_eq!(
        fs::read(f.home.join("cigar-catalog-state/key")).unwrap(),
        key
    );
}
