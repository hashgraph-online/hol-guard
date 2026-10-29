//! Exact real wheels, explicit test-only approval, no production trust roots.
use super::*;
use guard_cigar_release::{CatalogTrust, Feature, Qualification, TrustedKey};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

fn approved_catalog() -> TrustedCatalog {
    approved_catalog_requirement(None)
}
pub(super) fn approved_catalog_requirement(requirement: Option<&str>) -> TrustedCatalog {
    let mut document = TrustedCatalog::bundled().unwrap().document().clone();
    let receipt = fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../docs/guard/cigar-integration/evidence/upgrades-final-0.14.1-native-20261026.json",
    ))
    .unwrap();
    let platform = &mut document.builds[0].platforms[0];
    if let Some(requirement) = requirement {
        platform.wheel.as_mut().unwrap().requires_python = Some(requirement.into());
    }
    platform.qualification = Qualification::GuardQualified;
    platform.features = vec![
        Feature::Graph,
        Feature::Sharing,
        Feature::Persistence,
        Feature::ExecutionContext,
    ];
    platform.qualification_receipt_sha256 = Some(format!("{:x}", Sha256::digest(receipt)));
    document.issued_at = 900;
    document.expires_at = 2000;
    let pair = Ed25519KeyPair::from_seed_unchecked(&[95; 32]).unwrap();
    let key = TrustedKey {
        key_id: "install-actual-test-only".into(),
        public_key: pair.public_key().as_ref().try_into().unwrap(),
        not_before: 500,
        not_after: 3000,
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
    let envelope=serde_json::to_vec(&json!({"schema":"guard-cigar-signed-catalog.v1","key_id":key.key_id,"payload":payload,"signature_hex":signature})).unwrap();
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
#[test]
#[ignore = "requires explicit exact final SDK/dependency wheels and verified CPython3.14.7 in GUARD_CIGAR_INSTALL_TEST_INPUT"]
fn actual_managed_install_is_inactive_idempotent_and_reconciles_lost_publication_reply() {
    let input_path = std::env::var_os("GUARD_CIGAR_INSTALL_TEST_INPUT")
        .expect("explicit task-private artifact/interpreter inputs");
    let input: Value = serde_json::from_slice(&fs::read(input_path).unwrap()).unwrap();
    let fixture = Fixture::new();
    let python = Path::new(input["python"].as_str().unwrap());
    let interpreter = interpreters::register_interpreter(&fixture.home, python).unwrap();
    assert_eq!(interpreter.facts.version, [3, 14, 7]);
    let catalog = approved_catalog();
    let build_id = catalog.document().builds[0].identity.build_id.clone();
    let release = catalog
        .for_activation(&build_id, "darwin-arm64", false, &[Feature::Graph])
        .unwrap();
    let inputs: BTreeMap<String, PathBuf> =
        serde_json::from_value(input["wheels"].clone()).unwrap();
    cache::import(&fixture.home, &release, &inputs).unwrap();
    let jobs = Jobs::default();
    let request = InstallRequest {
        job_id: "real-final-install".into(),
        build_id,
        interpreter_id: interpreter.interpreter_id.clone(),
    };
    let start = Instant::now();
    jobs.install_catalog(&fixture.home, request.clone(), &catalog)
        .unwrap();
    let outcome = loop {
        let current = jobs.get(&fixture.home, &request.job_id).unwrap();
        if current["worker_live"] == false {
            break current;
        }
        assert!(start.elapsed() < Duration::from_secs(125));
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(outcome["phase"], "ready", "{outcome}");
    assert_eq!(outcome["activation_granted"], false);
    let runtime_id = outcome["runtime_id"].as_str().unwrap();
    let record = load(&fixture.home, runtime_id).unwrap();
    assert_eq!(record.schema, versioned::SCHEMA_V2);
    assert_eq!(record.qualification, "guard_qualified");
    validate_selection(&fixture.home, runtime_id).unwrap();
    let settings = crate::guard_config_load::context_assistance_config(&fixture.home).unwrap();
    assert!(!settings.requested.enabled);
    assert!(settings.requested.runtime_id.is_empty());
    assert_eq!(super::super::super::list(&fixture.home).unwrap().len(), 1);
    assert_eq!(
        jobs.install_catalog(&fixture.home, request.clone(), &catalog)
            .unwrap()["phase"],
        "ready"
    );
    assert_eq!(jobs.list(&fixture.home).unwrap().len(), 1);
    // Emulate the durable publication boundary with a lost acknowledgement.
    // Recovery must inspect the actual authenticated record/artifacts, without
    // replaying the SDK doctor or publishing another installation.
    let mut lost = store::get(&fixture.home, &request.job_id).unwrap().unwrap();
    store::save(&fixture.home, &mut lost, Phase::Publishing, "publishing").unwrap();
    let recovered = Jobs::default()
        .recover(&fixture.home, &request.job_id)
        .unwrap();
    assert_eq!(recovered["phase"], "ready");
    assert_eq!(super::super::super::list(&fixture.home).unwrap().len(), 1);
    println!(
        "GUARD_CIGAR_MANAGED_INSTALL_VERIFIED {}",
        json!({"build_id":request.build_id,"python":interpreter.facts.version,
        "tree":record.approval.package_tree_sha256,"worker":record.approval.worker_sha256,
        "guard_binary_sha256":crate::resident_state::runtime_digest().unwrap(),
        "off_preserved":true,"selection_unchanged":true,"idempotent":true,"lost_reply_reconciled":true,"elapsed_ms":start.elapsed().as_millis()})
    );
}

#[test]
#[ignore = "requires explicit final SDK wheels, current byte-approved CIGAR selection and CPython3.14.7"]
fn actual_preparation_cancellation_keeps_current_cigar_running_and_preferences_unchanged() {
    let input_path =
        std::env::var_os("GUARD_CIGAR_INSTALL_TEST_INPUT").expect("explicit private inputs");
    let input: Value = serde_json::from_slice(&fs::read(input_path).unwrap()).unwrap();
    let selection: Value =
        serde_json::from_slice(&fs::read(input["current_selection"].as_str().unwrap()).unwrap())
            .unwrap();
    let approval: Value =
        serde_json::from_slice(&fs::read(input["current_approval"].as_str().unwrap()).unwrap())
            .unwrap();
    let fixture = Fixture::new();
    // The current runtime is an explicitly enrolled v1 installation of the
    // final SDK. This proves active install-only continuity, not a historical
    // b47380 candidate-to-final switch or a real newer-version upgrade.
    let enrollment = json!({"schema":"guard-cigar-enroll-local.v1", "guard_home":fixture.home,
        "runtime_id":"operator-current", "local_candidate_approved":true,
        "source_revision":"10dd521dec8224d0957365a90111158e43c9d87f", "selection":selection,"approval":approval});
    let enrolled: Value = serde_json::from_slice(
        &super::super::super::run_enroll_command(enrollment.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(enrolled["ok"], true, "{enrolled}");
    let update = json!({"schema":"guard-config-update.v1","guard_home":fixture.home,"kind":"settings",
        "value_text":json!({"context_assistance":{"enabled":true,"runtime_id":"operator-current"}}).to_string()});
    let saved: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(update.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(saved["ok"], true, "{saved}");
    let interpreter = interpreters::register_interpreter(
        &fixture.home,
        Path::new(input["python"].as_str().unwrap()),
    )
    .unwrap();
    let catalog = approved_catalog();
    let build_id = catalog.document().builds[0].identity.build_id.clone();
    let release = catalog
        .for_activation(&build_id, "darwin-arm64", false, &[Feature::Graph])
        .unwrap();
    let wheels: BTreeMap<String, PathBuf> =
        serde_json::from_value(input["wheels"].clone()).unwrap();
    cache::import(&fixture.home, &release, &wheels).unwrap();
    let service = crate::context_assistance_service::Service::default();
    service
        .configure(crate::guard_config_load::context_assistance_config(&fixture.home).unwrap())
        .unwrap();
    service
        .schedule(
            crate::context_assistance_service::Check::Activate,
            fixture.home.clone(),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let ready = loop {
        let status = service.status().unwrap();
        if status["effective_enabled"] == true {
            break status;
        }
        assert!(Instant::now() < deadline, "{status}");
        std::thread::sleep(Duration::from_millis(25));
    };
    let config_before = fs::read(fixture.home.join("config.toml")).unwrap();
    let (entered, paused) = std::sync::mpsc::sync_channel(1);
    let (_resume, proceed) = std::sync::mpsc::sync_channel(1);
    let request = InstallRequest {
        job_id: "cancel-while-current-runs".into(),
        build_id,
        interpreter_id: interpreter.interpreter_id,
    };
    service
        .install_test_catalog(
            &fixture.home,
            request.clone(),
            &catalog,
            InstallPause { entered, proceed },
        )
        .unwrap();
    let start = Instant::now();
    let mut max_status_us = 0u128;
    loop {
        let checked = Instant::now();
        let current = service.status().unwrap();
        max_status_us = max_status_us.max(checked.elapsed().as_micros());
        assert_eq!(current["effective_enabled"], true, "{current}");
        assert_eq!(current["generation"], ready["generation"]);
        assert_eq!(
            current["runtime"]["worker_fingerprint"],
            ready["runtime"]["worker_fingerprint"]
        );
        if paused.try_recv().is_ok() {
            break;
        }
        let job = service
            .versions(
                &fixture.home,
                json!({"action":"job","job_id":request.job_id}),
            )
            .unwrap();
        assert_ne!(
            job["worker_live"], false,
            "replacement failed before the test boundary: {job}"
        );
        assert!(start.elapsed() < Duration::from_secs(125));
        std::thread::sleep(Duration::from_millis(25));
    }
    // The pause occurs after the replacement's actual SDK and every qualified
    // feature check succeeded, while its process is live and before publish.
    service
        .versions(
            &fixture.home,
            json!({"action":"cancel","job_id":request.job_id}),
        )
        .unwrap();
    let cancelled = loop {
        let job = service
            .versions(
                &fixture.home,
                json!({"action":"job","job_id":request.job_id}),
            )
            .unwrap();
        assert_eq!(service.status().unwrap()["effective_enabled"], true);
        if job["worker_live"] == false {
            break job;
        }
        assert!(start.elapsed() < Duration::from_secs(125));
        std::thread::sleep(Duration::from_millis(25));
    };
    let mut cancelled = cancelled;
    let cleanup_recovery_required = cancelled["phase"] == "recovery_required";
    if cleanup_recovery_required {
        assert_eq!(cancelled["code"], "install_cleanup_pending", "{cancelled}");
        // A bounded cleanup slice can expire under filesystem contention.
        // Exercise explicit native recovery, accepting only its same bounded
        // continuation code; unsafe ownership or other failures still fail.
        for _ in 0..8 {
            assert_eq!(service.status().unwrap()["effective_enabled"], true);
            assert_eq!(service.status().unwrap()["generation"], ready["generation"]);
            cancelled = service
                .versions(
                    &fixture.home,
                    json!({"action":"recover","job_id":request.job_id}),
                )
                .unwrap();
            if cancelled["phase"] == "cancelled" {
                break;
            }
            assert_eq!(cancelled["phase"], "recovery_required", "{cancelled}");
            assert_eq!(
                cancelled["code"],
                error("install_cleanup_limit"),
                "{cancelled}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    assert_eq!(cancelled["phase"], "cancelled", "{cancelled}");
    assert_eq!(
        fs::read(fixture.home.join("config.toml")).unwrap(),
        config_before
    );
    assert_eq!(service.status().unwrap()["generation"], ready["generation"]);
    assert_eq!(super::super::super::list(&fixture.home).unwrap().len(), 1);
    assert!(!fixture
        .home
        .join("context-assistance/installation-authority.json")
        .exists());
    let slot = cancelled["runtime_id"]
        .as_str()
        .unwrap()
        .strip_prefix("cigar:")
        .unwrap();
    assert!(!fixture
        .home
        .join("context-assistance/bundles")
        .join(slot)
        .exists());
    assert!(!fixture
        .home
        .join("context-assistance/work")
        .join(slot)
        .exists());
    assert!(
        max_status_us < 250_000,
        "status waited for optional SDK work"
    );
    service.shutdown();
    assert!(service.status().unwrap()["runtime"].is_null());
    println!(
        "GUARD_CIGAR_ACTIVE_INSTALL_CONTINUITY_VERIFIED {}",
        json!({"old_runtime_stayed_ready":true,
        "guard_binary_sha256":crate::resident_state::runtime_digest().unwrap(),
        "generation_unchanged":true,"preferences_byte_identical":true,"replacement_verified_before_cancel":true,
        "cancelled_before_publication":true,"bounded_cleanup_recovery_required":cleanup_recovery_required,"partial_slot_removed":true,"max_status_us":max_status_us,
        "elapsed_ms":start.elapsed().as_millis()})
    );
}
