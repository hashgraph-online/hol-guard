//! Real CPython + exact 0.14.1 bytes, using only an explicit test catalog key.
use super::*;
use guard_cigar_release::{CatalogTrust, Feature, Qualification, TrustedKey};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    time::{Duration, Instant},
};

fn qualified_catalog() -> TrustedCatalog {
    let mut doc = super::super::actual::approved_catalog_requirement(None)
        .document()
        .clone();
    let receipt = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../docs/guard/cigar-integration/evidence/receipts.json",
    ))
    .unwrap();
    doc.interpreters[0].qualification = Qualification::GuardQualified;
    doc.interpreters[0].qualification_receipt_sha256 =
        Some(format!("{:x}", Sha256::digest(receipt)));
    let pair = Ed25519KeyPair::from_seed_unchecked(&[103; 32]).unwrap();
    let key = TrustedKey {
        key_id: "private-python-test-only".into(),
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
    let started = Instant::now();
    loop {
        let view = match jobs.get(home, id) {
            Ok(view) => view,
            Err(code) if code == error("install_metadata_changed") => {
                assert!(started.elapsed() < Duration::from_secs(125));
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(code) => panic!("{code}"),
        };
        if view["worker_live"] == false {
            return view;
        }
        assert!(started.elapsed() < Duration::from_secs(125), "{view}");
        std::thread::sleep(Duration::from_millis(25));
    }
}
#[test]
#[ignore = "requires exact standalone CPython archive and final SDK wheels in GUARD_CIGAR_PRIVATE_PYTHON_TEST_INPUT"]
fn actual_private_python_setup_installs_sdk_and_recovers_without_replaying_processes() {
    let input = std::env::var_os("GUARD_CIGAR_PRIVATE_PYTHON_TEST_INPUT")
        .expect("explicit private artifacts");
    let input: Value = serde_json::from_slice(&fs::read(input).unwrap()).unwrap();
    let fixture = Fixture::new();
    let catalog = qualified_catalog();
    let build_id = catalog.document().interpreters[0].build_id.clone();
    let build = catalog
        .interpreter_for_setup(&build_id, "darwin-arm64")
        .unwrap();
    python_cache::import(
        &fixture.home,
        &build,
        Path::new(input["archive"].as_str().unwrap()),
    )
    .unwrap();
    let jobs = Jobs::default();
    let request = SetupInterpreterRequest {
        job_id: "real-private-python".into(),
        build_id,
    };
    let (entered, entered_rx) = mpsc::sync_channel(1);
    let (proceed, proceed_rx) = mpsc::sync_channel(1);
    let started = Instant::now();
    jobs.setup_test_catalog(
        &fixture.home,
        request.clone(),
        &catalog,
        InstallPause {
            entered,
            proceed: proceed_rx,
        },
    )
    .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(115)).unwrap();
    let pending = jobs.get(&fixture.home, &request.job_id).unwrap();
    assert_eq!(pending["phase"], "verifying");
    assert_eq!(pending["worker_live"], true);
    assert_eq!(
        jobs.recover(&fixture.home, &request.job_id),
        Err(error("install_busy"))
    );
    assert!(interpreters::interpreters(&fixture.home)
        .unwrap()
        .is_empty());
    proceed.send(()).unwrap();
    let ready = wait(&jobs, &fixture.home, &request.job_id);
    assert_eq!(ready["phase"], "ready", "{ready}");
    assert_eq!(ready["activation_granted"], false);
    let interpreter_id = ready["interpreter_id"].as_str().unwrap();
    let record = interpreters::load_interpreter(&fixture.home, interpreter_id).unwrap();
    assert_eq!(record.schema, managed_python::SCHEMA);
    assert_eq!(record.facts.version, [3, 14, 10]);
    assert_eq!(
        record.python_bundle().unwrap().binding,
        build.build().binding().unwrap()
    );
    // A later bundled catalog need not repeat qualification to keep an already
    // installed exact build. Idempotent replies require metadata, not a probe.
    assert_eq!(
        jobs.setup_interpreter(&fixture.home, request.clone())
            .unwrap()["phase"],
        "ready"
    );
    let second = SetupInterpreterRequest {
        job_id: "reuse-private-python".into(),
        ..request.clone()
    };
    let (entered, _entered_rx) = mpsc::sync_channel(1);
    let (_proceed, proceed_rx) = mpsc::sync_channel(1);
    jobs.setup_test_catalog(
        &fixture.home,
        second.clone(),
        &catalog,
        InstallPause {
            entered,
            proceed: proceed_rx,
        },
    )
    .unwrap();
    assert_eq!(
        wait(&jobs, &fixture.home, &second.job_id)["interpreter_id"],
        interpreter_id
    );
    assert_eq!(interpreters::interpreters(&fixture.home).unwrap().len(), 1);
    let release = catalog
        .for_activation(
            &catalog.document().builds[0].identity.build_id,
            "darwin-arm64",
            false,
            &[Feature::Graph],
        )
        .unwrap();
    let wheels: BTreeMap<String, PathBuf> =
        serde_json::from_value(input["wheels"].clone()).unwrap();
    cache::import(&fixture.home, &release, &wheels).unwrap();
    let install = InstallRequest {
        job_id: "sdk-on-private-python".into(),
        build_id: release.build().identity.build_id.clone(),
        interpreter_id: interpreter_id.into(),
    };
    jobs.install_catalog(&fixture.home, install.clone(), &catalog)
        .unwrap();
    let installed = wait(&jobs, &fixture.home, &install.job_id);
    assert_eq!(installed["phase"], "ready", "{installed}");
    let runtime_id = installed["runtime_id"].as_str().unwrap();
    let installation = load(&fixture.home, runtime_id).unwrap();
    assert_eq!(
        installation.approval.schema,
        "guard-cigar-bundle-approval.v3"
    );
    assert_eq!(installation.selection.python_bundle, record.python_bundle());
    validate_selection(&fixture.home, runtime_id).unwrap();
    let config = guard_context_assistance::ContextAssistanceConfig {
        runtime_id: runtime_id.into(),
        ..Default::default()
    };
    let mut runtime = installation
        .start_cancellable(&fixture.home, &config, Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert!(runtime.status().compile_verified);
    runtime.close();
    // Remove the interpreter probe's work directory: recovery cannot replay a
    // probe there. It must inspect the committed owner receipt and full tree.
    let work = fixture
        .home
        .join("context-assistance/python-work")
        .join(build.build().binding().unwrap().slot_id().unwrap());
    fs::remove_file(work.join("installation-owner.json")).unwrap();
    fs::remove_dir(&work).unwrap();
    let mut lost = python_store::get(&fixture.home, &request.job_id)
        .unwrap()
        .unwrap();
    lost.interpreter_id = None;
    python_store::save(&fixture.home, &mut lost, Phase::Publishing, "publishing").unwrap();
    assert_eq!(
        jobs.recover(&fixture.home, &request.job_id).unwrap()["phase"],
        "ready"
    );
    assert!(!work.exists());
    let mut maximum_metadata_us = 0;
    for _ in 0..20 {
        let measured = Instant::now();
        assert_eq!(jobs.interpreters(&fixture.home).unwrap().len(), 1);
        maximum_metadata_us = maximum_metadata_us.max(measured.elapsed().as_micros());
    }
    assert!(
        matches!(interpreters::register_interpreter(&fixture.home, &record.python),
        Err(code) if code == error("interpreter_managed_setup_required"))
    );
    let library = record
        .python_bundle()
        .unwrap()
        .root
        .join("lib/python3.14/os.py");
    let mut contents = fs::read(&library).unwrap();
    contents.extend_from_slice(b"\n# simulated replaced library\n");
    fs::set_permissions(&library, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&library, contents).unwrap();
    fs::set_permissions(&library, fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        guard_secure_fs::read_stable(&record.python, 128 * 1024 * 1024, false)
            .unwrap()
            .sha256,
        record.python_sha256
    );
    // Passive metadata remains cheap; an actual launch and explicit recovery
    // refuse the changed tree while preserving files for diagnosis/repair.
    assert_eq!(jobs.interpreters(&fixture.home).unwrap().len(), 1);
    assert!(validate_selection(&fixture.home, runtime_id).is_err());
    let mut lost = python_store::get(&fixture.home, &request.job_id)
        .unwrap()
        .unwrap();
    python_store::save(&fixture.home, &mut lost, Phase::Publishing, "publishing").unwrap();
    assert_eq!(
        jobs.recover(&fixture.home, &request.job_id).unwrap()["phase"],
        "recovery_required"
    );
    assert!(library.exists());
    let settings = crate::guard_config_load::context_assistance_config(&fixture.home).unwrap();
    assert!(!settings.requested.enabled);
    assert!(settings.requested.runtime_id.is_empty());
    println!(
        "PRIVATE_PYTHON_INSTALL_PROOF={}",
        json!({"schema":"guard-cigar-private-python-install-proof.v1",
        "scope":"local-source-macos-arm64-test-catalog-only", "runtime_binary_sha256":crate::resident_state::runtime_digest().unwrap(),
        "python_build":build.build(), "python_facts":record.facts,"sdk_build":release.build().identity,
        "approval_schema":installation.approval.schema,"features_verified":release.platform().features,
        "private_interpreter_id":interpreter_id,"runtime_id":runtime_id,"idempotent_reuse":true,
        "lost_reply_recovered_without_probe":true,"changed_stdlib_refused_with_same_executable":true,
        "off_preserved":true,"selection_unchanged":true,"max_metadata_us":maximum_metadata_us,
        "elapsed_ms":started.elapsed().as_millis()})
    );
}
