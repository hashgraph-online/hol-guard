use super::*;
use python_store::{Job as PythonJob, SetupInterpreterRequest};
fn job(fixture: &Fixture, id: &str) -> PythonJob {
    let catalog = TrustedCatalog::bundled().unwrap();
    let python = catalog.document().interpreters[0].binding().unwrap();
    let request = SetupInterpreterRequest {
        job_id: id.into(),
        build_id: python.build_id.clone(),
    };
    let now = store::now().unwrap();
    let mut job = PythonJob {
        schema: "guard-cigar-python-setup-job.v1".into(),
        request_sha256: python_store::request_sha(&request).unwrap(),
        request,
        slot: python.slot_id().unwrap(),
        python,
        interpreter_id: None,
        phase: Phase::Queued,
        code: "queued".into(),
        created_at_ms: now,
        updated_at_ms: now,
        deadline_at_ms: now + 120_000,
    };
    python_store::save(&fixture.home, &mut job, Phase::Queued, "queued").unwrap();
    job
}
fn stage(fixture: &Fixture, job: &PythonJob) -> PathBuf {
    let id = record_name(&job.request.job_id);
    let path = worker::child(
        &fixture.home,
        "python-staging",
        id.trim_end_matches(".json"),
    )
    .unwrap();
    python_worker::create_owned(&fixture.home, &path, job).unwrap();
    path
}
#[test]
fn private_python_job_metadata_needs_no_python_or_installation_key() {
    let fixture = Fixture::new();
    let job = job(&fixture, "python-metadata");
    let jobs = Jobs::default();
    let view = jobs.get(&fixture.home, &job.request.job_id).unwrap();
    assert_eq!(view["operation"], "setup_interpreter");
    assert_eq!(view["activation_granted"], false);
    assert!(view["worker_live"].is_null());
    assert!(view["interpreter_id"].is_null());
    assert_eq!(jobs.list(&fixture.home).unwrap().len(), 1);
    for name in [
        "python",
        "python-work",
        "python-artifacts",
        "installation-authority.json",
    ] {
        assert!(!fixture.home.join("context-assistance").join(name).exists());
    }
}
#[test]
fn idempotency_keys_cannot_change_setup_builds_or_cross_operation_types() {
    let fixture = Fixture::new();
    let job = job(&fixture, "shared-key");
    let jobs = Jobs::default();
    assert_eq!(
        jobs.setup_interpreter(&fixture.home, job.request.clone())
            .unwrap()["phase"],
        "queued"
    );
    let mut changed = job.request.clone();
    changed.build_id = "different-build".into();
    assert_eq!(
        jobs.setup_interpreter(&fixture.home, changed),
        Err(error("install_idempotency_conflict"))
    );
    assert_eq!(
        jobs.install(
            &fixture.home,
            InstallRequest {
                job_id: job.request.job_id,
                build_id: "sdk-build".into(),
                interpreter_id: "python:other".into()
            }
        ),
        Err(error("install_idempotency_conflict"))
    );
    let sdk = fixture.job("sdk-key");
    assert_eq!(
        jobs.setup_interpreter(
            &fixture.home,
            SetupInterpreterRequest {
                job_id: sdk.request.job_id,
                build_id: job.request.build_id
            }
        ),
        Err(error("install_idempotency_conflict"))
    );
}
#[test]
fn unknown_interpreters_refuse_setup_without_creating_jobs_or_keys() {
    let fixture = Fixture::new();
    let result = Jobs::default().setup_interpreter(
        &fixture.home,
        SetupInterpreterRequest {
            job_id: "unknown-python".into(),
            build_id: "cpython-9_9_9-20990101-darwin-arm64".into(),
        },
    );
    assert!(
        matches!(result, Err(ref code) if [error("cigar_build_unknown"),
        error("cigar_build_platform_unavailable"), error("install_platform_unqualified")].contains(code))
    );
    assert!(!fixture.home.join("context-assistance/python-jobs").exists());
    assert!(!fixture
        .home
        .join("context-assistance/installation-authority.json")
        .exists());
}
#[test]
fn cancelled_python_setup_recovers_owned_staging_without_enabling_or_probing() {
    let fixture = Fixture::new();
    let mut job = job(&fixture, "cancel-python");
    let stage = stage(&fixture, &job);
    fs::write(stage.join("incomplete-code"), b"not executed").unwrap();
    python_store::save(&fixture.home, &mut job, Phase::Extracting, "extracting").unwrap();
    let jobs = Jobs::default();
    assert_eq!(
        jobs.cancel(&fixture.home, &job.request.job_id).unwrap()["cancel_requested"],
        true
    );
    assert_eq!(
        jobs.recover(&fixture.home, &job.request.job_id).unwrap()["phase"],
        "cancelled"
    );
    assert!(!stage.exists());
    assert!(interpreters::interpreters(&fixture.home)
        .unwrap()
        .is_empty());
    let settings = crate::guard_config_load::context_assistance_config(&fixture.home).unwrap();
    assert!(!settings.requested.enabled);
    assert!(settings.requested.runtime_id.is_empty());
}
#[test]
fn unknown_ownership_remains_available_for_explicit_recovery() {
    let fixture = Fixture::new();
    let mut job = job(&fixture, "unknown-python");
    let path = worker::child(&fixture.home, "python", &job.slot).unwrap();
    crate::resident_state::ensure_private_directory_under(&path, &fixture.home, true).unwrap();
    fs::write(path.join("unknown"), b"preserve").unwrap();
    python_store::save(&fixture.home, &mut job, Phase::Extracting, "extracting").unwrap();
    let view = Jobs::default()
        .recover(&fixture.home, &job.request.job_id)
        .unwrap();
    assert_eq!(view["phase"], "recovery_required");
    assert_eq!(fs::read(path.join("unknown")).unwrap(), b"preserve");
}
#[test]
fn combined_python_and_sdk_job_status_is_bounded_and_detects_duplicate_keys() {
    let fixture = Fixture::new();
    let py = job(&fixture, "one-python");
    fixture.job("one-sdk");
    assert_eq!(Jobs::default().list(&fixture.home).unwrap().len(), 2);
    fixture.job(&py.request.job_id);
    assert_eq!(
        Jobs::default().get(&fixture.home, &py.request.job_id),
        Err(error("install_idempotency_conflict"))
    );
    assert_eq!(
        Jobs::default().list(&fixture.home),
        Err(error("install_idempotency_conflict"))
    );
}
#[cfg(unix)]
#[test]
fn managed_python_namespace_and_symlink_alias_cannot_use_external_registration() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let directory = store::directory(&fixture.home, "python", true).unwrap();
    let python = directory.join("temporary-python");
    fs::write(&python, b"not executed").unwrap();
    let alias = fixture.home.join("external-looking-python");
    symlink(&python, &alias).unwrap();
    for path in [&python, &alias] {
        assert!(
            matches!(interpreters::register_interpreter(&fixture.home, path),
            Err(code) if code == error("interpreter_managed_setup_required"))
        );
    }
    assert!(!fixture
        .home
        .join("context-assistance/interpreters")
        .exists());
}
#[test]
fn bounded_cleanup_keeps_ownership_available_for_the_next_recovery() {
    let fixture = Fixture::new();
    let mut job = job(&fixture, "cleanup-deadline");
    let path = stage(&fixture, &job);
    fs::write(
        path.join("partial-file"),
        b"preserve until removal can complete",
    )
    .unwrap();
    let mut items = Vec::new();
    cleanup::collect(
        &path,
        &mut items,
        &mut 0,
        0,
        std::time::Instant::now() + std::time::Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(
        cleanup::remove_collected(&path, items, std::time::Instant::now()),
        Err(error("install_cleanup_limit"))
    );
    assert!(path.join("installation-owner.json").exists());
    assert!(path.join("partial-file").exists());
    python_store::save(&fixture.home, &mut job, Phase::Extracting, "extracting").unwrap();
    assert_eq!(
        Jobs::default()
            .recover(&fixture.home, &job.request.job_id)
            .unwrap()["phase"],
        "failed"
    );
    assert!(!path.exists());
}
#[test]
fn setup_http_inputs_cannot_supply_paths_bindings_or_qualification_claims() {
    let fixture = Fixture::new();
    let service = crate::context_assistance_service::Service::default();
    for extra in ["python", "url", "tree_sha256", "guard_qualified"] {
        let mut request = json!({"action":"setup_interpreter", "job_id":"job", "build_id":"build"});
        request[extra] = json!("untrusted");
        assert_eq!(
            service.versions(&fixture.home, request),
            Err(error("versions_request_invalid"))
        );
    }
}

#[test]
fn atomic_job_status_reads_never_treat_a_replaced_snapshot_as_corrupt_metadata() {
    let fixture = Fixture::new();
    let mut pending = job(&fixture, "atomic-status-read");
    let home = fixture.home.clone();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let writer_barrier = Arc::clone(&barrier);
    let id = pending.request.job_id.clone();
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for index in 0..160 {
            let phase = if index % 2 == 0 {
                Phase::Acquiring
            } else {
                Phase::Verifying
            };
            python_store::save(&home, &mut pending, phase, "status_update").unwrap();
        }
    });
    barrier.wait();
    let jobs = Jobs::default();
    let mut reads = 0;
    while !writer.is_finished() {
        match jobs.get(&fixture.home, &id) {
            Ok(value) => {
                assert_eq!(value["job_id"], id);
                reads += 1;
            }
            Err(code) if code == error("install_metadata_changed") => {}
            Err(code) => panic!("atomic update must not be classified as invalid: {code}"),
        }
    }
    writer.join().unwrap();
    assert!(reads > 0);
    assert_eq!(jobs.get(&fixture.home, &id).unwrap()["phase"], "verifying");
    let path = store::directory(&fixture.home, "python-jobs", false)
        .unwrap()
        .join(record_name(&id));
    fs::write(path, b"{invalid json").unwrap();
    assert_eq!(
        jobs.get(&fixture.home, &id),
        Err(error("install_metadata_invalid"))
    );
}

#[cfg(unix)]
#[path = "context_assistance_python_jobs_actual_tests.rs"]
mod actual_python;
