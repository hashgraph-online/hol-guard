use super::*;
use store::{Job, Phase};

#[path = "context_assistance_install_reuse_tests.rs"]
mod reuse_tests;

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(temp.path()).unwrap();
        root(&home, true).unwrap();
        Self { _temp: temp, home }
    }
    fn job(&self, id: &str) -> Job {
        let catalog = TrustedCatalog::bundled().unwrap();
        let build = &catalog.document().builds[0];
        let release = catalog
            .prepare(&build.identity.build_id, "darwin-arm64", false)
            .unwrap();
        let request = InstallRequest {
            job_id: id.into(),
            build_id: build.identity.build_id.clone(),
            interpreter_id: "python:fixture".into(),
        };
        let now = store::now().unwrap();
        let slot = guard_cigar_install::slot_id(&release, &"d".repeat(64)).unwrap();
        let mut job = Job {
            schema: "guard-cigar-install-job.v1".into(),
            request_sha256: store::request_sha(&request).unwrap(),
            request,
            release: release.binding().unwrap(),
            package_tree_sha256: release.platform().package_tree_sha256.clone().unwrap(),
            worker_sha256: release.platform().worker_sha256.clone(),
            python_sha256: "d".repeat(64),
            python_bundle: None,
            runtime_id: format!("cigar:{slot}"),
            refresh: None,
            slot,
            phase: Phase::Queued,
            code: "queued".into(),
            created_at_ms: now,
            updated_at_ms: now,
            deadline_at_ms: now + 120_000,
        };
        store::save(&self.home, &mut job, Phase::Queued, "queued").unwrap();
        job
    }
    fn owned_stage(&self, job: &Job) -> PathBuf {
        let directory = store::directory(&self.home, "staging", true).unwrap();
        let path = directory.join(record_name(&job.request.job_id).trim_end_matches(".json"));
        crate::resident_state::ensure_private_directory_under(&path, &self.home, true).unwrap();
        let marker = json!({"schema":"guard-cigar-install-owner.v1", "job_id":job.request.job_id,
            "request_sha256":job.request_sha256,"slot":job.slot});
        persist_private_bytes(
            &path.join("installation-owner.json"),
            &serde_json::to_vec(&marker).unwrap(),
            4096,
            "cigar_install_job",
            &self.home,
        )
        .unwrap();
        path
    }
}
#[test]
fn passive_job_metadata_never_requires_an_interpreter_or_sdk_tree() {
    let fixture = Fixture::new();
    let job = fixture.job("read-only");
    let jobs = Jobs::default();
    let result = jobs.get(&fixture.home, &job.request.job_id).unwrap();
    assert_eq!(result["phase"], "queued");
    assert!(
        result["worker_live"].is_null(),
        "a journal alone cannot prove whether another process owns a worker"
    );
    assert_eq!(result["recovery_available"], true);
    assert_eq!(result["activation_granted"], false);
    assert_eq!(jobs.list(&fixture.home).unwrap().len(), 1);
    assert!(!fixture.home.join("context-assistance/work").exists());
    assert!(!fixture.home.join("context-assistance/bundles").exists());
    assert!(!fixture
        .home
        .join("context-assistance/installation-authority.json")
        .exists());
}
#[test]
fn repeated_requests_converge_and_reused_keys_cannot_change_the_target() {
    let fixture = Fixture::new();
    let job = fixture.job("same-request");
    let jobs = Jobs::default();
    assert_eq!(
        jobs.install(&fixture.home, job.request.clone()).unwrap()["phase"],
        "queued"
    );
    let mut request = job.request.clone();
    request.build_id = "different-build".into();
    assert_eq!(
        jobs.install(&fixture.home, request),
        Err(error("install_idempotency_conflict"))
    );
    let mut request = job.request;
    request.interpreter_id = "different-interpreter".into();
    assert_eq!(
        jobs.install(&fixture.home, request),
        Err(error("install_idempotency_conflict"))
    );
    assert_eq!(jobs.list(&fixture.home).unwrap().len(), 1);
}
#[test]
fn interrupted_preparation_recovers_without_launching_or_selecting_a_runtime() {
    let fixture = Fixture::new();
    let mut job = fixture.job("interrupted");
    let stage = fixture.owned_stage(&job);
    fs::write(stage.join("partial-package"), b"partial approved SDK bytes").unwrap();
    store::save(&fixture.home, &mut job, Phase::Extracting, "extracting").unwrap();
    let result = Jobs::default()
        .recover(&fixture.home, &job.request.job_id)
        .unwrap();
    assert_eq!(result["phase"], "failed");
    assert_eq!(result["code"], "install_interrupted");
    assert!(!stage.exists());
    let settings = crate::guard_config_load::context_assistance_config(&fixture.home).unwrap();
    assert!(!settings.requested.enabled);
    assert!(settings.requested.runtime_id.is_empty());
    assert!(!fixture
        .home
        .join("context-assistance/installation-authority.json")
        .exists());
}
#[test]
fn durable_cancel_intent_is_reconciled_after_the_worker_is_gone() {
    let fixture = Fixture::new();
    let job = fixture.job("cancel-on-restart");
    let jobs = Jobs::default();
    assert_eq!(
        jobs.cancel(&fixture.home, &job.request.job_id).unwrap()["cancel_requested"],
        true
    );
    let result = Jobs::default()
        .recover(&fixture.home, &job.request.job_id)
        .unwrap();
    assert_eq!(result["phase"], "cancelled");
    assert_eq!(result["activation_granted"], false);
}
#[test]
fn recovery_will_not_race_an_existing_preparation_lease() {
    let fixture = Fixture::new();
    let job = fixture.job("owned-elsewhere");
    let _owner = store::lease(&fixture.home).unwrap();
    assert_eq!(
        Jobs::default().recover(&fixture.home, &job.request.job_id),
        Err(error("install_busy"))
    );
    assert_eq!(
        store::get(&fixture.home, &job.request.job_id)
            .unwrap()
            .unwrap()
            .phase,
        Phase::Queued
    );
}
#[test]
#[cfg(unix)]
fn cleanup_preserves_external_symlink_targets_and_records_recovery_needed() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let mut job = fixture.job("unsafe-staging");
    let stage = fixture.owned_stage(&job);
    let external = fixture.home.join("operator-document.txt");
    fs::write(&external, b"operator-owned data").unwrap();
    symlink(&external, stage.join("unexpected-link")).unwrap();
    store::save(&fixture.home, &mut job, Phase::Extracting, "extracting").unwrap();
    let result = Jobs::default()
        .recover(&fixture.home, &job.request.job_id)
        .unwrap();
    assert_eq!(result["phase"], "recovery_required");
    assert_eq!(fs::read(external).unwrap(), b"operator-owned data");
    assert!(stage.join("unexpected-link").symlink_metadata().is_ok());
}
#[test]
fn metadata_listing_tolerates_its_atomic_writer_and_refuses_malformed_names() {
    let fixture = Fixture::new();
    let job = fixture.job("metadata-writer");
    let jobs = store::directory(&fixture.home, "jobs", false).unwrap();
    let pending = format!(".{}.123.1234567890.tmp", record_name(&job.request.job_id));
    fs::write(jobs.join(&pending), b"unfinished atomic write").unwrap();
    assert!(store::temporary_name(&pending));
    assert_eq!(Jobs::default().list(&fixture.home).unwrap().len(), 1);
    let unicode = format!("{}é.json", "a".repeat(62));
    assert_eq!(unicode.len(), 69);
    fs::write(jobs.join(unicode), b"{}").unwrap();
    assert_eq!(
        Jobs::default().list(&fixture.home),
        Err(error("install_job_invalid"))
    );
}
#[test]
fn job_record_tampering_and_public_path_injection_are_refused() {
    let fixture = Fixture::new();
    let mut job = fixture.job("invalid-metadata");
    job.slot = "../external".into();
    assert_eq!(job.validate(), Err(error("install_job_invalid")));
    let service = crate::context_assistance_service::Service::default();
    for input in [
        json!({"action":"install","job_id":"job","build_id":"build","interpreter_id":"python","python":"/arbitrary/python"}),
        json!({"action":"register_interpreter","python":"/arbitrary/python"}),
        json!({"action":"install","job_id":"job","build_id":"build","interpreter_id":"python","guard_qualified":true}),
    ] {
        assert_eq!(
            service.versions(&fixture.home, input),
            Err(error("versions_request_invalid"))
        );
    }
}

#[path = "context_assistance_python_jobs_tests.rs"]
mod private_python;

#[cfg(unix)]
#[path = "context_assistance_install_jobs_actual_tests.rs"]
mod actual;

fn metadata_interpreter(fixture: &Fixture) -> interpreters::Interpreter {
    let python = PathBuf::from("/not-executed/python3.14");
    let facts = InterpreterFacts {
        schema: "guard-cigar-interpreter.v1".into(),
        implementation: "cpython".into(),
        version: [3, 14, 7],
        release_level: "final".into(),
        free_threaded: false,
        debug_build: false,
        abi: "cpython-314-darwin".into(),
        platform: "darwin-arm64".into(),
    };
    let python_sha256 = "d".repeat(64);
    let bytes = serde_json::to_vec(&(
        "guard-cigar-interpreter-id.v1",
        &python,
        &python_sha256,
        &facts,
    ))
    .unwrap();
    let record = interpreters::Interpreter {
        schema: "guard-cigar-interpreter-installation.v1".into(),
        interpreter_id: format!("python:{:x}", Sha256::digest(bytes)),
        python,
        python_sha256,
        facts,
        managed_python: None,
    };
    let directory = store::directory(&fixture.home, "interpreters", true).unwrap();
    persist_private_bytes(
        &directory.join(record_name(&record.interpreter_id)),
        &serde_json::to_vec(&record).unwrap(),
        16 * 1024,
        "cigar_interpreter",
        &fixture.home,
    )
    .unwrap();
    record
}
#[test]
fn upstream_only_build_is_refused_before_any_job_or_sdk_preparation() {
    let fixture = Fixture::new();
    let interpreter = metadata_interpreter(&fixture);
    let catalog = TrustedCatalog::bundled().unwrap();
    let request = InstallRequest {
        job_id: "unqualified".into(),
        build_id: catalog.document().builds[0].identity.build_id.clone(),
        interpreter_id: interpreter.interpreter_id,
    };
    assert_eq!(
        Jobs::default().install(&fixture.home, request),
        Err(error("cigar_guard_qualification_required"))
    );
    assert!(store::list(&fixture.home).unwrap().is_empty());
    for name in ["bundles", "work", "staging", "artifacts"] {
        assert!(!fixture.home.join("context-assistance").join(name).exists());
    }
}
#[test]
fn local_setup_requires_operator_consent_and_rejects_supplied_interpreter_facts() {
    let fixture = Fixture::new();
    let request = json!({"schema":"guard-cigar-install-operator.v1","guard_home":fixture.home,"operator_approved":false,
        "operation":{"action":"register_interpreter","python":"/never-executed/python"}});
    let response: Value =
        serde_json::from_slice(&run_operator_command(request.to_string().as_bytes()).unwrap())
            .unwrap();
    assert_eq!(response["ok"], false);
    assert_eq!(
        response["code"],
        error("install_operator_approval_required")
    );
    let mut forged = request;
    forged["operator_approved"] = json!(true);
    forged["operation"]["facts"] = json!({"version":[3,14,7]});
    assert_eq!(
        run_operator_command(forged.to_string().as_bytes()),
        Err(error("install_operator_request_invalid"))
    );
    assert!(!fixture
        .home
        .join("context-assistance/interpreters")
        .exists());
}
#[test]
fn cleanup_preserves_every_registered_alias_even_when_it_is_not_selected() {
    let fixture = Fixture::new();
    let mut job = fixture.job("registered-alias");
    let stage = fixture.owned_stage(&job);
    let payload = stage.join("operator-sdk.py");
    fs::write(&payload, b"operator-owned SDK bytes").unwrap();
    let interpreter = metadata_interpreter(&fixture);
    let record = Installation {
        schema: SCHEMA.into(),
        runtime_id: "operator-alias".into(),
        qualification: "local_candidate".into(),
        source_revision: job.release.identity.source_revision.clone(),
        selection: RuntimeSelection {
            verified_python: None,
            python_bundle: None,
            python: interpreter.python,
            site_packages: stage.clone(),
            work_dir: fixture.home.join("operator-work"),
        },
        approval: BundleApproval {
            python_bundle: None,
            schema: "guard-cigar-bundle-approval.v1".into(),
            platform: "darwin-arm64".into(),
            python_sha256: job.python_sha256.clone(),
            package_tree_sha256: job.package_tree_sha256.clone(),
            worker_sha256: job.worker_sha256.clone(),
            files: 1,
            bytes: 24,
            release: None,
        },
        interpreter: interpreter.facts,
        receipt: None,
        managed_slot: None,
        verification_job_id: None,
    };
    let path = root(&fixture.home, false)
        .unwrap()
        .join(record_name(&record.runtime_id));
    persist_private_bytes(
        &path,
        &serde_json::to_vec(&record).unwrap(),
        MAX_RECORD,
        "cigar_installation",
        &fixture.home,
    )
    .unwrap();
    store::save(&fixture.home, &mut job, Phase::Extracting, "extracting").unwrap();
    let recovered = Jobs::default()
        .recover(&fixture.home, &job.request.job_id)
        .unwrap();
    assert_eq!(recovered["phase"], "recovery_required");
    assert_eq!(recovered["code"], error("install_slot_in_use"));
    assert_eq!(fs::read(payload).unwrap(), b"operator-owned SDK bytes");
}

#[cfg(unix)]
#[test]
fn later_python_patch_requirement_refuses_before_any_job_download_or_sdk() {
    let fixture = Fixture::new();
    let interpreter = metadata_interpreter(&fixture);
    let catalog = actual::approved_catalog_requirement(Some(">=3.14.8,<3.15"));
    let request = InstallRequest {
        job_id: "needs-newer-python".into(),
        build_id: catalog.document().builds[0].identity.build_id.clone(),
        interpreter_id: interpreter.interpreter_id,
    };
    let jobs = Jobs::default();
    assert_eq!(
        jobs.install_catalog(&fixture.home, request, &catalog),
        Err(error("cigar_python_version_required"))
    );
    assert!(jobs.list(&fixture.home).unwrap().is_empty());
    for name in ["artifacts", "downloads", "bundles", "work"] {
        assert!(
            !fixture.home.join("context-assistance").join(name).exists(),
            "{name}"
        );
    }
    let settings = crate::guard_config_load::context_assistance_config(&fixture.home).unwrap();
    assert!(!settings.requested.enabled);
    assert!(settings.requested.runtime_id.is_empty());
}
