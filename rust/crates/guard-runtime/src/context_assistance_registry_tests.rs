use super::*;
#[path = "context_assistance_registry_v2_tests.rs"]
mod versioned_tests;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "guard-cigar-registry-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        root(&path, true).unwrap();
        Self(path)
    }
    fn record(&self) -> Installation {
        Installation {
            schema: SCHEMA.into(),
            runtime_id: "local-314".into(),
            qualification: "local_candidate".into(),
            source_revision: "0".repeat(40),
            selection: RuntimeSelection {
                verified_python: None,
                python_bundle: None,
                python: "/not-launched/python".into(),
                site_packages: "/not-read/site".into(),
                work_dir: "/not-used/work".into(),
            },
            approval: BundleApproval {
                python_bundle: None,
                schema: "guard-cigar-bundle-approval.v1".into(),
                platform: "darwin-arm64".into(),
                python_sha256: "0".repeat(64),
                package_tree_sha256: "0".repeat(64),
                worker_sha256: "0".repeat(64),
                files: 1,
                bytes: 1,
                release: None,
            },
            receipt: None,
            managed_slot: None,
            verification_job_id: None,
            interpreter: InterpreterFacts {
                schema: "guard-cigar-interpreter.v1".into(),
                implementation: "cpython".into(),
                version: [3, 14, 7],
                release_level: "final".into(),
                free_threaded: false,
                debug_build: false,
                abi: "cpython-314-darwin".into(),
                platform: "darwin-arm64".into(),
            },
        }
    }
    fn write(&self, record: &Installation) -> PathBuf {
        let path = root(&self.0, false)
            .unwrap()
            .join(record_name(&record.runtime_id));
        persist_private_bytes(
            &path,
            &serde_json::to_vec(record).unwrap(),
            MAX_RECORD,
            "cigar_installation",
            &self.0,
        )
        .unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn private_record_is_bound_to_selection_id_and_does_not_grant_readiness() {
    let fixture = Fixture::new();
    let mut record = fixture.record();
    let path = fixture.write(&record);
    assert_eq!(
        load(&fixture.0, "local-314").unwrap().runtime_id,
        "local-314"
    );
    assert!(load(&fixture.0, "../local-314").is_err());
    record.runtime_id = "foreign".into();
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(load(&fixture.0, "local-314").is_err());
}

#[cfg(unix)]
#[test]
fn registry_rejects_shared_records_hardlinks_and_redirected_directories() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let path = fixture.write(&fixture.record());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load(&fixture.0, "local-314").is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = fixture.0.join("alias.json");
    fs::hard_link(&path, &alias).unwrap();
    assert!(load(&fixture.0, "local-314").is_err());
    fs::remove_file(alias).unwrap();
    let directory = fixture.0.join("context-assistance/installations");
    let redirected = fixture.0.join("redirected");
    fs::rename(&directory, &redirected).unwrap();
    std::os::unix::fs::symlink(&redirected, &directory).unwrap();
    assert!(load(&fixture.0, "local-314").is_err());
}

#[test]
fn enrollment_requires_explicit_local_candidate_approval_before_launch() {
    let fixture = Fixture::new();
    let record = fixture.record();
    let payload = json!({"schema":"guard-cigar-enroll-local.v1", "guard_home":fixture.0,
        "runtime_id":record.runtime_id, "local_candidate_approved":false, "source_revision":record.source_revision,
        "selection":record.selection, "approval":record.approval});
    let response: Value = serde_json::from_slice(
        &run_enroll_command(serde_json::to_vec(&payload).unwrap().as_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(response["ok"], false);
    assert_eq!(
        response["code"],
        "native_context_assistance_enrollment_invalid"
    );
}

#[test]
fn managed_prohibition_refuses_enrollment_before_any_selected_runtime_read_or_launch() {
    let fixture = Fixture::new();
    let policy = fixture.0.join("managed.json");
    fs::write(&policy, json!({"schemaVersion":"hol-guard-mdm-policy.v1", "settings":{"context_assistance":{"enabled":false}}}).to_string()).unwrap();
    let mut source = crate::managed_policy_load::ManagedPolicySource::native();
    source.policy_path = Some(policy);
    source.write_cache = false;
    let record = fixture.record();
    let request = EnrollRequest {
        schema: "guard-cigar-enroll-local.v1".into(),
        guard_home: fixture.0.clone(),
        runtime_id: record.runtime_id,
        source_revision: record.source_revision,
        local_candidate_approved: true,
        selection: record.selection,
        approval: record.approval,
    };
    assert_eq!(
        enroll_with_source(request, &source).unwrap_err(),
        "native_context_assistance_policy_restricted"
    );
    assert!(list(&fixture.0).unwrap().is_empty());
}
