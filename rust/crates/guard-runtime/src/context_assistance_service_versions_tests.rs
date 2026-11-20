use super::*;
use std::path::PathBuf;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "guard-cigar-version-controls-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        Self(crate::resident_state::ensure_private_directory(&path, true).unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn listing_jobs_is_passive_and_preparing_cannot_enable_an_off_runtime() {
    let f = Fixture::new();
    let s = Service::default();
    assert_eq!(
        s.versions(&f.0, json!({"action":"jobs"})).unwrap(),
        json!({"jobs":[]})
    );
    assert!(!f.0.join("context-assistance").exists());
    assert!(!f.0.join("config.toml").exists());
    #[cfg(unix)]
    {
        let first = s.versions(&f.0, json!({"action":"prepare_switch", "job_id":"off", "target_runtime_id":"target", "expected_generation":"1"})).unwrap();
        assert_eq!(first["initial_selection"], true);
        assert!(first["source_runtime_id"].is_null());
        assert_eq!(first["reconnect_required"], false);
        let started = Instant::now();
        loop {
            let job = s.switch_job(&f.0, "off").unwrap();
            if job["worker_live"] == false {
                assert_eq!(job["phase"], "failed");
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(5), "{job}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let status = s.status().unwrap();
    assert_eq!(status["availability"], "off");
    assert_eq!(status["requested_enabled"], false);
    assert!(status["runtime"].is_null());
    assert!(!f.0.join("config.toml").exists());
}
#[test]
fn generations_are_exact_decimal_strings_and_authority_fields_are_rejected() {
    let f = Fixture::new();
    let s = Service::default();
    for raw in [
        json!(1),
        json!(true),
        json!(null),
        json!("0"),
        json!("01"),
        json!("+1"),
        json!("1 "),
        json!("18446744073709551616"),
    ] {
        assert_eq!(s.versions(&f.0, json!({"action":"prepare_switch", "job_id":"test", "target_runtime_id":"target", "expected_generation":raw})).unwrap_err(), "native_context_assistance_versions_request_invalid");
    }
    for extra in [
        "python",
        "worker_sha256",
        "grants",
        "rollback",
        "source_disabled",
    ] {
        let mut input = json!({"action":"prepare_switch", "job_id":"test", "target_runtime_id":"target", "expected_generation":"1"});
        input[extra] = json!("untrusted");
        assert_eq!(
            s.versions(&f.0, input).unwrap_err(),
            "native_context_assistance_versions_request_invalid"
        );
    }
    assert!(!f.0.join("context-assistance").exists());
}
#[cfg(unix)]
#[test]
fn switch_jobs_join_metadata_listing_and_cancellation_without_starting_an_sdk() {
    use crate::policy_store::context_assistance_registry::switching::{
        jobs::{self, JobPhase, SwitchJob, SwitchRequest},
        Owner,
    };
    let f = Fixture::new();
    let s = Service::default();
    let owner = Owner::acquire(&f.0).unwrap();
    let mut job = SwitchJob::new(
        SwitchRequest {
            job_id: "switch-meta".into(),
            target_runtime_id: "target".into(),
            expected_generation: 9007199254740993,
            rollback: false,
        },
        "source".into(),
    )
    .unwrap();
    jobs::save(&f.0, &mut job, JobPhase::Ready, "ready").unwrap();
    drop(owner);
    let list = s.versions(&f.0, json!({"action":"jobs"})).unwrap();
    assert_eq!(list["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(list["jobs"][0]["operation"], "switch");
    assert_eq!(list["jobs"][0]["expected_generation"], "9007199254740993");
    assert_eq!(list["jobs"][0]["can_commit"], false);
    assert_eq!(list["jobs"][0]["recovery_available"], true);
    let get = s
        .versions(&f.0, json!({"action":"job", "job_id":"switch-meta"}))
        .unwrap();
    assert_eq!(get, list["jobs"][0]);
    assert!(s.versions(&f.0, json!({"action":"commit", "job_id":"switch-meta", "expected_generation":"9007199254740993", "reconnect":false})).unwrap_err().ends_with("switch_reconnect_acknowledgement_required"));
    assert!(s.versions(&f.0, json!({"action":"commit", "job_id":"switch-meta", "expected_generation":"9007199254740992", "reconnect":true})).unwrap_err().ends_with("switch_selection_conflict"));
    let cancelled = s
        .versions(&f.0, json!({"action":"cancel", "job_id":"switch-meta"}))
        .unwrap();
    assert_eq!(cancelled["cancel_requested"], true);
    assert_eq!(
        s.versions(&f.0, json!({"action":"recover", "job_id":"switch-meta"}))
            .unwrap_err(),
        "native_context_assistance_versions_request_invalid"
    );
    assert!(s
        .versions(
            &f.0,
            json!({"action":"recover", "job_id":"switch-meta", "expected_generation":"1"})
        )
        .unwrap_err()
        .ends_with("switch_transaction_missing"));
    assert!(s.status().unwrap()["runtime"].is_null());
    assert!(!f.0.join("config.toml").exists());
}

#[test]
fn version_routes_require_operator_authorization_and_resident_results_are_bound() {
    use crate::context_assistance_op::{Request, VERSIONS_FEATURE};
    for path in [
        "/v1/context-assistance/versions",
        "/v1/context-assistance/jobs",
        "/v1/context-assistance/interpreters",
    ] {
        assert!(crate::daemon_route_paths::requires_header_token(path));
        assert!(crate::daemon_route_paths::session_path("GET", path));
        assert!(crate::daemon_route_paths::session_path("POST", path));
        assert!(!crate::daemon_route_paths::protection_repair_session_allowed("POST", path));
    }
    assert!(crate::resident_protocol::capabilities()
        .features
        .iter()
        .any(|f| f == VERSIONS_FEATURE));
    let f = Fixture::new();
    use std::io::Write;
    let mut key =
        crate::resident_state::private_file(&f.0.join("policy-verifier.key"), true, &f.0).unwrap();
    key.write_all(&[82_u8; 32]).unwrap();
    drop(key);
    let store = crate::policy_store::PolicySnapshotStore::new(&f.0, &"a".repeat(64)).unwrap();
    let request: Request = serde_json::from_value(
        json!({"schema":"guard-context-assistance-request.v1", "request_id":"versions-off",
        "query":{"kind":"versions", "guard_home":f.0, "input":{"action":"jobs"}}}),
    )
    .unwrap();
    let answer: Value =
        serde_json::from_slice(&crate::context_assistance_op::evaluate(&request, &store).unwrap())
            .unwrap();
    assert_eq!(answer["status"], "ok");
    assert_eq!(
        answer["payload"]["data"],
        json!({"schema":"guard-cigar-versions-result.v1", "result":{"jobs":[]}})
    );
    assert_eq!(answer["payload"]["state"]["requested_enabled"], false);
    assert!(answer["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let frame = json!({"operation":"context_assistance", "request":request});
    assert_eq!(
        crate::resident_protocol::evaluate_resident_bytes(frame.to_string().as_bytes(), None)
            .unwrap_err(),
        "native_context_assistance_resident_required"
    );
    assert!(!f.0.join("context-assistance").exists());
}
