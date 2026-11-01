//! Explicit local-candidate proof through the real native control service.
use super::*;
use serde_json::Value;
use std::time::{Duration, Instant};

fn wait_for_job(fixture: &Fixture) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let answer = fixture.ask("status");
        assert_eq!(answer["status"], "ok");
        if answer["payload"]["state"]["job"].is_null() {
            return answer["payload"]["state"].clone();
        }
        assert!(
            Instant::now() < deadline,
            "native verification did not finish"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn opt_in(fixture: &Fixture) {
    let request = json!({"schema":"guard-config-update.v1", "guard_home":fixture.home, "kind":"settings",
        "value_text":json!({"context_assistance":{"enabled":true,"runtime_id":"candidate-314"}}).to_string()});
    let response: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(request.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(response["ok"], true, "{response}");
}

#[test]
#[ignore = "requires the explicitly approved installed CIGAR 0.14.1 candidate"]
fn installed_native_enrollment_activation_disable_and_cancel() {
    let selection_path =
        std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit candidate selection");
    let approval_path = std::env::var_os("GUARD_CIGAR_TEST_APPROVAL")
        .expect("independent recorded bundle approval");
    let selection: Value = serde_json::from_slice(&std::fs::read(selection_path).unwrap()).unwrap();
    let approval: Value = serde_json::from_slice(&std::fs::read(approval_path).unwrap()).unwrap();
    let fixture = Fixture::new();
    assert_eq!(
        fixture.ask("status")["payload"]["state"]["effective_enabled"],
        false
    );
    let enroll = json!({"schema":"guard-cigar-enroll-local.v1", "guard_home":fixture.home, "runtime_id":"candidate-314",
        "local_candidate_approved":true, "source_revision":"b47380e5a5cbeaaad5a61cab3372e9e67368732f", "selection":selection, "approval":approval});
    let enrollment: Value = serde_json::from_slice(
        &crate::policy_store::context_assistance_registry::run_enroll_command(
            enroll.to_string().as_bytes(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(enrollment["ok"], true, "{enrollment}");
    assert_eq!(enrollment["installation"]["activation_granted"], false);
    let choices = fixture.ask("installations");
    assert_eq!(choices["status"], "ok");
    assert_eq!(
        choices["payload"]["state"]["installation_options"][0]["runtime_id"],
        "candidate-314"
    );
    assert!(!choices
        .to_string()
        .contains(selection["site_packages"].as_str().unwrap()));
    opt_in(&fixture);
    let before = fixture.ask("status");
    assert_eq!(before["payload"]["state"]["requested_enabled"], true);
    assert_eq!(before["payload"]["state"]["effective_enabled"], false);
    let start = Instant::now();
    assert_eq!(fixture.ask("activate")["status"], "ok");
    let scheduling_ms = start.elapsed().as_millis();
    assert!(
        scheduling_ms < 1000,
        "verification blocked resident control request"
    );
    let ready = wait_for_job(&fixture);
    assert_eq!(ready["effective_enabled"], true, "{ready}");
    assert_eq!(ready["runtime"]["interpreter"]["version"][0], 3);
    assert_eq!(ready["runtime"]["interpreter"]["version"][1], 14);
    assert_eq!(ready["runtime"]["package_version"], "0.14.1");
    assert_eq!(
        ready["runtime"]["worker_fingerprint"],
        approval["worker_sha256"]
    );
    assert_eq!(
        fixture.ask("stop")["payload"]["state"]["effective_enabled"],
        false
    );
    assert_eq!(
        fixture.ask("status")["payload"]["state"]["requested_enabled"],
        false
    );
    opt_in(&fixture);
    assert_eq!(fixture.ask("activate")["status"], "ok");
    assert_eq!(wait_for_job(&fixture)["effective_enabled"], true);
    std::fs::write(
        fixture.home.join("config.toml"),
        "[context_assistance]\nenabled=false\nruntime_id='candidate-314'\n",
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        // This status method does not load settings: only the native watcher
        // can observe the file edit without a control request.
        let status = fixture.store.context_assistance().status().unwrap();
        if status["effective_enabled"] == false && status["requested_enabled"] == false {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "native settings watcher did not stop assistance"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    opt_in(&fixture);
    assert_eq!(fixture.ask("activate")["status"], "ok");
    std::thread::sleep(Duration::from_millis(50));
    let stopped = fixture.ask("stop");
    assert_eq!(stopped["payload"]["state"]["effective_enabled"], false);
    let cancelled = wait_for_job(&fixture);
    assert_eq!(cancelled["requested_enabled"], false);
    assert_eq!(cancelled["effective_enabled"], false);
    assert!(cancelled["runtime"].is_null());
    opt_in(&fixture);
    assert_eq!(fixture.ask("activate")["status"], "ok");
    assert_eq!(wait_for_job(&fixture)["effective_enabled"], true);
    fixture.store.context_assistance().shutdown();
    let retired = fixture.store.context_assistance().status().unwrap();
    assert_eq!(retired["effective_enabled"], false);
    assert!(retired["runtime"].is_null());
    let persisted = crate::guard_config_load::context_assistance_config(&fixture.home).unwrap();
    assert!(
        persisted.requested.enabled,
        "resident shutdown must not edit saved consent"
    );
    assert_eq!(
        fixture
            .store
            .context_assistance()
            .configure(persisted)
            .unwrap_err(),
        "native_context_assistance_shutdown"
    );
    println!(
        "GUARD_CIGAR_CONTROL_VERIFICATION={}",
        json!({"schema":"guard-cigar-native-control-verification.v1", "status":"passed",
        "qualification":"local-development-darwin-arm64-only", "activation_scheduling_ms":scheduling_ms,
        "worker_fingerprint":approval["worker_sha256"], "ready_observation":ready,
        "final_availability":cancelled["availability"], "final_effective_enabled":cancelled["effective_enabled"],
        "checks":["local_enrollment_actual_process_verification","enrollment_grants_no_activation","private_metadata_listing",
            "setup_listing_omits_paths","native_opt_in_gate","requested_is_not_effective","background_activation",
            "resident_shutdown_releases_actual_runtime","shutdown_prevents_late_config_reactivation","shutdown_preserves_saved_consent",
            "actual_cpython_314_sdk_worker","persisted_opt_out","out_of_band_opt_out_watched","pending_verification_cancelled","no_late_reactivation"]})
    );
}
