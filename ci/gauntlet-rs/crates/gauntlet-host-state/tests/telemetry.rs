use gauntlet_host_state::{resource_admission_reasons, TelemetryError, VmProbePlan};
use serde_json::{json, Value};
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;

#[test]
fn fixed_probe_and_resource_reasons_match_pinned_python() {
    let fixture: Value = serde_json::from_str(include_str!("python_telemetry_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/control_plane/telemetry.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(fixture["schema"], "gauntlet-telemetry-fixtures.v1");
    let operations: Value =
        serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
    let plan = VmProbePlan::new(&operations).unwrap();
    assert_eq!(plan.to_json()["argv"], fixture["probe"]["call"]["argv"]);
    assert_eq!(fixture["probe"]["call"]["timeout"], 12);
    assert_eq!(fixture["probe"]["call"]["capture_output"], true);
    assert_eq!(plan.to_json()["admission_eligible"], false);
    assert_eq!(
        plan.parse_response(
            fixture["probe"]["sample_stdout"]
                .as_str()
                .unwrap()
                .as_bytes()
        )
        .unwrap(),
        fixture["probe"]["positive"]
    );
    let cases = fixture["admission_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 11);
    let now = fixture["now"].as_f64().unwrap();
    for case in cases {
        assert_eq!(
            json!(resource_admission_reasons(&case["snapshot"], &operations, now).unwrap()),
            case["reasons"],
            "{case}"
        );
    }
}

#[test]
fn probe_refuses_duplicate_fields_bad_metrics_and_oversize() {
    let operations: Value =
        serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
    let plan = VmProbePlan::new(&operations).unwrap();
    let fixture: Value = serde_json::from_str(include_str!("python_telemetry_v1.json")).unwrap();
    let sample = fixture["probe"]["positive"].as_object().unwrap();
    let mut missing = sample.clone();
    missing.remove("name");
    missing.remove("disk_free");
    assert_eq!(
        plan.parse_response(&serde_json::to_vec(&missing).unwrap()),
        Err(TelemetryError::InvalidProbe)
    );
    let mut bad = missing.clone();
    bad.insert("disk_free".to_owned(), json!(u64::MAX));
    assert_eq!(
        plan.parse_response(&serde_json::to_vec(&bad).unwrap()),
        Err(TelemetryError::InvalidProbe)
    );
    let duplicate = br#"{"status":"running","status":"running"}"#;
    assert_eq!(
        plan.parse_response(duplicate),
        Err(TelemetryError::InvalidProbe)
    );
    assert_eq!(
        plan.parse_response(&vec![b'x'; 8193]),
        Err(TelemetryError::TooLarge)
    );
}

#[test]
fn fake_lima_probe_has_fixed_argv_and_generic_failures() {
    let temporary = tempfile::tempdir().unwrap();
    let executable = temporary.path().join("fake-limactl");
    let fixture: Value = serde_json::from_str(include_str!("python_telemetry_v1.json")).unwrap();
    let stdout = fixture["probe"]["sample_stdout"].as_str().unwrap();
    fs::write(&executable, format!("#!/bin/sh\nprintf '%s' '{stdout}'\n")).unwrap();
    fs::set_permissions(&executable, Permissions::from_mode(0o700)).unwrap();
    let mut operations: Value =
        serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
    operations["limactl"] = executable.to_str().unwrap().into();
    let plan = VmProbePlan::new(&operations).unwrap();
    assert_eq!(
        plan.execute_read_only().unwrap(),
        fixture["probe"]["positive"]
    );
    fs::write(&executable, b"#!/bin/sh\nexit 7\n").unwrap();
    assert_eq!(plan.execute_read_only(), Err(TelemetryError::Unavailable));
}

#[test]
fn malformed_snapshot_and_configuration_do_not_become_healthy() {
    let operations: Value =
        serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
    assert_eq!(
        resource_admission_reasons(&json!({"host":{"checked_at":"recent"}}), &operations, 100.0),
        Err(TelemetryError::InvalidSnapshot)
    );
    assert_eq!(
        resource_admission_reasons(&json!({}), &operations, f64::NAN),
        Err(TelemetryError::InvalidSnapshot)
    );
    let mut invalid = operations.clone();
    invalid["vm"] = json!("../other");
    assert_eq!(
        VmProbePlan::new(&invalid),
        Err(TelemetryError::InvalidConfig)
    );
}
