use serde_json::{json, Value};

use super::*;

const SNAPSHOT_SCHEMA_DOCUMENT: &str =
    include_str!("../../../../docs/guard/schemas/local-integrity-snapshot-v1.schema.json");

/// A machine where every probe passed.
fn healthy_request() -> Value {
    json!({
        "schema": SCHEMA,
        "generated_at": "2026-07-18T14:00:00.123456Z",
        "platform": "darwin",
        "architecture": "arm64",
        "fallback_version": "0.0.0",
        "manifest_hash": "a".repeat(64),
        "policy": {
            "status": "active",
            "reason_code": null,
            "install_owner": "mdm",
            "content_hash": "b".repeat(64),
        },
        "native": {
            "status": "healthy",
            "reason_code": "native_install_valid",
            "package_identity": "org.hol.guard",
            "signature_state": "verified",
            "version": "3.60.0",
        },
        "manifest": {
            "status": "healthy",
            "reason_code": "release_manifest_valid",
            "version": "3.60.1",
            "build_id": "build-1",
            "installer_identity": "org.hol.guard",
            "signature_state": "verified",
        },
        "acl": {"status": "healthy", "reason_code": "ownership_acl_valid", "surfaces": []},
        "supervisor": {"state": "running", "reason_code": "supervisor_running"},
        "device_key": {
            "state": "healthy",
            "level": "hardware-backed",
            "reason_code": "device_key_active",
        },
        "harness": {
            "state": "healthy",
            "reason_code": "harness_coverage_healthy",
            "coverage": {"required": 2, "protected": 2, "degraded": 0, "missing": 0},
        },
        "continuity": {
            "state": "active",
            "identity_reason_code": "installation_identity_active",
            "lease_reason_code": "lease_continuity_active",
            "record": {
                "machine_installation_id": "1".repeat(32),
                "installation_generation": "2".repeat(32),
                "generation_created_at": "2026-07-18T14:00:00+00:00",
                "key_id_at_generation_creation": "key-1",
                "last_issued_sequence": 7,
                "last_lease_digest": "c".repeat(64),
            },
            "observation": {"boot_session_id": "boot-1", "monotonic_uptime_ns": 5_000_000_001_u64},
        },
        "command_shadowing": {"state": "healthy", "reason_code": "command_shadowing_trusted"},
    })
}

fn run(request: &Value) -> Result<Value, String> {
    let bytes = run_command(serde_json::to_vec(request).unwrap_or_default().as_slice())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn snapshot_of(request: &Value) -> Value {
    run(request).unwrap_or(Value::Null)
}

fn with(mut request: Value, pointer: &str, value: Value) -> Value {
    if let Some(slot) = request.pointer_mut(pointer) {
        *slot = value;
    }
    request
}

#[test]
fn reason_codes_match_the_snapshot_schema() {
    let schema: Value = serde_json::from_str(SNAPSHOT_SCHEMA_DOCUMENT).unwrap_or(Value::Null);
    let mut expected: Vec<&str> = schema["$defs"]["reasonCode"]["enum"]
        .as_array()
        .map(|codes| codes.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut actual = REASON_CODES.to_vec();
    expected.sort_unstable();
    actual.sort_unstable();
    assert_eq!(actual, expected);
}

#[test]
fn healthy_machine_snapshot() {
    let snapshot = snapshot_of(&healthy_request());
    assert_eq!(
        snapshot["schemaVersion"],
        json!("local-integrity-snapshot.v1")
    );
    assert_eq!(
        snapshot["generatedAt"],
        json!("2026-07-18T14:00:00.123456Z")
    );
    assert_eq!(snapshot["scope"], json!("machine"));
    assert_eq!(snapshot["healthy"], json!(true));
    assert_eq!(snapshot["assuranceLevel"], json!("mdm-managed-unverified"));
    assert_eq!(snapshot["installOwner"], json!("mdm"));
    assert_eq!(snapshot["platform"], json!("darwin"));
    assert_eq!(snapshot["architecture"], json!("arm64"));
    assert_eq!(snapshot["reasonCodes"], json!([]));
    assert_eq!(snapshot["remediationClass"], json!("none"));
    assert_eq!(
        snapshot["identifiers"],
        json!({
            "workspaceId": null,
            "deviceId": null,
            "machineInstallationId": "1".repeat(32),
            "installationGeneration": "2".repeat(32),
        })
    );
    assert_eq!(
        snapshot["product"],
        json!({
            "version": "3.60.1",
            "buildId": "build-1",
            "sourceCommit": null,
            "packageIdentity": "org.hol.guard",
            "manifestHash": "a".repeat(64),
            "policyHash": "b".repeat(64),
        })
    );
    assert_eq!(
        snapshot["harnessCoverage"],
        json!({"required": 2, "protected": 2, "degraded": 0, "missing": 0})
    );
    assert_eq!(snapshot["continuity"]["sequence"], json!(7));
    assert_eq!(
        snapshot["continuity"]["previousLeaseDigest"],
        json!("c".repeat(64))
    );
    assert_eq!(snapshot["continuity"]["bootSessionId"], json!("boot-1"));
    let components = &snapshot["components"];
    assert_eq!(
        components["update"],
        json!({"state": "healthy", "healthy": true, "reasonCode": "update_version_allowed"})
    );
    assert_eq!(
        components["managedPolicy"],
        json!({"state": "healthy", "healthy": true, "reasonCode": "managed_policy_active"})
    );
    assert_eq!(
        components["deviceKey"],
        json!({
            "state": "healthy",
            "healthy": true,
            "level": "hardware-backed",
            "reasonCode": "device_key_active",
        })
    );
    assert_eq!(
        components["supervisor"],
        json!({"state": "running", "healthy": true, "reasonCode": "supervisor_running"})
    );
    assert_eq!(
        components["daemon"],
        json!({"state": "healthy", "healthy": true, "reasonCode": "daemon_running"})
    );
    assert_eq!(components.as_object().map(Map::len), Some(12));
}

#[test]
fn uptime_matches_python_true_division() {
    let response = run_command(
        serde_json::to_vec(&healthy_request())
            .unwrap_or_default()
            .as_slice(),
    )
    .unwrap_or_default();
    let text = String::from_utf8(response).unwrap_or_default();
    assert!(text.contains("\"monotonicUptimeSeconds\":5.000000001"));
    assert_eq!(uptime_seconds(0).to_string(), "0.000000000");
    assert_eq!(
        uptime_seconds(u64::MAX).to_string(),
        "18446744073.709551615"
    );
    let snapshot = snapshot_of(&with(
        healthy_request(),
        "/continuity/observation",
        Value::Null,
    ));
    assert_eq!(
        snapshot["continuity"]["monotonicUptimeSeconds"],
        Value::Null
    );
    assert_eq!(snapshot["continuity"]["bootSessionId"], Value::Null);
}

#[test]
fn unknown_states_and_reason_codes_are_normalized() {
    assert_eq!(
        component("compromised", "release_manifest_absent"),
        Component {
            state: "unknown".to_owned(),
            healthy: false,
            reason_code: "release_manifest_absent".to_owned(),
            level: None,
        }
    );
    assert_eq!(
        component("tampered", "a_reason_nobody_named").reason_code,
        "integrity_reason_unrecognized"
    );
    let preserved = component("tampered", "managed_policy_source_tampered");
    assert_eq!(
        (preserved.state.as_str(), preserved.reason_code.as_str()),
        ("tampered", "managed_policy_source_tampered")
    );
}

#[test]
fn daemon_component_has_stable_supervisor_reason_codes() {
    for (supervisor, expected) in [
        ("supervisor_running", ("healthy", "daemon_running")),
        ("supervisor_absent", ("absent", "daemon_absent")),
        ("supervisor_stopped", ("degraded", "daemon_stopped")),
        ("supervisor_disabled", ("tampered", "daemon_disabled")),
        (
            "supervisor_registration_invalid",
            ("tampered", "daemon_registration_invalid"),
        ),
        (
            "supervisor_executable_mismatch",
            ("tampered", "daemon_registration_invalid"),
        ),
        (
            "supervisor_schedule_invalid",
            ("tampered", "daemon_registration_invalid"),
        ),
        (
            "supervisor_probe_failed",
            ("unknown", "daemon_probe_failed"),
        ),
        (
            "supervisor_verification_unavailable",
            ("unsupported", "daemon_verification_unavailable"),
        ),
    ] {
        let daemon = daemon_component(supervisor);
        assert_eq!(
            (daemon.state.as_str(), daemon.reason_code.as_str()),
            expected,
            "{supervisor}"
        );
    }
}

#[test]
fn continuity_reason_codes_map_to_component_states() {
    for (identity, expected) in [
        ("installation_identity_active", "healthy"),
        ("installation_identity_absent", "absent"),
        ("installation_identity_invalid", "tampered"),
        ("installation_identity_acl_invalid", "tampered"),
        ("installation_identity_key_mismatch", "tampered"),
        ("installation_identity_probe_failed", "unknown"),
    ] {
        let snapshot = snapshot_of(&with(
            healthy_request(),
            "/continuity/identity_reason_code",
            json!(identity),
        ));
        assert_eq!(
            snapshot["components"]["installationIdentity"]["state"],
            json!(expected),
            "{identity}"
        );
    }
    for (lease, expected) in [
        ("lease_continuity_active", "healthy"),
        ("lease_continuity_uninitialized", "healthy"),
        ("lease_continuity_absent", "absent"),
        ("lease_continuity_invalid", "tampered"),
        ("lease_continuity_monotonic_regression", "tampered"),
        ("lease_continuity_sequence_exhausted", "degraded"),
        ("lease_continuity_platform_unsupported", "unsupported"),
        ("lease_continuity_boot_probe_failed", "unknown"),
    ] {
        let snapshot = snapshot_of(&with(
            healthy_request(),
            "/continuity/lease_reason_code",
            json!(lease),
        ));
        assert_eq!(
            snapshot["components"]["leaseContinuity"]["state"],
            json!(expected),
            "{lease}"
        );
    }
}

#[test]
fn policy_state_and_install_owner() {
    let absent = json!({
        "status": "absent",
        "reason_code": "managed_policy_absent",
        "install_owner": null,
        "content_hash": null,
    });
    let snapshot = snapshot_of(&with(healthy_request(), "/policy", absent));
    assert_eq!(snapshot["installOwner"], json!("user"));
    assert_eq!(snapshot["assuranceLevel"], json!("user-managed"));
    assert_eq!(snapshot["product"]["policyHash"], Value::Null);
    assert_eq!(
        snapshot["components"]["managedPolicy"],
        json!({"state": "absent", "healthy": false, "reasonCode": "managed_policy_absent"})
    );
    assert_eq!(snapshot["remediationClass"], json!("user-reinstall"));

    for status in ["invalid", "inaccessible", "tampered"] {
        let policy = json!({
            "status": status,
            "reason_code": "managed_policy_invalid",
            "install_owner": null,
            "content_hash": null,
        });
        let snapshot = snapshot_of(&with(healthy_request(), "/policy", policy));
        assert_eq!(snapshot["installOwner"], json!("mdm"), "{status}");
        let expected = if status == "tampered" {
            "tampered"
        } else {
            "degraded"
        };
        assert_eq!(
            snapshot["components"]["managedPolicy"]["state"],
            json!(expected),
            "{status}"
        );
    }

    let cached = with(
        healthy_request(),
        "/policy/reason_code",
        json!("managed_policy_profile_removed_cached"),
    );
    let snapshot = snapshot_of(&cached);
    assert_eq!(
        snapshot["components"]["managedPolicy"],
        json!({
            "state": "degraded",
            "healthy": false,
            "reasonCode": "managed_policy_profile_removed_cached",
        })
    );
    assert_eq!(snapshot["remediationClass"], json!("mdm-repair"));

    let unnamed = with(healthy_request(), "/policy/reason_code", json!(""));
    let snapshot = snapshot_of(&unnamed);
    assert_eq!(
        snapshot["components"]["managedPolicy"]["reasonCode"],
        json!("managed_policy_active")
    );
}

#[test]
fn product_version_needs_a_verified_source() {
    let unverified_manifest = with(healthy_request(), "/manifest/status", json!("tampered"));
    let snapshot = snapshot_of(&unverified_manifest);
    assert_eq!(snapshot["product"]["version"], json!("3.60.0"));
    assert_eq!(snapshot["product"]["buildId"], Value::Null);
    let update = &snapshot["components"]["update"];
    assert_eq!(update["state"], json!("tampered"));
    assert_eq!(update["reasonCode"], json!("release_manifest_valid"));

    let neither = with(unverified_manifest, "/native/status", json!("unknown"));
    let snapshot = snapshot_of(&neither);
    assert_eq!(snapshot["product"]["version"], json!("0.0.0"));
    assert_eq!(
        snapshot["product"]["packageIdentity"],
        json!("org.hol.guard")
    );
}

#[test]
fn reason_codes_list_each_unhealthy_component_once() {
    let mut request = with(
        healthy_request(),
        "/supervisor",
        json!({
            "state": "disabled",
            "reason_code": "supervisor_disabled",
        }),
    );
    request = with(request, "/device_key/state", json!("degraded"));
    request = with(
        request,
        "/acl",
        json!({"status": "tampered", "reason_code": "ownership_acl_wrong_owner", "surfaces": []}),
    );
    let snapshot = snapshot_of(&request);
    assert_eq!(snapshot["healthy"], json!(false));
    assert_eq!(
        snapshot["reasonCodes"],
        json!([
            "daemon_disabled",
            "device_key_active",
            "ownership_acl_wrong_owner",
            "supervisor_disabled",
        ])
    );
    assert_eq!(snapshot["remediationClass"], json!("administrator-action"));
    assert_eq!(
        snapshot["components"]["supervisor"],
        json!({"state": "disabled", "healthy": false, "reasonCode": "supervisor_disabled"})
    );
}

#[test]
fn remediation_class_prefers_tamper_then_managed_repair() {
    assert_eq!(
        remediation_class("mdm-managed", true, &["healthy", "running"]),
        "none"
    );
    assert_eq!(
        remediation_class("user-managed", false, &["degraded", "tampered"]),
        "administrator-action"
    );
    assert_eq!(
        remediation_class("mdm-managed-unverified", false, &["degraded"]),
        "mdm-repair"
    );
    assert_eq!(
        remediation_class("user-managed", false, &["absent"]),
        "user-reinstall"
    );
}

#[test]
fn absent_continuity_record_leaves_identifiers_empty() {
    let snapshot = snapshot_of(&with(healthy_request(), "/continuity/record", Value::Null));
    assert_eq!(
        snapshot["identifiers"]["machineInstallationId"],
        Value::Null
    );
    assert_eq!(
        snapshot["identifiers"]["installationGeneration"],
        Value::Null
    );
    assert_eq!(snapshot["continuity"]["sequence"], Value::Null);
    assert_eq!(snapshot["continuity"]["previousLeaseDigest"], Value::Null);
}

#[test]
fn malformed_requests_fail() {
    let invalid = Err("integrity_snapshot_request_invalid".to_owned());
    assert_eq!(
        run(&with(healthy_request(), "/schema", json!("other.v1"))),
        invalid
    );
    let mut extra = healthy_request();
    if let Some(object) = extra.as_object_mut() {
        object.insert("unexpected".to_owned(), json!(true));
    }
    assert_eq!(run(&extra), invalid);
    let mut missing = healthy_request();
    if let Some(object) = missing.as_object_mut() {
        object.remove("harness");
    }
    assert_eq!(run(&missing), invalid);
    assert_eq!(
        run(&with(
            healthy_request(),
            "/continuity/record/last_issued_sequence",
            json!(-1),
        )),
        invalid
    );
    assert_eq!(
        run_command(&b"not json"[..]),
        Err("integrity_snapshot_request_invalid".to_owned())
    );
    let oversize = vec![b' '; 256 * 1024 + 1];
    assert_eq!(
        run_command(oversize.as_slice()),
        Err("integrity_snapshot_request_too_large".to_owned())
    );
}
