//! `integrity-snapshot --stdin`: compose the machine's local integrity snapshot
//! from the probe results Python gathered (`mdm/integrity.py` before the
//! composition moved here).
//!
//! Python still runs every probe: the managed policy load, the native package
//! and release manifest checks, ownership and ACLs, the supervisor, the device
//! key, harness coverage, installation continuity and command shadowing. The
//! probe results arrive as their dataclass fields, and this module maps them
//! onto the snapshot's components, reason codes, assurance level and
//! remediation class. Only a malformed request fails the command.

use std::collections::BTreeSet;
use std::io::Read;

use serde::Deserialize;
use serde_json::{json, Map, Number, Value};

const SCHEMA: &str = "integrity-snapshot.v1";
const SNAPSHOT_SCHEMA: &str = "local-integrity-snapshot.v1";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const PROFILE_REMOVED_CACHED: &str = "managed_policy_profile_removed_cached";
const STATES: [&str; 6] = [
    "healthy",
    "degraded",
    "absent",
    "tampered",
    "unsupported",
    "unknown",
];
/// `IntegrityReasonCode` in `mdm/contracts.py`, and the snapshot schema's
/// `reasonCode` enum.
const REASON_CODES: [&str; 112] = [
    "release_manifest_absent",
    "release_manifest_architecture_mismatch",
    "release_manifest_hash_mismatch",
    "release_manifest_coverage_gap",
    "release_manifest_duplicate_path",
    "release_manifest_file_limit_exceeded",
    "release_manifest_file_missing",
    "release_manifest_insecure_permissions",
    "release_manifest_invalid",
    "release_manifest_installer_identity_mismatch",
    "release_manifest_native_version_mismatch",
    "release_manifest_path_escape",
    "release_manifest_platform_mismatch",
    "release_manifest_size_limit_exceeded",
    "release_manifest_unsigned",
    "release_manifest_untrusted_key",
    "release_manifest_trust_anchor_absent",
    "release_manifest_valid",
    "release_manifest_version_rollback",
    "release_manifest_version_invalid",
    "release_manifest_wrong_owner",
    "release_runtime_insecure_permissions",
    "release_runtime_wrong_owner",
    "native_install_valid",
    "native_package_identity_absent",
    "native_package_receipt_absent",
    "native_package_version_invalid",
    "native_platform_unsupported",
    "native_publisher_signature_invalid",
    "native_publisher_pin_absent",
    "managed_policy_active",
    "managed_policy_absent",
    "managed_policy_cache_invalid",
    "managed_policy_cache_tampered",
    "managed_policy_inaccessible",
    "managed_policy_invalid",
    "managed_policy_source_tampered",
    "managed_policy_profile_removed_cached",
    "ownership_acl_verification_unavailable",
    "ownership_acl_valid",
    "ownership_acl_surface_absent",
    "ownership_acl_wrong_owner",
    "ownership_acl_standard_user_writable",
    "ownership_acl_path_escape",
    "ownership_acl_probe_failed",
    "ownership_acl_platform_unsupported",
    "supervisor_verification_unavailable",
    "supervisor_running",
    "supervisor_absent",
    "supervisor_stopped",
    "supervisor_disabled",
    "supervisor_registration_invalid",
    "supervisor_executable_mismatch",
    "supervisor_schedule_invalid",
    "supervisor_probe_failed",
    "supervisor_platform_unsupported",
    "device_key_verification_unavailable",
    "device_key_active",
    "device_key_absent",
    "device_key_revoked",
    "device_key_metadata_invalid",
    "device_key_public_mismatch",
    "device_key_acl_invalid",
    "device_key_unusable",
    "device_key_provider_unavailable",
    "device_key_rotation_incomplete",
    "device_key_revocation_incomplete",
    "device_key_probe_failed",
    "device_key_platform_unsupported",
    "harness_coverage_verification_unavailable",
    "harness_coverage_not_required",
    "harness_coverage_healthy",
    "harness_coverage_degraded",
    "harness_coverage_missing",
    "harness_coverage_registry_absent",
    "harness_coverage_probe_failed",
    "installation_identity_verification_unavailable",
    "lease_continuity_verification_unavailable",
    "installation_identity_active",
    "installation_identity_absent",
    "installation_identity_invalid",
    "installation_identity_acl_invalid",
    "installation_identity_key_mismatch",
    "installation_identity_probe_failed",
    "lease_continuity_active",
    "lease_continuity_uninitialized",
    "lease_continuity_absent",
    "lease_continuity_invalid",
    "lease_continuity_boot_probe_failed",
    "lease_continuity_monotonic_probe_failed",
    "lease_continuity_monotonic_regression",
    "lease_continuity_sequence_exhausted",
    "lease_continuity_probe_failed",
    "lease_continuity_platform_unsupported",
    "daemon_verification_unavailable",
    "daemon_running",
    "daemon_absent",
    "daemon_stopped",
    "daemon_disabled",
    "daemon_registration_invalid",
    "daemon_probe_failed",
    "command_shadowing_verification_unavailable",
    "command_shadowing_absent",
    "command_shadowing_trusted",
    "command_shadowing_detected",
    "command_shadowing_probe_failed",
    "update_verification_unavailable",
    "update_version_allowed",
    "integrity_reason_unrecognized",
    "release_manifest_probe_failed",
    "native_install_probe_failed",
    "managed_policy_probe_failed",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    generated_at: String,
    platform: String,
    architecture: String,
    fallback_version: String,
    manifest_hash: Option<String>,
    policy: Policy,
    native: Native,
    manifest: Manifest,
    acl: Acl,
    supervisor: Supervisor,
    device_key: DeviceKey,
    harness: Harness,
    continuity: Continuity,
    command_shadowing: Shadowing,
}

/// The managed policy state. `install_owner` and `content_hash` are absent
/// when no policy document loaded.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    status: String,
    reason_code: Option<String>,
    install_owner: Option<String>,
    content_hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Shadowing {
    state: String,
    reason_code: String,
}

// The probe results below arrive as `dataclasses.asdict` output, so the
// fields this module does not read are ignored.

#[derive(Deserialize)]
struct Native {
    status: String,
    reason_code: String,
    package_identity: String,
    version: Option<String>,
}

#[derive(Deserialize)]
struct Manifest {
    status: String,
    reason_code: String,
    version: Option<String>,
    build_id: Option<String>,
}

#[derive(Deserialize)]
struct Acl {
    status: String,
    reason_code: String,
}

#[derive(Deserialize)]
struct Supervisor {
    state: String,
    reason_code: String,
}

#[derive(Deserialize)]
struct DeviceKey {
    state: String,
    level: String,
    reason_code: String,
}

#[derive(Deserialize)]
struct Harness {
    state: String,
    reason_code: String,
    coverage: Value,
}

#[derive(Deserialize)]
struct Continuity {
    identity_reason_code: String,
    lease_reason_code: String,
    record: Option<ContinuityRecord>,
    observation: Option<Observation>,
}

#[derive(Deserialize)]
struct ContinuityRecord {
    machine_installation_id: String,
    installation_generation: String,
    last_issued_sequence: u64,
    last_lease_digest: Option<String>,
}

#[derive(Deserialize)]
struct Observation {
    boot_session_id: String,
    monotonic_uptime_ns: u64,
}

/// One snapshot component. Only the device key carries a protection level.
#[derive(Debug, PartialEq, Eq)]
struct Component {
    state: String,
    healthy: bool,
    reason_code: String,
    level: Option<String>,
}

impl Component {
    fn to_value(&self) -> Value {
        let mut value = json!({
            "state": self.state,
            "healthy": self.healthy,
            "reasonCode": self.reason_code,
        });
        if let Some(level) = &self.level {
            value["level"] = json!(level);
        }
        value
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "integrity-snapshot"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "integrity_snapshot_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("integrity_snapshot_request_too_large".to_owned());
    }
    let response = answer(&bytes)?;
    serde_json::to_vec(&response)
        .map_err(|_| "integrity_snapshot_response_encode_failed".to_owned())
}

fn answer(bytes: &[u8]) -> Result<Value, String> {
    let request: Request = serde_json::from_slice(bytes)
        .map_err(|_| "integrity_snapshot_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("integrity_snapshot_request_invalid".to_owned());
    }
    Ok(snapshot(&request))
}

/// A component whose state and reason code must be ones the snapshot schema
/// names; anything else reads as unknown or unrecognized.
fn component(state: &str, reason_code: &str) -> Component {
    let state = if STATES.contains(&state) {
        state
    } else {
        "unknown"
    };
    let reason_code = if REASON_CODES.contains(&reason_code) {
        reason_code
    } else {
        "integrity_reason_unrecognized"
    };
    Component {
        state: state.to_owned(),
        healthy: state == "healthy",
        reason_code: reason_code.to_owned(),
        level: None,
    }
}

fn daemon_component(supervisor_reason_code: &str) -> Component {
    let (state, reason_code) = match supervisor_reason_code {
        "supervisor_running" => ("healthy", "daemon_running"),
        "supervisor_absent" => ("absent", "daemon_absent"),
        "supervisor_stopped" => ("degraded", "daemon_stopped"),
        "supervisor_disabled" => ("tampered", "daemon_disabled"),
        "supervisor_registration_invalid"
        | "supervisor_executable_mismatch"
        | "supervisor_schedule_invalid" => ("tampered", "daemon_registration_invalid"),
        "supervisor_probe_failed" => ("unknown", "daemon_probe_failed"),
        _ => ("unsupported", "daemon_verification_unavailable"),
    };
    component(state, reason_code)
}

fn continuity_components(continuity: &Continuity) -> (Component, Component) {
    let identity_state = match continuity.identity_reason_code.as_str() {
        "installation_identity_active" => "healthy",
        "installation_identity_absent" => "absent",
        "installation_identity_invalid"
        | "installation_identity_acl_invalid"
        | "installation_identity_key_mismatch" => "tampered",
        _ => "unknown",
    };
    let lease_state = match continuity.lease_reason_code.as_str() {
        "lease_continuity_active" | "lease_continuity_uninitialized" => "healthy",
        "lease_continuity_absent" => "absent",
        "lease_continuity_invalid" | "lease_continuity_monotonic_regression" => "tampered",
        "lease_continuity_sequence_exhausted" => "degraded",
        "lease_continuity_platform_unsupported" => "unsupported",
        _ => "unknown",
    };
    (
        component(identity_state, &continuity.identity_reason_code),
        component(lease_state, &continuity.lease_reason_code),
    )
}

/// An unreadable policy counts as degraded, as does a removed profile still
/// served from the cache.
fn policy_component(policy: &Policy) -> Component {
    let removed_cached = policy.reason_code.as_deref() == Some(PROFILE_REMOVED_CACHED);
    let state = match policy.status.as_str() {
        "active" if !removed_cached => "healthy",
        "invalid" | "inaccessible" => "degraded",
        _ if removed_cached => "degraded",
        status => status,
    };
    let reason_code = match policy.reason_code.as_deref() {
        Some(reason_code) if !reason_code.is_empty() => reason_code,
        _ if policy.status == "active" => "managed_policy_active",
        _ => "managed_policy_absent",
    };
    component(state, reason_code)
}

/// Who owns updates. A policy that exists but cannot be trusted still marks
/// the machine as managed.
fn install_owner(policy: &Policy) -> &str {
    match policy.install_owner.as_deref() {
        Some(owner) => owner,
        None if matches!(
            policy.status.as_str(),
            "invalid" | "inaccessible" | "tampered"
        ) =>
        {
            "mdm"
        }
        None => "user",
    }
}

fn remediation_class(assurance_level: &str, healthy: bool, states: &[&str]) -> &'static str {
    if healthy {
        "none"
    } else if states.contains(&"tampered") {
        "administrator-action"
    } else if assurance_level != "user-managed" {
        "mdm-repair"
    } else {
        "user-reinstall"
    }
}

/// The public installed version, taken only from a source whose verification
/// passed.
fn product_version(request: &Request) -> &str {
    verified(&request.manifest.status, &request.manifest.version)
        .or_else(|| verified(&request.native.status, &request.native.version))
        .unwrap_or(&request.fallback_version)
}

fn verified<'a>(status: &str, value: &'a Option<String>) -> Option<&'a str> {
    value.as_deref().filter(|_| status == "healthy")
}

/// `nanoseconds / 1_000_000_000` as Python's true division gives it: the exact
/// decimal quotient, which a JSON reader rounds to the same nearest double.
fn uptime_seconds(nanoseconds: u64) -> Value {
    let text = format!(
        "{}.{:09}",
        nanoseconds / 1_000_000_000,
        nanoseconds % 1_000_000_000
    );
    serde_json::from_str::<Number>(&text).map_or(Value::Null, Value::Number)
}

fn components(request: &Request) -> [(&'static str, Component); 12] {
    let (installation_identity, lease_continuity) = continuity_components(&request.continuity);
    let manifest = component(&request.manifest.status, &request.manifest.reason_code);
    let update = if manifest.healthy {
        component("healthy", "update_version_allowed")
    } else {
        component(&request.manifest.status, &request.manifest.reason_code)
    };
    [
        ("manifest", manifest),
        (
            "nativePackage",
            component(&request.native.status, &request.native.reason_code),
        ),
        ("managedPolicy", policy_component(&request.policy)),
        (
            "ownershipAndAcl",
            component(&request.acl.status, &request.acl.reason_code),
        ),
        (
            "supervisor",
            Component {
                state: request.supervisor.state.clone(),
                healthy: request.supervisor.state == "running",
                reason_code: request.supervisor.reason_code.clone(),
                level: None,
            },
        ),
        (
            "deviceKey",
            Component {
                state: request.device_key.state.clone(),
                healthy: request.device_key.state == "healthy",
                reason_code: request.device_key.reason_code.clone(),
                level: Some(request.device_key.level.clone()),
            },
        ),
        (
            "harnessCoverage",
            component(&request.harness.state, &request.harness.reason_code),
        ),
        ("installationIdentity", installation_identity),
        ("leaseContinuity", lease_continuity),
        ("daemon", daemon_component(&request.supervisor.reason_code)),
        (
            "commandShadowing",
            component(
                &request.command_shadowing.state,
                &request.command_shadowing.reason_code,
            ),
        ),
        ("update", update),
    ]
}

fn snapshot(request: &Request) -> Value {
    let owner = install_owner(&request.policy);
    let assurance_level = if owner == "mdm" {
        "mdm-managed-unverified"
    } else {
        "user-managed"
    };
    let components = components(request);
    let healthy = components.iter().all(|(_, component)| component.healthy);
    let states: Vec<&str> = components
        .iter()
        .map(|(_, component)| component.state.as_str())
        .collect();
    let reason_codes: BTreeSet<&str> = components
        .iter()
        .filter(|(_, component)| !component.healthy)
        .map(|(_, component)| component.reason_code.as_str())
        .collect();
    let record = request.continuity.record.as_ref();
    let observation = request.continuity.observation.as_ref();
    let identifiers = json!({
        "workspaceId": null,
        "deviceId": null,
        "machineInstallationId": record.map(|record| record.machine_installation_id.as_str()),
        "installationGeneration": record.map(|record| record.installation_generation.as_str()),
    });
    let product = json!({
        "version": product_version(request),
        "buildId": verified(&request.manifest.status, &request.manifest.build_id),
        "sourceCommit": null,
        "packageIdentity": request.native.package_identity,
        "manifestHash": request.manifest_hash,
        "policyHash": request.policy.content_hash,
    });
    let continuity = json!({
        "monotonicUptimeSeconds": observation
            .map_or(Value::Null, |observation| uptime_seconds(observation.monotonic_uptime_ns)),
        "sequence": record.map(|record| record.last_issued_sequence),
        "previousLeaseDigest": record.and_then(|record| record.last_lease_digest.as_deref()),
        "bootSessionId": observation.map(|observation| observation.boot_session_id.as_str()),
    });
    let component_values: Map<String, Value> = components
        .iter()
        .map(|(name, component)| ((*name).to_owned(), component.to_value()))
        .collect();
    json!({
        "schemaVersion": SNAPSHOT_SCHEMA,
        "generatedAt": request.generated_at,
        "scope": "machine",
        "healthy": healthy,
        "assuranceLevel": assurance_level,
        "installOwner": owner,
        "platform": request.platform,
        "architecture": request.architecture,
        "identifiers": identifiers,
        "product": product,
        "components": component_values,
        "harnessCoverage": request.harness.coverage,
        "continuity": continuity,
        "reasonCodes": reason_codes,
        "remediationClass": remediation_class(assurance_level, healthy, &states),
    })
}

#[cfg(test)]
#[path = "mdm_integrity_snapshot_tests.rs"]
mod tests;
