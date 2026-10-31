use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use super::vocabulary::ALIASES;
use super::{run_command, snapshot_is_bound, timestamp_is_valid, Claims};

fn claims() -> Claims {
    Claims {
        workspace_id: "workspace-a".to_owned(),
        device_id: "device-a".to_owned(),
        machine_installation_id: "1".repeat(32),
        installation_generation: "2".repeat(32),
        sequence: 1,
        snapshot_schema_version: "local-integrity-snapshot.v1".to_owned(),
        previous_lease_digest: None,
    }
}

fn snapshot() -> Value {
    let component =
        json!({"state": "healthy", "healthy": true, "reasonCode": "release_manifest_valid"});
    let mut components = serde_json::Map::new();
    for name in [
        "manifest",
        "nativePackage",
        "managedPolicy",
        "ownershipAndAcl",
        "harnessCoverage",
        "installationIdentity",
        "leaseContinuity",
        "daemon",
        "commandShadowing",
        "update",
    ] {
        components.insert(name.to_owned(), component.clone());
    }
    components.insert(
        "supervisor".to_owned(),
        json!({"state": "running", "healthy": true, "reasonCode": "supervisor_running"}),
    );
    components.insert(
        "deviceKey".to_owned(),
        json!({"state": "healthy", "healthy": true, "reasonCode": "release_manifest_valid", "level": "os-protected"}),
    );
    json!({
        "schemaVersion": "local-integrity-snapshot.v1",
        "generatedAt": "2026-07-18T14:00:00.123456Z",
        "scope": "machine",
        "healthy": true,
        "assuranceLevel": "mdm-managed",
        "installOwner": "mdm",
        "platform": "Darwin",
        "architecture": "arm64",
        "identifiers": {
            "workspaceId": "workspace-a",
            "deviceId": "device-a",
            "machineInstallationId": "1".repeat(32),
            "installationGeneration": "2".repeat(32),
        },
        "product": {
            "version": "3.0.0a1",
            "buildId": null,
            "sourceCommit": null,
            "packageIdentity": "test",
            "manifestHash": "a".repeat(64),
            "policyHash": null,
        },
        "components": components,
        "harnessCoverage": {"required": 2, "protected": 1, "degraded": 0, "missing": null},
        "continuity": {
            "monotonicUptimeSeconds": 10.5,
            "sequence": 0,
            "previousLeaseDigest": null,
            "bootSessionId": "boot-a",
        },
        "reasonCodes": ["managed_policy_active", "release_manifest_valid"],
        "remediationClass": "none",
    })
}

fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    guard_contracts::write_canonical_json(value, &mut bytes).expect("canonical");
    bytes
}

fn bound(value: &Value) -> bool {
    snapshot_is_bound(&canonical(value), &claims())
}

fn mutated(pointer: &str, replacement: Value) -> Value {
    let mut value = snapshot();
    *value.pointer_mut(pointer).expect("pointer") = replacement;
    value
}

#[test]
fn a_canonical_bound_snapshot_is_valid() {
    assert!(bound(&snapshot()));
}

#[test]
fn bytes_other_than_the_canonical_spelling_are_refused() {
    let pretty = serde_json::to_vec_pretty(&snapshot()).expect("pretty");
    assert!(!snapshot_is_bound(&pretty, &claims()));
    assert!(!snapshot_is_bound(b"", &claims()));
    assert!(!snapshot_is_bound(b"[]", &claims()));
    let oversized = vec![b' '; 256 * 1024 + 1];
    assert!(!snapshot_is_bound(&oversized, &claims()));
}

#[test]
fn every_container_holds_exactly_its_keys() {
    for container in [
        "",
        "/identifiers",
        "/product",
        "/components",
        "/harnessCoverage",
        "/continuity",
        "/components/manifest",
    ] {
        let mut extra = snapshot();
        let target = extra.pointer_mut(container).expect("container");
        target
            .as_object_mut()
            .expect("object")
            .insert("unexpected".to_owned(), json!(true));
        assert!(!bound(&extra), "extra key in {container:?}");
    }
    let mut missing = snapshot();
    missing.as_object_mut().expect("object").remove("platform");
    assert!(!bound(&missing));
    let mut without_level = snapshot();
    without_level["components"]["deviceKey"]
        .as_object_mut()
        .expect("object")
        .remove("level");
    assert!(!bound(&without_level));
}

#[test]
fn component_vocabularies_are_closed() {
    assert!(!bound(&mutated(
        "/components/manifest/state",
        json!("running")
    )));
    assert!(!bound(&mutated(
        "/components/supervisor/state",
        json!("tampered")
    )));
    assert!(!bound(&mutated("/components/manifest/state", json!({}))));
    assert!(!bound(&mutated("/components/manifest/healthy", json!(1))));
    assert!(!bound(&mutated(
        "/components/manifest/reasonCode",
        json!("made_up")
    )));
    assert!(!bound(&mutated(
        "/components/deviceKey/level",
        json!("titanium")
    )));
    assert!(bound(&mutated(
        "/components/deviceKey/level",
        json!("hardware-backed")
    )));
}

#[test]
fn top_level_fields_are_checked() {
    assert!(!bound(&mutated(
        "/schemaVersion",
        json!("local-integrity-snapshot.v2")
    )));
    assert!(!bound(&mutated("/scope", json!("user"))));
    assert!(!bound(&mutated("/healthy", json!(null))));
    assert!(!bound(&mutated("/assuranceLevel", json!("trusted"))));
    assert!(!bound(&mutated("/installOwner", json!("root"))));
    assert!(!bound(&mutated("/remediationClass", json!(null))));
    assert!(!bound(&mutated("/platform", json!(""))));
    assert!(!bound(&mutated("/architecture", json!("x".repeat(65)))));
    assert!(bound(&mutated("/architecture", json!("x".repeat(64)))));
}

#[test]
fn reason_codes_are_known_sorted_unique_and_bounded() {
    assert!(bound(&mutated("/reasonCodes", json!([]))));
    assert!(!bound(&mutated(
        "/reasonCodes",
        json!(["release_manifest_valid", "managed_policy_active"])
    )));
    assert!(!bound(&mutated(
        "/reasonCodes",
        json!(["managed_policy_active", "managed_policy_active"])
    )));
    assert!(!bound(&mutated("/reasonCodes", json!(["made_up"]))));
    assert!(!bound(&mutated("/reasonCodes", json!([{}]))));
    let mut codes: Vec<&str> = super::vocabulary::INTEGRITY_REASON_CODES.to_vec();
    codes.sort_unstable();
    assert!(bound(&mutated("/reasonCodes", json!(codes[..64]))));
    assert!(!bound(&mutated("/reasonCodes", json!(codes[..65]))));
}

#[test]
fn product_strings_and_digests_are_bounded() {
    assert!(!bound(&mutated("/product/version", json!("x".repeat(129)))));
    assert!(!bound(&mutated("/product/version", json!(null))));
    assert!(bound(&mutated("/product/buildId", json!("b".repeat(256)))));
    assert!(!bound(&mutated(
        "/product/sourceCommit",
        json!("c".repeat(257))
    )));
    assert!(!bound(&mutated("/product/packageIdentity", json!(null))));
    assert!(!bound(&mutated(
        "/product/manifestHash",
        json!("A".repeat(64))
    )));
    assert!(!bound(&mutated(
        "/product/policyHash",
        json!("a".repeat(63))
    )));
    // Bytes, not characters, bound a string.
    assert!(!bound(&mutated("/platform", json!("é".repeat(33)))));
}

#[test]
fn coverage_counts_are_unsigned_integers() {
    assert!(!bound(&mutated("/harnessCoverage/required", json!(true))));
    assert!(!bound(&mutated("/harnessCoverage/required", json!(-1))));
    assert!(!bound(&mutated("/harnessCoverage/required", json!(1.0))));
    assert!(bound(&mutated(
        "/harnessCoverage/required",
        json!(u64::MAX)
    )));
    let over: Value = serde_json::from_str("18446744073709551616").expect("big");
    assert!(!bound(&mutated("/harnessCoverage/required", over)));
}

#[test]
fn uptime_is_null_or_a_non_negative_number() {
    assert!(bound(&mutated(
        "/continuity/monotonicUptimeSeconds",
        json!(null)
    )));
    assert!(bound(&mutated(
        "/continuity/monotonicUptimeSeconds",
        json!(0)
    )));
    assert!(bound(&mutated(
        "/continuity/monotonicUptimeSeconds",
        json!(-0.0)
    )));
    let huge: Value = serde_json::from_str("123456789012345678901234567890").expect("big");
    assert!(bound(&mutated("/continuity/monotonicUptimeSeconds", huge)));
    let unreadable: Value = serde_json::from_str(&"9".repeat(4301)).expect("big");
    assert!(!bound(&mutated(
        "/continuity/monotonicUptimeSeconds",
        unreadable
    )));
    assert!(!bound(&mutated(
        "/continuity/monotonicUptimeSeconds",
        json!(-1)
    )));
    assert!(!bound(&mutated(
        "/continuity/monotonicUptimeSeconds",
        json!(-0.5)
    )));
    assert!(!bound(&mutated(
        "/continuity/monotonicUptimeSeconds",
        json!("10")
    )));
    assert!(!bound(&mutated("/continuity/bootSessionId", json!(""))));
}

#[test]
fn the_snapshot_names_the_lease_before_this_one() {
    assert!(!bound(&mutated("/identifiers/deviceId", json!("device-b"))));
    assert!(!bound(&mutated("/continuity/sequence", json!(1))));
    assert!(!bound(&mutated("/continuity/sequence", json!(null))));
    let digest = "d".repeat(64);
    let chained = mutated("/continuity/previousLeaseDigest", json!(digest));
    assert!(!bound(&chained));
    let mut next = claims();
    next.previous_lease_digest = Some(digest);
    let mut later = chained;
    later["continuity"]["sequence"] = json!(4);
    next.sequence = 5;
    assert!(snapshot_is_bound(&canonical(&later), &next));
    next.sequence = 0;
    assert!(!snapshot_is_bound(&canonical(&later), &next));
}

#[test]
fn timestamps_read_as_python_reads_them() {
    for valid in [
        "2026-07-18T14:00:00Z",
        "2026-07-18T14:00:00.1Z",
        "2024-02-29T23:59:59.123456789Z",
        "0001-01-01T00:00:00Z",
    ] {
        assert!(timestamp_is_valid(valid), "{valid}");
    }
    for invalid in [
        "2026-07-18T14:00:00+00:00",
        "2026-07-18 14:00:00Z",
        "2023-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "0000-01-01T00:00:00Z",
        "2026-07-18T24:00:00Z",
        "2026-07-18T14:60:00Z",
        "2026-07-18T14:00:60Z",
        "2026-07-18T14:00:00.Z",
        "2026-07-18T14:00:00,5Z",
        "2026-07-0\u{661}T14:00:00Z",
        "2026-07-18T14:00:00Zx",
    ] {
        assert!(!timestamp_is_valid(invalid), "{invalid}");
    }
    // At most 64 bytes, however long the fraction.
    let longest = format!("2026-07-18T14:00:00.{}Z", "1".repeat(43));
    assert_eq!(longest.len(), 64);
    assert!(timestamp_is_valid(&longest));
    assert!(!timestamp_is_valid(&format!(
        "2026-07-18T14:00:00.{}Z",
        "1".repeat(44)
    )));
}

#[test]
fn the_command_answers_a_framed_request() {
    let request = |snapshot: &[u8], schema: &str| {
        json!({
            "schema": schema,
            "snapshot": STANDARD.encode(snapshot),
            "claims": {
                "workspace_id": "workspace-a",
                "device_id": "device-a",
                "machine_installation_id": "1".repeat(32),
                "installation_generation": "2".repeat(32),
                "sequence": 1,
                "snapshot_schema_version": "local-integrity-snapshot.v1",
                "previous_lease_digest": null,
            },
        })
        .to_string()
    };
    let answer = |text: String| -> Value {
        serde_json::from_slice(&run_command(text.as_bytes()).expect("answer")).expect("json")
    };
    let valid = canonical(&snapshot());
    assert_eq!(
        answer(request(&valid, "health-snapshot-binding.v1")),
        json!({"ok": true, "valid": true})
    );
    assert_eq!(
        answer(request(b"{}", "health-snapshot-binding.v1")),
        json!({"ok": true, "valid": false})
    );
    assert!(run_command(request(&valid, "health-snapshot-binding.v2").as_bytes()).is_err());
    let bad_base64 = request(&valid, "health-snapshot-binding.v1")
        .replace("\"snapshot\":\"", "\"snapshot\":\"!");
    assert!(run_command(bad_base64.as_bytes()).is_err());
    assert!(run_command(&b"{}"[..]).is_err());
}

#[test]
fn vocabularies_match_the_python_contract() {
    let contracts = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src/codex_plugin_scanner/guard/mdm/contracts.py");
    let source = std::fs::read_to_string(contracts).expect("contracts.py");
    for (alias, expected) in ALIASES {
        let marker = format!("\n{alias} = Literal[");
        let start = source
            .find(&marker)
            .unwrap_or_else(|| panic!("{alias} missing"))
            + marker.len();
        let body = &source[start..start + source[start..].find(']').expect("closing bracket")];
        let values: Vec<&str> = body.split('"').skip(1).step_by(2).collect();
        assert_eq!(
            values,
            expected.to_vec(),
            "{alias} drifted from contracts.py"
        );
    }
}
