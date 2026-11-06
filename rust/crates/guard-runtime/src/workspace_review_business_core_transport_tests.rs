//! Opt-in source integration. This is not provider, worker or installed proof.
use super::*;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
#[ignore = "requires an explicitly selected compiled runtime and Python interpreter"]
fn producer_saved_request_is_selectable_through_real_resident_and_core_http() {
    let runtime = std::env::var("HOL_GUARD_BUSINESS_TRANSPORT_NATIVE")
        .expect("compiled candidate runtime must be selected explicitly");
    let python = std::env::var("HOL_GUARD_BUSINESS_TRANSPORT_PYTHON")
        .expect("test Python interpreter must be selected explicitly");
    let digest = guard_policy_snapshot::digest_bytes(&std::fs::read(&runtime).unwrap());
    let contract_output = Command::new(&runtime)
        .args(["rule-contract", "--json"])
        .output()
        .unwrap();
    assert!(contract_output.status.success());
    let native_contract: Value = serde_json::from_slice(&contract_output.stdout).unwrap();
    let fixture_contract = serde_json::to_value(guard_rule_contract::rule_contract()).unwrap();
    if native_contract["rule_digest"] != fixture_contract["rule_digest"] {
        for component in fixture_contract["components"].as_array().unwrap() {
            let native = native_contract["components"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["name"] == component["name"])
                .unwrap();
            if native["sha256"] != component["sha256"] {
                eprintln!("rule_component_mismatch: {}", component["name"]);
            }
        }
    }
    assert_eq!(
        native_contract["rule_digest"], fixture_contract["rule_digest"],
        "selected resident and producer fixture must share the exact rule contract"
    );
    let fixture = Fixture::for_core_transport("business-core-transport", &digest);
    let prepared = prepare(input(b"CORE_TRANSPORT_PRIVATE_BODY_CANARY", &[])).unwrap();
    persist_prepared_review(&fixture.store, "opaque-core-selector", &prepared, || true).unwrap();
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut child = Command::new(python)
        .current_dir(repository)
        .arg("scripts/ci/verify_native_business_review_core_transport.py")
        .arg("--guard-home")
        .arg(fixture.root.parent().unwrap())
        .arg("--request-id")
        .arg("opaque-core-selector")
        .arg("--runtime-sha256")
        .arg(&digest)
        .env("HOL_GUARD_NATIVE", "force")
        .env("HOL_GUARD_NATIVE_DIAGNOSTIC", "1")
        .env("HOL_GUARD_NATIVE_BINARY", runtime)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            &canonical_json_bytes(&json!({
                "operation":"policy_snapshot_push", "request":{
                    "schema":"guard-policy-snapshot-push.v1", "snapshot":fixture.snapshot
                }
            }))
            .unwrap(),
        )
        .unwrap();
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "real resident/Core transport probe failed"
    );
    assert!(!fixture
        .root
        .join("workspace-review-business-attempts")
        .exists());
    // Fixture Drop removes native state only. The Guard home contains test-owned
    // Core DB files and must also be removed after its daemon/resident stopped.
    let home = fixture.root.parent().unwrap().to_path_buf();
    drop(fixture);
    std::fs::remove_dir_all(home).unwrap();
}
