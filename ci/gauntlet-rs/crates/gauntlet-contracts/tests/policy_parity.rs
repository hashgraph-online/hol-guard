//! Python `ci_gate.validate_policy` and `_policy_bindings` fixtures at b4efd817.

use gauntlet_contracts::{bind_gate_policy, GatePolicyError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

fn fixture() -> (Value, Vec<Value>, Value) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config: Value =
        serde_json::from_slice(&std::fs::read(root.join("runner_config_v1.json")).unwrap())
            .unwrap();
    let campaign_raw = std::fs::read(root.join("campaign_v1.json")).unwrap();
    let policy_raw = std::fs::read(root.join("policy_v1.json")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&campaign_raw)),
        config["campaign"]["sha256"]
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&policy_raw)),
        config["policy"]["sha256"]
    );
    let campaign: Value = serde_json::from_slice(&campaign_raw).unwrap();
    let selection: Vec<Value> = config["selection"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| {
            campaign["inventory"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == *id)
                .unwrap()
                .clone()
        })
        .collect();
    (
        config,
        selection,
        serde_json::from_slice(&policy_raw).unwrap(),
    )
}

#[test]
fn python_frozen_policy_covers_exact_selected_cells() {
    let (_, selected, policy) = fixture();
    let raw = serde_json::to_vec(&policy).unwrap();
    assert!(bind_gate_policy(&raw, &selected).is_ok());
}

#[test]
fn measurement_exception_and_native_surface_cannot_be_reassigned() {
    let (_, selected, policy) = fixture();
    let mut changed = policy.clone();
    changed["cells"][0]["outcome"] = json!("attacked-baseline-measurement");
    assert!(matches!(
        bind_gate_policy(&serde_json::to_vec(&changed).unwrap(), &selected),
        Err(GatePolicyError::UnsafeOutcome)
    ));

    let mut changed = policy.clone();
    changed["cells"][0]["outcome"] = json!("authorized-approval");
    assert!(matches!(
        bind_gate_policy(&serde_json::to_vec(&changed).unwrap(), &selected),
        Err(GatePolicyError::UnsafeOutcome)
    ));

    let unprotected = selected
        .iter()
        .find(|row| row["protected"] == false)
        .unwrap();
    let mut changed = policy.clone();
    let rule = changed["cells"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["episode_id"] == unprotected["id"])
        .unwrap();
    rule["required_surfaces"] = json!(["native-mcp"]);
    assert!(matches!(
        bind_gate_policy(&serde_json::to_vec(&changed).unwrap(), &selected),
        Err(GatePolicyError::UnsupportedSurface)
    ));
}

#[test]
fn duplicate_missing_or_extra_policy_episode_is_refused() {
    let (_, selected, policy) = fixture();
    let mut changed = policy.clone();
    let duplicate = changed["cells"][0].clone();
    changed["cells"].as_array_mut().unwrap().push(duplicate);
    assert!(matches!(
        bind_gate_policy(&serde_json::to_vec(&changed).unwrap(), &selected),
        Err(GatePolicyError::DuplicateEpisode)
    ));

    let mut changed = policy.clone();
    changed["cells"].as_array_mut().unwrap().pop();
    assert!(matches!(
        bind_gate_policy(&serde_json::to_vec(&changed).unwrap(), &selected),
        Err(GatePolicyError::InexactCoverage)
    ));

    let mut changed = policy;
    changed["cells"][0]["episode_id"] = json!("unscheduled-episode");
    assert!(matches!(
        bind_gate_policy(&serde_json::to_vec(&changed).unwrap(), &selected),
        Err(GatePolicyError::InexactCoverage)
    ));
}
