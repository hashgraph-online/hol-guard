//! Python `ci_runner_config.load_config` document/reservation outcomes at b4efd817.

use gauntlet_contracts::canonical_sha256;
use gauntlet_evidence::{
    verify_runner_file_assets, verify_runner_inputs, verify_runner_inputs_from_paths,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../gauntlet-contracts/tests/fixtures")
        .canonicalize()
        .unwrap()
}

fn fixture(version: u8) -> (Vec<u8>, String, Vec<u8>, Vec<u8>, Value) {
    let root = root();
    let config = std::fs::read(root.join(format!("runner_config_v{version}.json"))).unwrap();
    let pins: Value =
        serde_json::from_slice(&std::fs::read(root.join("runner_config_pins.json")).unwrap())
            .unwrap();
    let expectations: Value = serde_json::from_slice(
        &std::fs::read(root.join("runner_input_expectations.json")).unwrap(),
    )
    .unwrap();
    let document_version = if version <= 5 { 1 } else { 6 };
    (
        config,
        pins[version.to_string()].as_str().unwrap().to_owned(),
        std::fs::read(root.join(format!("campaign_v{document_version}.json"))).unwrap(),
        std::fs::read(root.join(format!("policy_v{document_version}.json"))).unwrap(),
        expectations[version.to_string()].clone(),
    )
}

#[test]
fn all_seven_python_configurations_match_selection_and_reservations() {
    for version in 1..=7 {
        let (config, pin, campaign, policy, expected) = fixture(version);
        let result = verify_runner_inputs(&config, &pin, &campaign, &policy).unwrap();
        assert_eq!(result.version, version);
        assert_eq!(
            result.selection_reservations.to_json(),
            expected["selection_reservations"]
        );
        assert_eq!(
            result.shards,
            serde_json::from_value::<Vec<Vec<String>>>(expected["shards"].clone()).unwrap()
        );
        assert_eq!(result.attempt_layout, expected["attempt_layout"]);
        assert_eq!(
            canonical_sha256(result.campaign.to_string().as_bytes()).unwrap(),
            expected["campaign_digest"]
        );
        assert_eq!(
            canonical_sha256(result.policy.canonical_bytes()).unwrap(),
            expected["policy_digest"]
        );
    }
}

#[test]
fn changed_document_bytes_and_selection_are_rejected() {
    let (config, pin, campaign, policy, _) = fixture(7);
    let mut changed = campaign.clone();
    changed.push(b' ');
    assert!(verify_runner_inputs(&config, &pin, &changed, &policy).is_err());
    let mut changed = policy.clone();
    changed.push(b' ');
    assert!(verify_runner_inputs(&config, &pin, &campaign, &changed).is_err());

    let mut value: Value = serde_json::from_slice(&config).unwrap();
    value["selection"].as_array_mut().unwrap().pop();
    let changed = serde_json::to_vec(&value).unwrap();
    let changed_pin = canonical_sha256(&changed).unwrap();
    assert!(verify_runner_inputs(&changed, &changed_pin, &campaign, &policy).is_err());

    let mut value: Value = serde_json::from_slice(&config).unwrap();
    value["runtime"]["mcp_protocol_profiles"] = json!({"unscheduled-cell": {
        "schema": "gauntlet-mcp-protocol-profile.v1", "id": "structured-content"
    }});
    let changed = serde_json::to_vec(&value).unwrap();
    let changed_pin = canonical_sha256(&changed).unwrap();
    assert!(verify_runner_inputs(&changed, &changed_pin, &campaign, &policy).is_err());

    let (config, _, campaign, policy, _) = fixture(5);
    let mut value: Value = serde_json::from_slice(&config).unwrap();
    value["runtime"]["guard_package_version"] = json!("3.50.0+unreviewed");
    let changed = serde_json::to_vec(&value).unwrap();
    let changed_pin = canonical_sha256(&changed).unwrap();
    assert!(verify_runner_inputs(&changed, &changed_pin, &campaign, &policy).is_err());
}

#[test]
fn no_symlink_file_reader_matches_python_documents_and_file_pins() {
    let config_root = root();
    let asset_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for version in 1..=7 {
        let (_, pin, _, _, expected) = fixture(version);
        let assets = asset_root.join(if version <= 5 {
            "python_runner_assets_v1"
        } else {
            "python_runner_assets_v6"
        });
        let config_path = config_root.join(format!("runner_config_v{version}.json"));
        let verified = verify_runner_inputs_from_paths(&config_path, &pin, &assets).unwrap();
        assert_eq!(
            verified.selection_reservations.to_json(),
            expected["selection_reservations"]
        );
        if version == 1 || version >= 6 {
            let observed = verify_runner_file_assets(&verified, &assets).unwrap();
            assert_eq!(
                observed["node"],
                verified.config.value()["assets"]["node"]["sha256"]
            );
            assert_eq!(
                observed["wheel"],
                verified.config.value()["assets"]["wheel"]["sha256"]
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn symlinked_document_and_changed_file_asset_are_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().canonicalize().unwrap();
    let assets = directory.join("assets");
    std::fs::create_dir(&assets).unwrap();
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python_runner_assets_v1");
    for name in [
        "bun",
        "campaign.json",
        "compiler",
        "model_manifest",
        "native",
        "node",
        "policy",
        "policy.json",
        "provider_manifest",
        "wheel",
    ] {
        std::fs::copy(source.join(name), assets.join(name)).unwrap();
    }
    let (config, pin, _, _, _) = fixture(1);
    let config_path = directory.join("config.json");
    std::fs::write(&config_path, config).unwrap();
    let verified = verify_runner_inputs_from_paths(&config_path, &pin, &assets).unwrap();
    let bun = assets.join("bun");
    let original_mode = std::fs::metadata(&bun).unwrap().permissions().mode();
    std::fs::set_permissions(
        &bun,
        std::fs::Permissions::from_mode(original_mode & !0o111),
    )
    .unwrap();
    assert!(verify_runner_file_assets(&verified, &assets).is_err());
    std::fs::set_permissions(&bun, std::fs::Permissions::from_mode(original_mode)).unwrap();
    std::fs::write(assets.join("wheel"), b"changed wheel").unwrap();
    assert!(verify_runner_file_assets(&verified, &assets).is_err());

    std::fs::remove_file(assets.join("campaign.json")).unwrap();
    symlink(source.join("campaign.json"), assets.join("campaign.json")).unwrap();
    assert!(verify_runner_inputs_from_paths(&config_path, &pin, &assets).is_err());
}
