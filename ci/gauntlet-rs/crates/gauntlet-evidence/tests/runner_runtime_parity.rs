use gauntlet_evidence::{
    load_runner_config_from_paths, runner_runtime_declaration, verify_runner_inputs,
    verify_runner_inputs_from_paths, verify_runner_installed_version_metadata,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn contract_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../gauntlet-contracts/tests/fixtures")
        .canonicalize()
        .unwrap()
}

fn asset_fixtures(version: u8) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(if version <= 5 {
            "python_runner_assets_v1"
        } else {
            "python_runner_assets_v6"
        })
        .canonicalize()
        .unwrap()
}

fn normalize_paths(value: &mut Value, root: &str) {
    match value {
        Value::String(text) => *text = text.replace(root, "{ASSET_ROOT}"),
        Value::Array(rows) => {
            for row in rows {
                normalize_paths(row, root);
            }
        }
        Value::Object(rows) => {
            for row in rows.values_mut() {
                normalize_paths(row, root);
            }
        }
        _ => {}
    }
}

#[test]
fn seven_python_load_config_runtime_and_path_vectors_match() {
    let fixtures = contract_fixtures();
    let pins: Value =
        serde_json::from_slice(&std::fs::read(fixtures.join("runner_config_pins.json")).unwrap())
            .unwrap();
    let frozen: Value = serde_json::from_str(include_str!(
        "fixtures/python_runner_runtime_expectations.json"
    ))
    .unwrap();
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    assert_eq!(frozen["source_commit"], baseline["source_commit"]);
    let source = baseline["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/benchmark/ci_runner_config.py")
        .unwrap();
    assert_eq!(frozen["ci_runner_config_sha256"], source["sha256"]);
    for version in 1..=7 {
        let root = asset_fixtures(version);
        let config = fixtures.join(format!("runner_config_v{version}.json"));
        let verified = verify_runner_inputs_from_paths(
            &config,
            pins[version.to_string()].as_str().unwrap(),
            &root,
        )
        .unwrap();
        let mut actual = runner_runtime_declaration(&verified, &root).unwrap();
        let prefix = root.to_str().unwrap();
        normalize_paths(&mut actual.runtime, prefix);
        normalize_paths(&mut actual.paths, prefix);
        assert_eq!(
            actual.runtime,
            frozen["versions"][version.to_string()]["runtime"]
        );
        assert_eq!(
            actual.paths,
            frozen["versions"][version.to_string()]["paths"]
        );
    }
}

#[test]
fn installed_metadata_is_bound_to_outside_version_source_and_native_pins() {
    let fixtures = contract_fixtures();
    let pins: Value =
        serde_json::from_slice(&std::fs::read(fixtures.join("runner_config_pins.json")).unwrap())
            .unwrap();
    let config = std::fs::read(fixtures.join("runner_config_v7.json")).unwrap();
    let campaign = std::fs::read(fixtures.join("campaign_v6.json")).unwrap();
    let policy = std::fs::read(fixtures.join("policy_v6.json")).unwrap();
    let verified =
        verify_runner_inputs(&config, pins["7"].as_str().unwrap(), &campaign, &policy).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let manifest = root.join(
        "guard_prefix/lib/python3.12/site-packages/codex_plugin_scanner/_native/runtime-manifest.json",
    );
    std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    let config: Value = serde_json::from_slice(&config).unwrap();
    let correct = json!({
        "package_version": config["runtime"]["guard_package_version"],
        "source_sha": config["runtime"]["guard_source_sha"],
        "runtime_sha256": config["assets"]["native"]["sha256"]
    });
    std::fs::write(&manifest, serde_json::to_vec(&correct).unwrap()).unwrap();
    assert_eq!(
        verify_runner_installed_version_metadata(&verified, &root).unwrap(),
        Some("3.46.0".to_owned())
    );
    let wrong = json!({"package_version":"3.46.0","source_sha":config["runtime"]["guard_source_sha"],
        "runtime_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"});
    std::fs::write(&manifest, serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert!(verify_runner_installed_version_metadata(&verified, &root).is_err());
}

#[test]
fn integrated_loader_requires_version_metadata_only_for_v5_and_later() {
    let fixtures = contract_fixtures();
    let pins: Value =
        serde_json::from_slice(&std::fs::read(fixtures.join("runner_config_pins.json")).unwrap())
            .unwrap();
    for version in 1..=7 {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let source = asset_fixtures(version);
        for document in ["campaign.json", "policy.json"] {
            std::fs::copy(source.join(document), root.join(document)).unwrap();
        }
        let config_path = fixtures.join(format!("runner_config_v{version}.json"));
        let pin = pins[version.to_string()].as_str().unwrap();
        if version >= 5 {
            assert!(load_runner_config_from_paths(&config_path, pin, &root).is_err());
            let config: Value =
                serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
            let manifest = root.join(
                "guard_prefix/lib/python3.12/site-packages/codex_plugin_scanner/_native/runtime-manifest.json",
            );
            std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
            std::fs::write(
                &manifest,
                serde_json::to_vec(&json!({
                    "package_version": config["runtime"]["guard_package_version"],
                    "source_sha": config["runtime"]["guard_source_sha"],
                    "runtime_sha256": config["assets"]["native"]["sha256"]
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let loaded = load_runner_config_from_paths(&config_path, pin, &root).unwrap();
        assert_eq!(loaded.verified.version, version);
        assert_eq!(loaded.installed_package_version.is_some(), version >= 5);
        assert_eq!(loaded.declaration.runtime["product_isolated"], true);
    }
}

#[cfg(unix)]
#[test]
fn private_cell_path_symlink_is_rejected_during_runtime_declaration() {
    use std::os::unix::fs::symlink;

    let fixtures = contract_fixtures();
    let pins: Value =
        serde_json::from_slice(&std::fs::read(fixtures.join("runner_config_pins.json")).unwrap())
            .unwrap();
    let config = std::fs::read(fixtures.join("runner_config_v2.json")).unwrap();
    let campaign = std::fs::read(fixtures.join("campaign_v1.json")).unwrap();
    let policy = std::fs::read(fixtures.join("policy_v1.json")).unwrap();
    let verified =
        verify_runner_inputs(&config, pins["2"].as_str().unwrap(), &campaign, &policy).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("actual-cell")).unwrap();
    symlink(root.join("actual-cell"), root.join("cell")).unwrap();
    assert!(runner_runtime_declaration(&verified, &root).is_err());
}
