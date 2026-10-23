//! Linux Root diagnostic over an outside-pinned config, package and controller.
//! It never starts a control or grants candidate execution.

use crate::local_conformance_package::{
    verify_local_conformance_package_ineligible,
    verify_local_conformance_package_with_key_pins_ineligible, LocalConformancePackageShadow,
    EXECUTION_SOURCES,
};
use crate::local_conformance_runtime::expected_runtime;
use crate::public_files::PublicRootReader;
use crate::{
    inventory_tree, load_runner_config_from_paths, verify_controller_tree,
    verify_runner_file_assets, EvidenceError, Result, TreeKind,
};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

fn invalid(message: &'static str) -> EvidenceError {
    EvidenceError::Invalid(message)
}

fn observed_platform() -> Result<Value> {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    let kernel = kernel.trim_end_matches('\n');
    if kernel.is_empty() || kernel.len() > 128 || !kernel.is_ascii() {
        return Err(invalid("Linux kernel release unavailable"));
    }
    let release = PublicRootReader::open(Path::new("/"))?.read_file("usr/lib/os-release", 8192)?;
    let release = std::str::from_utf8(&release).map_err(|_| invalid("OS release is not UTF-8"))?;
    let mut fields = BTreeMap::new();
    for line in release.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(invalid("malformed OS release"))?;
        let value = value.trim_matches('"');
        if matches!(key, "ID" | "VERSION_ID")
            && (fields.insert(key, value).is_some() || value.is_empty() || value.len() > 128)
        {
            return Err(invalid("ambiguous OS release"));
        }
    }
    Ok(json!({
        "kernel_release":kernel,
        "machine":std::env::consts::ARCH,
        "os_id":fields.get("ID").ok_or(invalid("OS ID missing"))?,
        "os_version":fields.get("VERSION_ID").ok_or(invalid("OS version missing"))?,
    }))
}

fn observed_public_assets(config: &Value, asset_root: &Path) -> Result<Value> {
    let sdk = &config["assets"]["sdk"];
    let sdk_path = sdk["path"].as_str().ok_or(invalid("SDK path missing"))?;
    let sdk_inventory = inventory_tree(&asset_root.join(sdk_path), TreeKind::Sdk)?;
    if sdk_inventory.digest != sdk["sha256"] {
        return Err(invalid("SDK differs from config pin"));
    }
    let bun = &config["assets"]["bun"];
    let bun_path = bun["path"].as_str().ok_or(invalid("Bun path missing"))?;
    let bun_inventory = PublicRootReader::open(asset_root)?.file_inventory(bun_path, true)?;
    if bun_inventory.sha256 != bun["sha256"] {
        return Err(invalid("Bun differs from config pin"));
    }
    Ok(json!({
        "sdk":{"tree_digest":sdk_inventory.digest,"entries":sdk_inventory.entries,"bytes":sdk_inventory.bytes},
        "bun":{"sha256":bun_inventory.sha256,"size":bun_inventory.size,"mode":bun_inventory.mode,
            "uid":bun_inventory.uid,"gid":bun_inventory.gid},
    }))
}

/// Read the exact config-pinned package and 50 source files from a separately
/// pinned Root-owned controller tree. The control records are signed openings
/// only; this path intentionally omits independent SDK/Native/kernel verdicts.
pub fn observe_local_conformance_package_from_paths_ineligible(
    config_path: &Path,
    outside_config_sha256: &str,
    asset_root: &Path,
    controller_root: &Path,
    outside_controller_tree_sha256: &str,
) -> Result<LocalConformancePackageShadow> {
    observe_package_from_paths(
        config_path,
        outside_config_sha256,
        asset_root,
        controller_root,
        outside_controller_tree_sha256,
        None,
    )
}

/// Compare signed records with a complete, caller-supplied role-to-key map.
/// The caller must separately authenticate that map before invoking this
/// reader; the conformance package itself is not an acceptable source.
pub fn observe_local_conformance_package_with_key_pins_ineligible(
    config_path: &Path,
    outside_config_sha256: &str,
    asset_root: &Path,
    controller_root: &Path,
    outside_controller_tree_sha256: &str,
    outside_control_keys: &BTreeMap<String, String>,
) -> Result<LocalConformancePackageShadow> {
    observe_package_from_paths(
        config_path,
        outside_config_sha256,
        asset_root,
        controller_root,
        outside_controller_tree_sha256,
        Some(outside_control_keys),
    )
}

fn observe_package_from_paths(
    config_path: &Path,
    outside_config_sha256: &str,
    asset_root: &Path,
    controller_root: &Path,
    outside_controller_tree_sha256: &str,
    outside_control_keys: Option<&BTreeMap<String, String>>,
) -> Result<LocalConformancePackageShadow> {
    if geteuid().as_raw() != 0 {
        return Err(invalid("Linux Root required for conformance shadow"));
    }
    let controller = verify_controller_tree(controller_root, outside_controller_tree_sha256)?;
    let loaded = load_runner_config_from_paths(config_path, outside_config_sha256, asset_root)?;
    if loaded.verified.version != 7 {
        return Err(invalid("v7 local conformance config required"));
    }
    let config = loaded.verified.config.value();
    let expected = expected_runtime(config)?;
    let file_assets = verify_runner_file_assets(&loaded.verified, asset_root)?;
    let conformance = &config["assets"]["conformance"];
    let package_sha256 = conformance["sha256"]
        .as_str()
        .ok_or(invalid("conformance pin missing"))?;
    if file_assets.get("conformance").map(String::as_str) != Some(package_sha256) {
        return Err(invalid("conformance file not in verified asset inventory"));
    }
    let package_path = conformance["path"]
        .as_str()
        .ok_or(invalid("conformance path missing"))?;
    let package = PublicRootReader::open(asset_root)?.read_file(package_path, 8 * 1024 * 1024)?;
    let public_assets = observed_public_assets(config, asset_root)?;
    let source_reader = PublicRootReader::open(controller_root)?;
    let mut source_hashes = BTreeMap::new();
    for name in EXECUTION_SOURCES {
        let path = format!("ci/gauntlet/benchmark/{name}");
        source_hashes.insert(name.to_owned(), source_reader.file_digest(&path, false)?);
    }
    let platform = observed_platform()?;
    let shadow = match outside_control_keys {
        Some(keys) => verify_local_conformance_package_with_key_pins_ineligible(
            &package,
            package_sha256,
            &expected,
            &platform,
            &source_hashes,
            Some(&public_assets),
            keys,
        )?,
        None => verify_local_conformance_package_ineligible(
            &package,
            package_sha256,
            &expected,
            &platform,
            &source_hashes,
            Some(&public_assets),
        )?,
    };
    let after = verify_controller_tree(controller_root, outside_controller_tree_sha256)?;
    if after != controller
        || verify_runner_file_assets(&loaded.verified, asset_root)? != file_assets
        || observed_public_assets(config, asset_root)? != public_assets
    {
        return Err(invalid("conformance inputs changed while reading"));
    }
    Ok(shadow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_tuple_comes_from_config_not_package() {
        let config = json!({
            "runtime":{"guard_source_sha":"source", "guard_bwrap_sha256":"bwrap", "guard_executor_image_id":"executor", "guard_package_version":"3.49.0",
                "private_cell":{"initializer_sha256":"init", "native_sha256":"native", "runtime_tree_digest":"tree", "idmap_runtime":"idmap", "cpu_profile":"cpu"}},
            "assets":{"guard_prefix":{"sha256":"prefix"}, "private_cell":{"sha256":"manifest"}}
        });
        let expected = expected_runtime(&config).unwrap();
        assert_eq!(
            expected["private_cell"]["artifact_manifest_sha256"],
            "manifest"
        );
        assert_eq!(expected["prefix_digest"], "prefix");
        assert_eq!(expected["package_version"], "3.49.0");
    }
}
