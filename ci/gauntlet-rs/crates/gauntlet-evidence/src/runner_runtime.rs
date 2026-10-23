//! Python-parity runtime path declarations after pinned config/document checks.
//! These paths are inert data until every referenced asset passes custody.

use crate::package_version::verify_installed_version_metadata;
use crate::public_files::PublicRootReader;
use crate::runner_inputs::{verify_runner_inputs_from_paths, VerifiedRunnerInputs};
use crate::{EvidenceError, Result};
use serde_json::{json, Map, Value};
use std::io::ErrorKind;
use std::path::Path;

const FILE_ROLES: [&str; 8] = [
    "bun",
    "compiler",
    "model_manifest",
    "native",
    "node",
    "policy",
    "provider_manifest",
    "wheel",
];

#[derive(Debug, Clone)]
pub struct RunnerRuntimeDeclaration {
    pub runtime: Value,
    pub paths: Value,
}

#[derive(Debug)]
pub struct LoadedRunnerConfig {
    pub verified: VerifiedRunnerInputs,
    pub declaration: RunnerRuntimeDeclaration,
    pub installed_package_version: Option<String>,
}

/// Complete inert v1-v7 loader. The installed metadata comparison for v5-v7
/// does not replace the separate full asset/prefix inventory requirement.
pub fn load_runner_config_from_paths(
    config_path: &Path,
    expected_config_digest: &str,
    asset_root: &Path,
) -> Result<LoadedRunnerConfig> {
    let verified =
        verify_runner_inputs_from_paths(config_path, expected_config_digest, asset_root)?;
    let declaration = runner_runtime_declaration(&verified, asset_root)?;
    let installed_package_version =
        verify_runner_installed_version_metadata(&verified, asset_root)?;
    Ok(LoadedRunnerConfig {
        verified,
        declaration,
        installed_package_version,
    })
}

fn path_string(root: &Path, relative: &str) -> Result<String> {
    root.join(relative)
        .to_str()
        .map(str::to_owned)
        .ok_or(EvidenceError::Invalid("non-UTF8 runner asset path"))
}

fn reject_existing_symlinks(root: &Path, relative: &str) -> Result<()> {
    let mut path = root.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(EvidenceError::Invalid(
                    "private-cell artifact path is a symlink",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => break,
            Err(error) => return Err(EvidenceError::Io(error.to_string())),
        }
    }
    Ok(())
}

/// Reproduce Python `load_config`'s returned runtime and path declarations.
/// The caller must independently hash files, trees, private-cell artifacts,
/// installed prefix and conformance before using these paths for execution.
pub fn runner_runtime_declaration(
    inputs: &VerifiedRunnerInputs,
    asset_root: &Path,
) -> Result<RunnerRuntimeDeclaration> {
    PublicRootReader::open(asset_root)?;
    let config = inputs.config.value();
    let assets = config["assets"]
        .as_object()
        .ok_or(EvidenceError::Invalid("asset declarations missing"))?;
    let mut paths = Map::new();
    for (name, row) in assets {
        let relative = row["path"]
            .as_str()
            .ok_or(EvidenceError::Invalid("asset path missing"))?;
        paths.insert(name.clone(), json!(path_string(asset_root, relative)?));
    }
    let get = |role: &str| -> Result<&str> {
        paths
            .get(role)
            .and_then(Value::as_str)
            .ok_or(EvidenceError::Invalid("required runtime asset missing"))
    };
    let options = &config["runtime"];
    let mut artifacts: Vec<String> = FILE_ROLES
        .iter()
        .map(|role| get(role).map(str::to_owned))
        .collect::<Result<_>>()?;
    let mut runtime = json!({
        "bun": get("bun")?,
        "sdk_root": format!("{}/@oh-my-pi/pi-coding-agent", get("sdk")?),
        "guard_python": format!("{}/bin/python", get("guard_prefix")?),
        "guard_source_sha": options["guard_source_sha"],
        "guard_prefix_digest": assets["guard_prefix"]["sha256"],
        "guard_bwrap_sha256": options["guard_bwrap_sha256"],
        "guard_executor_image_id": options["guard_executor_image_id"],
        "base_url": options["base_url"],
        "model_id": options["model_id"],
        "protected_adapter": "hol-guard",
        "isolated": true,
        "product_isolated": true,
    });
    if let Some(version) = options.get("guard_package_version") {
        runtime["guard_package_version"] = version.clone();
    }
    if let Some(surface) = options.get("mcp_agent_surfaces") {
        runtime["mcp_agent_surfaces"] = surface.clone();
    }
    if let Some(profiles) = options.get("mcp_protocol_profiles") {
        runtime["mcp_protocol_profiles"] = profiles.clone();
    }
    if let Some(path) = paths.get("zod_cache") {
        runtime["zod_cache"] = path.clone();
    }
    if inputs.version >= 2 {
        let private_path = assets["private_cell"]["path"]
            .as_str()
            .ok_or(EvidenceError::Invalid("private-cell artifact path missing"))?;
        reject_existing_symlinks(asset_root, private_path)?;
        let private = options["private_cell"]
            .as_object()
            .ok_or(EvidenceError::Invalid("private-cell declaration missing"))?;
        let mut cell = private.clone();
        cell.insert("schema".into(), json!("developer-private-cell-config.v1"));
        cell.insert("artifacts".into(), json!(get("private_cell")?));
        cell.insert(
            "artifact_manifest_sha256".into(),
            assets["private_cell"]["sha256"].clone(),
        );
        runtime["guard_private_cell"] = Value::Object(cell);
    }
    if inputs.version >= 3 {
        runtime["guard_conformance"] = json!({
            "path": get("conformance")?,
            "sha256": assets["conformance"]["sha256"]
        });
        artifacts.push(get("conformance")?.to_owned());
    }
    runtime["artifacts"] = json!(artifacts);
    Ok(RunnerRuntimeDeclaration {
        runtime,
        paths: Value::Object(paths),
    })
}

/// Read only installed version metadata using outside source/native/version
/// pins. This is not a substitute for complete Root-owned prefix inventory.
pub fn verify_runner_installed_version_metadata(
    inputs: &VerifiedRunnerInputs,
    asset_root: &Path,
) -> Result<Option<String>> {
    if inputs.version < 5 {
        return Ok(None);
    }
    let declared = runner_runtime_declaration(inputs, asset_root)?;
    let prefix = declared.paths["guard_prefix"]
        .as_str()
        .ok_or(EvidenceError::Invalid("installed prefix path missing"))?;
    let version = inputs.config.value()["runtime"]["guard_package_version"]
        .as_str()
        .ok_or(EvidenceError::Invalid("installed package version missing"))?;
    let source = inputs.config.value()["runtime"]["guard_source_sha"]
        .as_str()
        .ok_or(EvidenceError::Invalid("installed source SHA missing"))?;
    let native = inputs.config.value()["assets"]["native"]["sha256"]
        .as_str()
        .ok_or(EvidenceError::Invalid("installed native digest missing"))?;
    verify_installed_version_metadata(Path::new(prefix), version, source, native).map(Some)
}
