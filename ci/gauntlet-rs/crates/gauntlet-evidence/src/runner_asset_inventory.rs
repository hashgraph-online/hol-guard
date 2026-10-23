//! Composite inert asset inventory for a fully loaded runner declaration.
//! This does not admit execution or establish installed-prefix parity on Linux.

use crate::runner_inputs::verify_runner_file_assets;
use crate::runner_runtime::LoadedRunnerConfig;
use crate::tree_inventory::{inventory_tree, TreeKind};
use crate::{verify_private_cell_artifacts, EvidenceError, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerAssetInventory {
    pub observed: BTreeMap<String, String>,
    pub installed_package_version: Option<String>,
    pub execution_eligible: bool,
}

fn value_str<'a>(value: &'a Value, message: &'static str) -> Result<&'a str> {
    value.as_str().ok_or(EvidenceError::Invalid(message))
}

/// Hash every declared file, SDK/cache tree, installed prefix and private-cell
/// artifact set as inert bytes. Each result is compared with the frozen runner
/// pin. A successful inventory remains diagnostic pending Linux race/OS-access
/// proof, independent scoring and trusted controller deployment.
pub fn verify_runner_assets_inert(
    loaded: &LoadedRunnerConfig,
    asset_root: &Path,
) -> Result<RunnerAssetInventory> {
    let config = loaded.verified.config.value();
    let assets = config["assets"]
        .as_object()
        .ok_or(EvidenceError::Invalid("asset declarations missing"))?;
    let mut observed = verify_runner_file_assets(&loaded.verified, asset_root)?;
    for (role, row) in assets {
        let kind = value_str(&row["kind"], "asset kind missing")?;
        let expected = value_str(&row["sha256"], "asset digest missing")?;
        let path = loaded.declaration.paths[role]
            .as_str()
            .ok_or(EvidenceError::Invalid("asset path missing from runtime"))?;
        let actual = match kind {
            "file" => {
                let result = observed
                    .get(role)
                    .ok_or(EvidenceError::Invalid("file asset was not inventoried"))?;
                result.clone()
            }
            "sdk-tree" => inventory_tree(Path::new(path), TreeKind::Sdk)?.digest,
            "guard-prefix" => inventory_tree(Path::new(path), TreeKind::InstalledPrefix)?.digest,
            "cell-artifacts" => {
                let private = &loaded.declaration.runtime["guard_private_cell"];
                let initializer = value_str(
                    &private["initializer_sha256"],
                    "private-cell initializer pin missing",
                )?;
                verify_private_cell_artifacts(Path::new(path), expected, initializer)?
                    .manifest_sha256
            }
            _ => return Err(EvidenceError::Invalid("unknown runner asset kind")),
        };
        if actual != expected {
            return Err(EvidenceError::Invalid(
                "runner asset differs from its frozen digest",
            ));
        }
        observed.insert(role.clone(), actual);
    }
    if observed.len() != assets.len() {
        return Err(EvidenceError::Invalid("runner asset inventory incomplete"));
    }
    Ok(RunnerAssetInventory {
        observed,
        installed_package_version: loaded.installed_package_version.clone(),
        execution_eligible: false,
    })
}
