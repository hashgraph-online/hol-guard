use super::*;

/// `_toml_lock_direct_versions` (:4300-4319) — direct `{normalized_name:
/// version}` map from a `[[package]]` TOML lockfile (poetry/uv shape).
// supply_chain_package_eval.py:4300-4319
#[allow(dead_code)]
pub(super) fn toml_lock_direct_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut direct_versions: BTreeMap<String, String> = BTreeMap::new();
    let Ok(payload) = text.parse::<toml::Value>() else {
        return direct_versions;
    };
    let Some(toml::Value::Array(packages)) = payload.get("package") else {
        return direct_versions;
    };
    for package in packages {
        let toml::Value::Table(pkg) = package else {
            continue;
        };
        let name = pkg.get("name").and_then(|v| v.as_str()).map(str::to_string);
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let normalized_name = name.map(|n| normalize_package_name(deps, "pypi", &n));
        if let (Some(norm), Some(ver)) = (normalized_name, version) {
            if direct_manifest_names.contains(&norm) {
                direct_versions.insert(norm, ver);
            }
        }
    }
    direct_versions
}

/// `_poetry_lock_direct_versions` (:4321) — alias over toml parser.
// supply_chain_package_eval.py:4321
#[allow(dead_code)]
pub(super) fn poetry_lock_direct_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    toml_lock_direct_versions(deps, text, direct_manifest_names)
}

/// `_uv_lock_direct_versions` (:4322) — alias over toml parser.
// supply_chain_package_eval.py:4322
#[allow(dead_code)]
pub(super) fn uv_lock_direct_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    toml_lock_direct_versions(deps, text, direct_manifest_names)
}

/// `_poetry_lock_target_versions` (:4292-4298).
// supply_chain_package_eval.py:4292-4298
#[allow(dead_code)]
pub(super) fn poetry_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    target_versions_from_direct_map(
        deps,
        targets,
        &poetry_lock_direct_versions(deps, text, direct_manifest_names),
    )
}

/// `_uv_lock_target_versions` (:4325-4332).
// supply_chain_package_eval.py:4325-4332
#[allow(dead_code)]
pub(super) fn uv_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    target_versions_from_direct_map(
        deps,
        targets,
        &uv_lock_direct_versions(deps, text, direct_manifest_names),
    )
}

/// `_pipfile_lock_target_versions` (:4334-4341).
// supply_chain_package_eval.py:4334-4341
#[allow(dead_code)]
pub(super) fn pipfile_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    target_versions_from_direct_map(
        deps,
        targets,
        &pipfile_lock_direct_versions(deps, text, direct_manifest_names),
    )
}

/// `_pipfile_lock_direct_versions` (:4354-4368) — direct pypi deps from
/// Pipfile.lock `default`/`develop` sections.
// supply_chain_package_eval.py:4354-4368
#[allow(dead_code)]
pub(super) fn pipfile_lock_direct_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut direct_versions: BTreeMap<String, String> = BTreeMap::new();
    let payload: Value = serde_json::from_str(text).unwrap_or_else(|_| json!({}));
    for section in ["default", "develop"] {
        let Some(Value::Object(values)) = payload.get(section) else {
            continue;
        };
        for (package_name, package_value) in values {
            if !package_value.is_object() {
                continue;
            }
            let exact = python_lockfile_version(deps, package_value.get("version"));
            let normalized_name = normalize_package_name(deps, "pypi", package_name);
            if let Some(exact) = exact {
                if direct_manifest_names.contains(&normalized_name) {
                    direct_versions.insert(normalized_name, exact);
                }
            }
        }
    }
    direct_versions
}
