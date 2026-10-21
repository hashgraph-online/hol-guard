use super::manifest_versions::{manifest_exact_version, source_url_from_specifier};
use super::*;

/// `_manifest_ecosystem_for_path` (manifest_dependency_targets.py:28-30).
fn manifest_ecosystem_for_path(path: &str) -> Option<&'static str> {
    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match name.as_str() {
        "package.json" => Some("npm"),
        "requirements.txt" | "requirements-dev.txt" | "pyproject.toml" | "setup.py" => Some("pypi"),
        "cargo.toml" => Some("cargo"),
        "go.mod" => Some("go"),
        _ => None,
    }
}

/// `_manifest_dependency_targets` (manifest_dependency_targets.py:55-155) —
/// manifest-declared deps that aren't pinned in the applicable lockfile become
/// `manifest_unsynced` targets, which the evaluator grades `ask`. The prior
/// resident seam emitted only `{name, version}` so `manifest_unsynced` was
/// unreachable and unknown packages silently degraded to `monitor`.
pub(super) fn manifest_dependency_targets(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
    include_locked: bool,
) -> Vec<Map<String, Value>> {
    let Some(ws) = workspace_dir else {
        return Vec::new();
    };
    let Some(manifest_paths) = artifact
        .metadata
        .get("manifest_paths")
        .and_then(Value::as_array)
        .filter(|p| !p.is_empty())
    else {
        return Vec::new();
    };
    let package_manager = optional_string(artifact.metadata.get("package_manager"))
        .unwrap_or_else(|| "npm".to_string());
    let redacted_command = optional_string(artifact.metadata.get("redacted_command"));

    // lockfile_dependencies: (parent dir, ecosystem, normalized_name -> version)
    let mut lockfile_dependencies: Vec<(PathBuf, String, BTreeMap<String, String>)> = Vec::new();
    if let Some(lockfile_paths) = artifact
        .metadata
        .get("lockfile_paths")
        .and_then(Value::as_array)
    {
        for rel in lockfile_paths
            .iter()
            .filter_map(Value::as_str)
            .filter(|p| !p.is_empty())
        {
            let Some(lockfile_path) = resolve_path_within_workspace(ws, rel) else {
                continue;
            };
            if !lockfile_path.exists() {
                continue;
            }
            let Some(lockfile_text) = deps.workspace_io.read_text(ws, rel) else {
                continue;
            };
            let file_name = lockfile_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let lockfile_eco = if file_name.is_empty() {
                "npm".to_string()
            } else {
                lockfile_ecosystem(&file_name)
            };
            let mut versions: BTreeMap<String, String> = BTreeMap::new();
            for (pkg_name, version) in deps.manifest.parse_manifest_dependencies(
                rel,
                &lockfile_text,
                crate::local_supply_chain::DEFAULT_MANIFEST_PARSE_BYTE_LIMIT,
                crate::local_supply_chain::DEFAULT_MANIFEST_PARSE_DEADLINE_MS,
            ) {
                let norm = normalize_package_name(deps, &lockfile_eco, &pkg_name);
                versions.insert(norm, version);
            }
            let lockfile_parent = lockfile_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_default();
            lockfile_dependencies.push((lockfile_parent, lockfile_eco, versions));
        }
    }

    let mut unsynced: Vec<Map<String, Value>> = Vec::new();
    for rel in manifest_paths
        .iter()
        .filter_map(Value::as_str)
        .filter(|p| !p.is_empty())
    {
        let Some(ecosystem) = manifest_ecosystem_for_path(rel) else {
            continue;
        };
        let Some(manifest_path) = resolve_path_within_workspace(ws, rel) else {
            continue;
        };
        if !manifest_path.exists() {
            continue;
        }
        let Some(manifest_text) = deps.workspace_io.read_text(ws, rel) else {
            continue;
        };
        let dependency_map = super::manifest_dependencies::artifact_manifest_dependency_map(
            deps,
            &package_manager,
            rel,
            &manifest_text,
        );
        let manifest_parent = manifest_path.parent().map(|p| p.to_path_buf());
        // `manifest_path.parent.parents` — strict ancestors, excluding the parent dir.
        let manifest_ancestors: Vec<PathBuf> = manifest_parent
            .as_ref()
            .and_then(|p| p.parent())
            .map(|gp| gp.ancestors().map(|a| a.to_path_buf()).collect())
            .unwrap_or_default();
        let applicable: Vec<&(PathBuf, String, BTreeMap<String, String>)> = lockfile_dependencies
            .iter()
            .filter(|(lp, leco, _)| {
                *leco == ecosystem
                    && manifest_parent
                        .as_ref()
                        .is_some_and(|mp| lp == mp || manifest_ancestors.iter().any(|a| a == lp))
            })
            .collect();
        let scoped_versions: Vec<&BTreeMap<String, String>> = if applicable.is_empty() {
            Vec::new()
        } else {
            let closest = applicable
                .iter()
                .map(|(lp, _, _)| lp.components().count())
                .max()
                .unwrap_or(0);
            applicable
                .iter()
                .filter(|(lp, _, _)| lp.components().count() == closest)
                .map(|t| &t.2)
                .collect()
        };
        let mut lockfile_versions: BTreeMap<String, Option<String>> = BTreeMap::new();
        for versions in scoped_versions {
            for (norm, version) in versions {
                match lockfile_versions.get(norm) {
                    None => {
                        lockfile_versions.insert(norm.clone(), Some(version.clone()));
                    }
                    Some(existing) if existing.as_deref() != Some(version.as_str()) => {
                        lockfile_versions.insert(norm.clone(), None);
                    }
                    _ => {}
                }
            }
        }
        for (package_name, specifier) in dependency_map {
            let normalized_name = normalize_package_name(deps, ecosystem, &package_name);
            let locked_version = lockfile_versions
                .get(&normalized_name)
                .and_then(|v| v.clone());
            if !include_locked && locked_version.is_some() {
                continue;
            }
            let (namespace, name) = split_namespace_name(&package_name, ecosystem);
            let exact_version = if include_locked {
                locked_version.clone()
            } else {
                None
            }
            .or_else(|| manifest_exact_version(deps, ecosystem, Some(specifier.as_str())));
            let mut target = Map::new();
            target.insert("ecosystem".into(), Value::String(ecosystem.to_string()));
            target.insert("package_name".into(), Value::String(package_name.clone()));
            target.insert("normalized_name".into(), Value::String(normalized_name));
            target.insert(
                "namespace".into(),
                namespace.map(Value::String).unwrap_or(Value::Null),
            );
            target.insert("name".into(), Value::String(name));
            target.insert(
                "raw_spec".into(),
                Value::String(match &exact_version {
                    Some(v) => format!("{package_name}@{v}"),
                    None => package_name.clone(),
                }),
            );
            target.insert(
                "version".into(),
                exact_version
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
            target.insert(
                "range".into(),
                if exact_version.is_none() {
                    Value::String(specifier.clone())
                } else {
                    Value::Null
                },
            );
            target.insert(
                "source_url".into(),
                source_url_from_specifier(Some(specifier.as_str()))
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
            target.insert("alias".into(), Value::Null);
            target.insert("dependency_group".into(), Value::Null);
            target.insert("extras".into(), Value::Array(Vec::new()));
            target.insert("editable".into(), Value::Bool(false));
            target.insert(
                "package_manager".into(),
                Value::String(package_manager.clone()),
            );
            target.insert(
                "redacted_command".into(),
                redacted_command
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
            target.insert(
                "manifest_unsynced".into(),
                Value::Bool(locked_version.is_none()),
            );
            unsynced.push(target);
        }
    }
    unsynced
}
