use super::*;

/// `_artifact_manifest_dependency_map` (:4007-4017) — dependency map for one
/// manifest path; pip falls back to `requirements.txt` when the manifest has
/// no deps.
// supply_chain_package_eval.py:4007-4017
#[allow(dead_code)]
pub(super) fn artifact_manifest_dependency_map(
    deps: &SupplyChainEvalDeps<'_>,
    package_manager: &str,
    relative_path: &str,
    manifest_text: &str,
) -> BTreeMap<String, String> {
    // `deadline_ms` mirrors the Python default (`parse_manifest_dependencies`,
    // deadline_ms=50): the parse budget is a soft cap, never `0` — a `0`ms
    // deadline instantiates an already-expired `Deadline` and returns an empty
    // map for every manifest.
    let dependency_map = deps.manifest.parse_manifest_dependencies(
        relative_path,
        manifest_text,
        crate::local_supply_chain::DEFAULT_MANIFEST_PARSE_BYTE_LIMIT,
        crate::local_supply_chain::DEFAULT_MANIFEST_PARSE_DEADLINE_MS,
    );
    if !dependency_map.is_empty() || package_manager != "pip" {
        return dependency_map;
    }
    deps.manifest.parse_manifest_dependencies(
        "requirements.txt",
        manifest_text,
        crate::local_supply_chain::DEFAULT_MANIFEST_PARSE_BYTE_LIMIT,
        crate::local_supply_chain::DEFAULT_MANIFEST_PARSE_DEADLINE_MS,
    )
}

/// `_manifest_direct_dependency_names` (:3933-3962) — normalized direct
/// dependency names across the artifact's manifests for `ecosystem`.
// supply_chain_package_eval.py:3933-3962
#[allow(dead_code)]
pub(super) fn manifest_direct_dependency_names(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    ecosystem: &str,
) -> BTreeSet<String> {
    let Some(ws) = workspace_dir else {
        return BTreeSet::new();
    };
    let Some(manifest_paths) = artifact
        .metadata
        .get("manifest_paths")
        .and_then(Value::as_array)
    else {
        return BTreeSet::new();
    };
    let package_manager = artifact
        .metadata
        .get("package_manager")
        .and_then(Value::as_str)
        .unwrap_or("npm");
    let mut direct_names: BTreeSet<String> = BTreeSet::new();
    for rel in manifest_paths.iter().filter_map(Value::as_str) {
        let Some(manifest_path) = resolve_path_within_workspace(ws, rel) else {
            continue;
        };
        if !manifest_path.exists() {
            continue;
        }
        let Some(manifest_text) = deps.workspace_io.read_text(ws, rel) else {
            continue;
        };
        let dependency_map =
            artifact_manifest_dependency_map(deps, package_manager, rel, &manifest_text);
        for package_name in dependency_map.keys() {
            direct_names.insert(normalize_package_name(deps, ecosystem, package_name));
        }
    }
    direct_names
}

/// `_manifest_dependency_versions` (:3965-4004) — resolve each target's exact
/// version from manifest specifiers across the artifact's manifests.
// supply_chain_package_eval.py:3965-4004
#[allow(dead_code)]
pub(super) fn manifest_dependency_versions(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let Some(ws) = workspace_dir else {
        return BTreeMap::new();
    };
    let Some(manifest_paths) = artifact
        .metadata
        .get("manifest_paths")
        .and_then(Value::as_array)
    else {
        return BTreeMap::new();
    };
    let package_manager = artifact
        .metadata
        .get("package_manager")
        .and_then(Value::as_str)
        .unwrap_or("npm");
    let mut keyed_targets: Vec<(String, &Map<String, Value>)> = Vec::new();
    for target in targets {
        if let Some(key) = lockfile_target_key(target) {
            keyed_targets.push((key, target));
        }
    }
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for rel in manifest_paths.iter().filter_map(Value::as_str) {
        let Some(manifest_path) = resolve_path_within_workspace(ws, rel) else {
            continue;
        };
        if !manifest_path.exists() {
            continue;
        }
        let Some(manifest_text) = deps.workspace_io.read_text(ws, rel) else {
            continue;
        };
        let dependency_map =
            artifact_manifest_dependency_map(deps, package_manager, rel, &manifest_text);
        if dependency_map.is_empty() {
            continue;
        }
        for (target_key, target) in &keyed_targets {
            if versions.contains_key(target_key) {
                continue;
            }
            let ecosystem =
                optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
            let normalized_dependencies: BTreeMap<String, String> = dependency_map
                .iter()
                .map(|(k, v)| (normalize_package_name(deps, &ecosystem, k), v.clone()))
                .collect();
            for candidate in target_candidate_names(deps, target) {
                let candidate_norm = normalize_package_name(deps, &ecosystem, &candidate);
                let specifier = normalized_dependencies.get(&candidate_norm);
                if let Some(exact) =
                    manifest_exact_version(deps, &ecosystem, specifier.map(String::as_str))
                {
                    versions.insert(target_key.clone(), exact);
                    break;
                }
            }
        }
    }
    versions
}

/// `_composer_lock_target_versions` (:4134-4144).
// supply_chain_package_eval.py:4134-4144
#[allow(dead_code)]
pub(super) fn composer_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let parse_result =
        safe_dependency_map_result_for_path(deps, "composer.lock", text, monotonic_seconds() + 0.2);
    target_versions_from_direct_map(deps, targets, &parse_result.dependency_map())
}

/// `_gemfile_lock_target_versions` (:4147-4156).
// supply_chain_package_eval.py:4147-4156
#[allow(dead_code)]
pub(super) fn gemfile_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let parse_result =
        safe_dependency_map_result_for_path(deps, "Gemfile.lock", text, monotonic_seconds() + 0.2);
    target_versions_from_direct_map(deps, targets, &parse_result.dependency_map())
}

/// `_cargo_lock_target_versions` (:4109-4115).
// supply_chain_package_eval.py:4109-4115
#[allow(dead_code)]
pub(super) fn cargo_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let parse_result =
        safe_dependency_map_result_for_path(deps, "Cargo.lock", text, monotonic_seconds() + 0.2);
    target_versions_from_direct_map(deps, targets, &parse_result.dependency_map())
}
